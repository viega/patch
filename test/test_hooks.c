#include "patch/patch.h"
#include "patch/patch_hook.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Test functions with patchable entry points
// ============================================================================

PATCH_DEFINE_HOOKABLE(int, add_two, int a, int b)
{
    return a + b;
}

PATCH_DEFINE_HOOKABLE(int, multiply_two, int a, int b)
{
    return a * b;
}

PATCH_DEFINE_HOOKABLE(int, compute_sum, int start, int count)
{
    int sum = 0;
    for (int i = 0; i < count; i++) {
        sum += start + i;
    }
    return sum;
}

// ============================================================================
// Test state and callbacks for low-level API (Linux only)
// ============================================================================

#ifndef PATCH_PLATFORM_DARWIN

static int  g_prologue_call_count = 0;
static int  g_epilogue_call_count = 0;
static int  g_last_arg0           = 0;
static int  g_last_arg1           = 0;
static int  g_last_return         = 0;
static bool g_skip_original       = false;
static int  g_fake_return         = 0;

static void
reset_test_state(void)
{
    g_prologue_call_count = 0;
    g_epilogue_call_count = 0;
    g_last_arg0           = 0;
    g_last_arg1           = 0;
    g_last_return         = 0;
    g_skip_original       = false;
    g_fake_return         = 0;
}

static bool
counting_prologue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;
    g_prologue_call_count++;

    // Capture arguments
    int *arg0 = (int *)patch_context_get_arg(ctx, 0);
    int *arg1 = (int *)patch_context_get_arg(ctx, 1);
    if (arg0) g_last_arg0 = *arg0;
    if (arg1) g_last_arg1 = *arg1;

    if (g_skip_original) {
        patch_context_set_return(ctx, &g_fake_return, sizeof(g_fake_return));
        return false;
    }
    return true;
}

static void
counting_epilogue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;
    g_epilogue_call_count++;

    // Capture return value
    int *ret = (int *)patch_context_get_return(ctx);
    if (ret) g_last_return = *ret;
}

static bool
arg_modifying_prologue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;

    // Double both arguments
    int *arg0 = (int *)patch_context_get_arg(ctx, 0);
    int *arg1 = (int *)patch_context_get_arg(ctx, 1);

    if (arg0 && arg1) {
        int new_arg0 = *arg0 * 2;
        int new_arg1 = *arg1 * 2;
        patch_context_set_arg(ctx, 0, &new_arg0, sizeof(new_arg0));
        patch_context_set_arg(ctx, 1, &new_arg1, sizeof(new_arg1));
    }

    return true;
}

static void
return_modifying_epilogue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;

    // Add 1000 to return value
    int *ret = (int *)patch_context_get_return(ctx);
    if (ret) {
        int new_ret = *ret + 1000;
        patch_context_set_return(ctx, &new_ret, sizeof(new_ret));
    }
}

#endif // !PATCH_PLATFORM_DARWIN

// ============================================================================
// Hook functions for unified macro tests
// ============================================================================

static int
hook_add_100(int a, int b)
{
    return PATCH_CALL_ORIGINAL(add_two, a, b) + 100;
}

static int
hook_triple_result(int a, int b)
{
    return PATCH_CALL_ORIGINAL(multiply_two, a, b) * 3;
}

static int
hook_recursive_sum(int start, int count)
{
    // This hook calls the original, demonstrating recursive safety
    int original = PATCH_CALL_ORIGINAL(compute_sum, start, count);
    return original + 1; // Add 1 to distinguish from original
}

// ============================================================================
// Tests
// ============================================================================

static void
test_hook_is_called(void)
{
    printf("Test: Hook is called...\n");

    int result = PATCH_CALL(add_two, 10, 20);
    assert(result == 30);

    PATCH_HOOK_INSTALL(add_two, hook_add_100);

    result = PATCH_CALL(add_two, 10, 20);
    assert(result == 130); // 30 + 100

    PATCH_HOOK_REMOVE(add_two);

    result = PATCH_CALL(add_two, 10, 20);
    assert(result == 30);

    printf("  PASSED\n");
}

static void
test_multiple_hooks_independent(void)
{
    printf("Test: Multiple independent hooks...\n");

    PATCH_HOOK_INSTALL(add_two, hook_add_100);
    PATCH_HOOK_INSTALL(multiply_two, hook_triple_result);

    int sum  = PATCH_CALL(add_two, 5, 5);      // (5+5) + 100 = 110
    int prod = PATCH_CALL(multiply_two, 3, 4); // (3*4) * 3 = 36

    assert(sum == 110);
    assert(prod == 36);

    // Remove one, verify other still works
    PATCH_HOOK_REMOVE(add_two);

    sum  = PATCH_CALL(add_two, 5, 5);      // 10 (unhooked)
    prod = PATCH_CALL(multiply_two, 3, 4); // still 36

    assert(sum == 10);
    assert(prod == 36);

    PATCH_HOOK_REMOVE(multiply_two);

    printf("  PASSED\n");
}

static void
test_hook_calls_original(void)
{
    printf("Test: Hook calling original (recursive safety)...\n");

    // compute_sum(1, 5) = 1+2+3+4+5 = 15
    int result = PATCH_CALL(compute_sum, 1, 5);
    assert(result == 15);

    PATCH_HOOK_INSTALL(compute_sum, hook_recursive_sum);

    // With hook: original + 1 = 16
    result = PATCH_CALL(compute_sum, 1, 5);
    assert(result == 16);

    PATCH_HOOK_REMOVE(compute_sum);

    printf("  PASSED\n");
}

static void
test_rehook_after_remove(void)
{
    printf("Test: Re-hook after remove...\n");

    // First hook
    PATCH_HOOK_INSTALL(add_two, hook_add_100);
    int result = PATCH_CALL(add_two, 1, 2);
    assert(result == 103);

    // Remove
    PATCH_HOOK_REMOVE(add_two);
    result = PATCH_CALL(add_two, 1, 2);
    assert(result == 3);

    // Re-hook
    PATCH_HOOK_INSTALL(add_two, hook_add_100);
    result = PATCH_CALL(add_two, 1, 2);
    assert(result == 103);

    // Remove again
    PATCH_HOOK_REMOVE(add_two);
    result = PATCH_CALL(add_two, 1, 2);
    assert(result == 3);

    printf("  PASSED\n");
}

#ifndef PATCH_PLATFORM_DARWIN
// Low-level API tests only run on Linux where code patching works

static void
test_prologue_callback_receives_args(void)
{
    printf("Test: Prologue callback receives arguments...\n");

    patch_error_t err = patch_can_install((void *)add_two);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (pattern not recognized)\n");
        return;
    }

    reset_test_state();

    patch_config_t config = {
        .target   = (void *)add_two,
        .prologue = counting_prologue,
    };

    patch_handle_t *handle = nullptr;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    int result = PATCH_CALL(add_two, 42, 58);

    assert(g_prologue_call_count == 1);
    assert(g_last_arg0 == 42);
    assert(g_last_arg1 == 58);
    assert(result == 100);

    patch_remove(handle);
    printf("  PASSED\n");
}

static void
test_epilogue_callback_receives_return(void)
{
    printf("Test: Epilogue callback receives return value...\n");

    patch_error_t err = patch_can_install((void *)add_two);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (pattern not recognized)\n");
        return;
    }

    reset_test_state();

    patch_config_t config = {
        .target   = (void *)add_two,
        .epilogue = counting_epilogue,
    };

    patch_handle_t *handle = nullptr;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    int result = PATCH_CALL(add_two, 7, 3);

    assert(g_epilogue_call_count == 1);
    assert(g_last_return == 10);
    assert(result == 10);

    patch_remove(handle);
    printf("  PASSED\n");
}

static void
test_prologue_can_modify_args(void)
{
    printf("Test: Prologue can modify arguments...\n");

    patch_error_t err = patch_can_install((void *)add_two);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (pattern not recognized)\n");
        return;
    }

    patch_config_t config = {
        .target   = (void *)add_two,
        .prologue = arg_modifying_prologue,
    };

    patch_handle_t *handle = nullptr;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    // Original would compute 5+3=8, but prologue doubles args: 10+6=16
    int result = PATCH_CALL(add_two, 5, 3);
    assert(result == 16);

    patch_remove(handle);
    printf("  PASSED\n");
}

static void
test_epilogue_can_modify_return(void)
{
    printf("Test: Epilogue can modify return value...\n");

    patch_error_t err = patch_can_install((void *)add_two);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (pattern not recognized)\n");
        return;
    }

    patch_config_t config = {
        .target   = (void *)add_two,
        .epilogue = return_modifying_epilogue,
    };

    patch_handle_t *handle = nullptr;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    // Original: 5+3=8, epilogue adds 1000: 1008
    int result = PATCH_CALL(add_two, 5, 3);
    assert(result == 1008);

    patch_remove(handle);
    printf("  PASSED\n");
}

static void
test_prologue_can_skip_original(void)
{
    printf("Test: Prologue can skip original...\n");

    patch_error_t err = patch_can_install((void *)add_two);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (pattern not recognized)\n");
        return;
    }

    reset_test_state();
    g_skip_original = true;
    g_fake_return   = 9999;

    patch_config_t config = {
        .target   = (void *)add_two,
        .prologue = counting_prologue,
        .epilogue = counting_epilogue,
    };

    patch_handle_t *handle = nullptr;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    int result = PATCH_CALL(add_two, 100, 200);

    assert(g_prologue_call_count == 1);
    assert(result == 9999); // Fake return, original was skipped
    // Epilogue should still be called
    assert(g_epilogue_call_count == 1);

    patch_remove(handle);
    printf("  PASSED\n");
}

static void
test_both_callbacks(void)
{
    printf("Test: Both prologue and epilogue callbacks...\n");

    patch_error_t err = patch_can_install((void *)add_two);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (pattern not recognized)\n");
        return;
    }

    reset_test_state();

    patch_config_t config = {
        .target   = (void *)add_two,
        .prologue = counting_prologue,
        .epilogue = counting_epilogue,
    };

    patch_handle_t *handle = nullptr;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    int result = PATCH_CALL(add_two, 11, 22);

    assert(g_prologue_call_count == 1);
    assert(g_epilogue_call_count == 1);
    assert(g_last_arg0 == 11);
    assert(g_last_arg1 == 22);
    assert(g_last_return == 33);
    assert(result == 33);

    patch_remove(handle);
    printf("  PASSED\n");
}

static void
test_disable_enable(void)
{
    printf("Test: Disable and enable patch...\n");

    patch_error_t err = patch_can_install((void *)add_two);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (pattern not recognized)\n");
        return;
    }

    reset_test_state();

    patch_config_t config = {
        .target   = (void *)add_two,
        .prologue = counting_prologue,
    };

    patch_handle_t *handle = nullptr;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    // Hook active
    PATCH_CALL(add_two, 1, 1);
    assert(g_prologue_call_count == 1);

    // Disable
    err = patch_disable(handle);
    assert(err == PATCH_SUCCESS);

    PATCH_CALL(add_two, 1, 1);
    assert(g_prologue_call_count == 1); // Still 1, not called

    // Re-enable
    err = patch_enable(handle);
    assert(err == PATCH_SUCCESS);

    PATCH_CALL(add_two, 1, 1);
    assert(g_prologue_call_count == 2); // Now 2

    patch_remove(handle);
    printf("  PASSED\n");
}

#endif // !PATCH_PLATFORM_DARWIN

// ============================================================================
// Main
// ============================================================================

int
main(void)
{
    printf("=== Hook Integration Tests ===\n\n");

    // Unified macro tests (work on all platforms)
    test_hook_is_called();
    test_multiple_hooks_independent();
    test_hook_calls_original();
    test_rehook_after_remove();

#ifndef PATCH_PLATFORM_DARWIN
    // Low-level API tests (Linux only)
    printf("\n--- Low-level API Tests ---\n\n");
    test_prologue_callback_receives_args();
    test_epilogue_callback_receives_return();
    test_prologue_can_modify_args();
    test_epilogue_can_modify_return();
    test_prologue_can_skip_original();
    test_both_callbacks();
    test_disable_enable();
#endif

    printf("\n=== All Hook Tests Passed ===\n");
    return 0;
}
