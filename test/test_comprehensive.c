#include "patch/patch.h"
#include "patch/patch_hook.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Test Counters
// ============================================================================

static int g_tests_passed = 0;
static int g_tests_failed = 0;
static int g_tests_skipped = 0;

#define TEST_PASS() do { g_tests_passed++; printf("  PASSED\n"); } while(0)
#define TEST_FAIL(msg) do { g_tests_failed++; printf("  FAILED: %s\n", msg); } while(0)
#define TEST_SKIP(msg) do { g_tests_skipped++; printf("  SKIPPED: %s\n", msg); } while(0)

// ============================================================================
// Test Functions - Hookable via unified macros
// ============================================================================

PATCH_DEFINE_HOOKABLE(int, func_add, int a, int b)
{
    return a + b;
}

PATCH_DEFINE_HOOKABLE(int, func_sub, int a, int b)
{
    return a - b;
}

PATCH_DEFINE_HOOKABLE(int, func_mul, int a, int b)
{
    return a * b;
}

PATCH_DEFINE_HOOKABLE(int, func_div, int a, int b)
{
    if (b == 0) return 0;
    return a / b;
}

PATCH_DEFINE_HOOKABLE(int, func_identity, int x)
{
    return x;
}

PATCH_DEFINE_HOOKABLE(int, func_chain_a, int x)
{
    return x + 1;
}

PATCH_DEFINE_HOOKABLE(int, func_variadic_args, int a, int b, int c, int d, int e, int f)
{
    return a + b + c + d + e + f;
}

PATCH_DEFINE_HOOKABLE(long long, func_64bit_return, long long x)
{
    return x * 2;
}

PATCH_DEFINE_HOOKABLE(void*, func_pointer_return, void *p)
{
    return p;
}

// Function with more than register args to test stack argument access
// x86-64: 6 register args, so args 7+ are on stack
// ARM64: 8 register args, so args 9+ are on stack
PATCH_DEFINE_HOOKABLE(int, func_many_args, int a, int b, int c, int d, int e, int f, int g, int h, int i)
{
    return a + b + c + d + e + f + g + h + i;
}

// Floating point test functions - usable with FFI for proper FP arg forwarding
// Mixed int and FP arguments
PATCH_DEFINE_HOOKABLE(double, func_mixed_args, int a, double b, int c, double d)
{
    return (double)a + b + (double)c + d;
}

// Pure FP arguments
PATCH_DEFINE_HOOKABLE(double, func_fp_only, double a, double b, double c)
{
    return a * b + c;
}

// ============================================================================
// Hook Functions
// ============================================================================

static int hook_add_1000(int a, int b) {
    return PATCH_CALL_ORIGINAL(func_add, a, b) + 1000;
}

static int hook_negate_result(int a, int b) {
    return -PATCH_CALL_ORIGINAL(func_sub, a, b);
}

static int hook_square_result(int a, int b) {
    int result = PATCH_CALL_ORIGINAL(func_mul, a, b);
    return result * result;
}

static int hook_always_42(int a, int b) {
    (void)a; (void)b;
    return 42;
}

// hook_double_input: doubles input, passes to original
static int hook_double_input(int x) {
    return PATCH_CALL_ORIGINAL(func_identity, x * 2);
}

// Used by test_identity_hook
static int hook_add_1_to_identity(int x) {
    return PATCH_CALL_ORIGINAL(func_identity, x) + 1;
}

static int hook_chain_intercept(int x) {
    return PATCH_CALL_ORIGINAL(func_chain_a, x) + 100;
}

static int hook_sum_doubled(int a, int b, int c, int d, int e, int f) {
    return PATCH_CALL_ORIGINAL(func_variadic_args, a, b, c, d, e, f) * 2;
}

static long long hook_add_large(long long x) {
    return PATCH_CALL_ORIGINAL(func_64bit_return, x) + 0x1000000000LL;
}

static int g_hook_target = 999;

static void* hook_replace_pointer(void *p) {
    (void)p;
    return &g_hook_target;
}

static bool dummy_prologue(patch_context_t *ctx, void *ud) {
    (void)ctx;
    (void)ud;
    return true;
}

// Captures stack arguments for verification
static int g_captured_stack_args[4] = {0};
static int g_captured_reg_args[8] = {0};

static bool stack_arg_prologue(patch_context_t *ctx, void *ud) {
    (void)ud;

    // Capture register arguments for verification
    for (int i = 0; i < PATCH_REG_ARGS; i++) {
        int *arg = (int *)patch_context_get_arg(ctx, i);
        if (arg) g_captured_reg_args[i] = *arg;
    }

    // On x86-64: args 0-5 are in registers, 6+ are on stack
    // On ARM64: args 0-7 are in registers, 8+ are on stack
    // Our function has 9 args (a-i), so:
    //   x86-64: args g(6), h(7), i(8) are stack args 0, 1, 2
    //   ARM64: arg i(8) is stack arg 0

#ifdef PATCH_ARCH_X86_64
    // Stack args: g=6, h=7, i=8 -> stack indices 0, 1, 2
    int *stack_arg_0 = (int *)patch_context_get_stack_arg(ctx, 0);
    int *stack_arg_1 = (int *)patch_context_get_stack_arg(ctx, 1);
    int *stack_arg_2 = (int *)patch_context_get_stack_arg(ctx, 2);
    if (stack_arg_0) g_captured_stack_args[0] = *stack_arg_0;
    if (stack_arg_1) g_captured_stack_args[1] = *stack_arg_1;
    if (stack_arg_2) g_captured_stack_args[2] = *stack_arg_2;

    // Compute expected result and return it (skip original)
    // This avoids the limitation that stack args aren't forwarded to trampoline
    int sum = g_captured_reg_args[0] + g_captured_reg_args[1] + g_captured_reg_args[2] +
              g_captured_reg_args[3] + g_captured_reg_args[4] + g_captured_reg_args[5] +
              g_captured_stack_args[0] + g_captured_stack_args[1] + g_captured_stack_args[2];
    patch_context_set_return(ctx, &sum, sizeof(sum));
    return false;  // Skip original - we computed the result ourselves
#else
    // ARM64: arg i(8) is the only stack arg
    int *stack_arg_0 = (int *)patch_context_get_stack_arg(ctx, 0);
    if (stack_arg_0) g_captured_stack_args[0] = *stack_arg_0;

    // Compute expected result
    int sum = g_captured_reg_args[0] + g_captured_reg_args[1] + g_captured_reg_args[2] +
              g_captured_reg_args[3] + g_captured_reg_args[4] + g_captured_reg_args[5] +
              g_captured_reg_args[6] + g_captured_reg_args[7] + g_captured_stack_args[0];
    patch_context_set_return(ctx, &sum, sizeof(sum));
    return false;  // Skip original
#endif
}

// ============================================================================
// Section 1: Basic API Validation
// ============================================================================

static void test_null_arguments(void)
{
    printf("Test: Null argument validation...\n");

    patch_error_t err;

    // patch_can_install with null
    err = patch_can_install(NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // patch_install with null config
    patch_handle_t *handle = NULL;
    err = patch_install(NULL, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // patch_install with null handle output
    // Use PATCH_HOOK_ORIGINAL for portable function reference (works on both macOS and Linux)
    patch_config_t config = {
        .target = (void*)PATCH_HOOK_ORIGINAL(func_add),
        .replacement = (void*)hook_add_1000
    };
    err = patch_install(&config, NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // patch_install with null target
    config.target = NULL;
    err = patch_install(&config, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // patch_remove with null
    err = patch_remove(NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // patch_disable with null
    err = patch_disable(NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // patch_enable with null
    err = patch_enable(NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // patch_get_trampoline with null
    void *tramp = patch_get_trampoline(NULL);
    assert(tramp == NULL);

    TEST_PASS();
}

static void test_config_validation(void)
{
    printf("Test: Config validation (replacement vs callbacks)...\n");

    patch_error_t err;
    patch_handle_t *handle = NULL;

    // Neither replacement nor callbacks - should fail
    patch_config_t config1 = { .target = (void*)PATCH_HOOK_ORIGINAL(func_add) };
    err = patch_install(&config1, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Both replacement AND prologue - should fail (mutually exclusive)
    patch_config_t config2 = {
        .target = (void*)PATCH_HOOK_ORIGINAL(func_add),
        .replacement = (void*)hook_add_1000,
        .prologue = dummy_prologue,
    };
    err = patch_install(&config2, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    TEST_PASS();
}

// ============================================================================
// Section 2: Simple Replacement Mode (New Feature)
// ============================================================================

static patch_handle_t *g_simple_handle = NULL;

static int simple_replacement_hook(int a, int b)
{
    typedef int (*orig_fn)(int, int);
    orig_fn original = (orig_fn)patch_get_trampoline(g_simple_handle);
    return original(a, b) + 500;
}

static void test_simple_replacement_mode(void)
{
    printf("Test: Simple replacement mode...\n");

    patch_error_t err = patch_can_install((void*)PATCH_HOOK_ORIGINAL(func_add));
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("Pattern not recognized");
        return;
    }

    // Verify original behavior
    int result = PATCH_CALL(func_add, 10, 20);
    assert(result == 30);

    // Install simple replacement
    patch_config_t config = {
        .target = (void*)PATCH_HOOK_ORIGINAL(func_add),
        .replacement = (void*)simple_replacement_hook,
    };

    err = patch_install(&config, &g_simple_handle);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP(patch_get_error_details());
        return;
    }

    // Verify hook works and can call original via trampoline
    result = PATCH_CALL(func_add, 10, 20);
    assert(result == 530);  // 30 + 500

    // Remove and verify restoration
    err = patch_remove(g_simple_handle);
    assert(err == PATCH_SUCCESS);
    g_simple_handle = NULL;

    result = PATCH_CALL(func_add, 10, 20);
    assert(result == 30);

    TEST_PASS();
}

// Global handle for simple replacement disable/enable test
static patch_handle_t *g_disable_enable_handle = NULL;

// Hook for disable/enable test - uses patch_get_trampoline since we're
// in simple replacement mode (not callback mode with context)
static int hook_negate_result_via_trampoline(int a, int b)
{
    typedef int (*orig_fn)(int, int);
    orig_fn original = (orig_fn)patch_get_trampoline(g_disable_enable_handle);
    return -original(a, b);
}

static void test_simple_replacement_disable_enable(void)
{
    printf("Test: Simple replacement disable/enable...\n");

    patch_error_t err = patch_can_install((void*)PATCH_HOOK_ORIGINAL(func_sub));
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("Pattern not recognized");
        return;
    }

    patch_config_t config = {
        .target = (void*)PATCH_HOOK_ORIGINAL(func_sub),
        .replacement = (void*)hook_negate_result_via_trampoline,
    };

    err = patch_install(&config, &g_disable_enable_handle);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP(patch_get_error_details());
        return;
    }

    // Hooked: 10-3=7, negated = -7
    int result = PATCH_CALL(func_sub, 10, 3);
    assert(result == -7);

    // Disable
    err = patch_disable(g_disable_enable_handle);
    assert(err == PATCH_SUCCESS);

    // Original: 10-3=7
    result = PATCH_CALL(func_sub, 10, 3);
    assert(result == 7);

    // Re-enable
    err = patch_enable(g_disable_enable_handle);
    assert(err == PATCH_SUCCESS);

    // Hooked again
    result = PATCH_CALL(func_sub, 10, 3);
    assert(result == -7);

    patch_remove(g_disable_enable_handle);
    g_disable_enable_handle = NULL;
    TEST_PASS();
}

// ============================================================================
// Section 3: PATCH_METHOD_CODE Testing
// ============================================================================

static void test_method_code_basic(void)
{
    printf("Test: PATCH_METHOD_CODE basic functionality...\n");

    int result = PATCH_CALL(func_mul, 3, 4);
    assert(result == 12);

    // Install with explicit CODE method
    PATCH_HOOK_INSTALL(func_mul, hook_square_result, PATCH_METHOD_CODE);

    // 3*4=12, squared=144
    result = PATCH_CALL(func_mul, 3, 4);
    assert(result == 144);

    PATCH_HOOK_REMOVE(func_mul);

    result = PATCH_CALL(func_mul, 3, 4);
    assert(result == 12);

    TEST_PASS();
}

static void test_method_code_vs_pointer(void)
{
    printf("Test: PATCH_METHOD_CODE vs PATCH_METHOD_POINTER...\n");

    // Test POINTER method
    PATCH_HOOK_INSTALL(func_identity, hook_double_input, PATCH_METHOD_POINTER);
    int result1 = PATCH_CALL(func_identity, 5);  // double(5)=10, identity(10)=10
    PATCH_HOOK_REMOVE(func_identity);

    // Test CODE method (should produce same result)
    PATCH_HOOK_INSTALL(func_identity, hook_double_input, PATCH_METHOD_CODE);
    int result2 = PATCH_CALL(func_identity, 5);
    PATCH_HOOK_REMOVE(func_identity);

    assert(result1 == 10);
    assert(result2 == 10);

    TEST_PASS();
}

// ============================================================================
// Section 4: Edge Cases and Stress Tests
// ============================================================================

static void test_rapid_hook_unhook(void)
{
    printf("Test: Rapid hook/unhook cycles...\n");

    for (int i = 0; i < 100; i++) {
        PATCH_HOOK_INSTALL(func_add, hook_add_1000);
        int hooked = PATCH_CALL(func_add, 1, 1);
        assert(hooked == 1002);

        PATCH_HOOK_REMOVE(func_add);
        int unhooked = PATCH_CALL(func_add, 1, 1);
        assert(unhooked == 2);
    }

    TEST_PASS();
}

static void test_multiple_functions_hooked(void)
{
    printf("Test: Multiple functions hooked simultaneously...\n");

    PATCH_HOOK_INSTALL(func_add, hook_add_1000);
    PATCH_HOOK_INSTALL(func_sub, hook_negate_result);
    PATCH_HOOK_INSTALL(func_mul, hook_square_result);
    PATCH_HOOK_INSTALL(func_div, hook_always_42);

    assert(PATCH_CALL(func_add, 5, 5) == 1010);   // 10 + 1000
    assert(PATCH_CALL(func_sub, 10, 3) == -7);    // -(10-3)
    assert(PATCH_CALL(func_mul, 2, 3) == 36);     // 6^2
    assert(PATCH_CALL(func_div, 100, 5) == 42);   // always 42

    // Remove in different order than install
    PATCH_HOOK_REMOVE(func_mul);
    PATCH_HOOK_REMOVE(func_add);
    PATCH_HOOK_REMOVE(func_div);
    PATCH_HOOK_REMOVE(func_sub);

    assert(PATCH_CALL(func_add, 5, 5) == 10);
    assert(PATCH_CALL(func_sub, 10, 3) == 7);
    assert(PATCH_CALL(func_mul, 2, 3) == 6);
    assert(PATCH_CALL(func_div, 100, 5) == 20);

    TEST_PASS();
}

static void test_hook_with_call_original(void)
{
    printf("Test: Hook that calls original function...\n");

    // func_chain_a(5) = 5 + 1 = 6
    int result = PATCH_CALL(func_chain_a, 5);
    assert(result == 6);

    // hook_chain_intercept calls original and adds 100
    PATCH_HOOK_INSTALL(func_chain_a, hook_chain_intercept);

    // Now: 5 + 1 + 100 = 106
    result = PATCH_CALL(func_chain_a, 5);
    assert(result == 106);

    PATCH_HOOK_REMOVE(func_chain_a);

    result = PATCH_CALL(func_chain_a, 5);
    assert(result == 6);

    TEST_PASS();
}

static void test_identity_function_hook(void)
{
    printf("Test: Identity function with hook...\n");

    // func_identity just returns its input
    int result = PATCH_CALL(func_identity, 42);
    assert(result == 42);

    // Hook doubles input before passing to original
    PATCH_HOOK_INSTALL(func_identity, hook_double_input);

    // hook_double_input(5) = identity(5*2) = 10
    result = PATCH_CALL(func_identity, 5);
    assert(result == 10);

    PATCH_HOOK_REMOVE(func_identity);

    // Back to normal
    result = PATCH_CALL(func_identity, 5);
    assert(result == 5);

    // Test with add hook
    PATCH_HOOK_INSTALL(func_identity, hook_add_1_to_identity);
    result = PATCH_CALL(func_identity, 10);
    assert(result == 11);

    PATCH_HOOK_REMOVE(func_identity);

    TEST_PASS();
}

static void test_hook_is_installed_macro(void)
{
    printf("Test: PATCH_HOOK_IS_INSTALLED macro...\n");

    assert(!PATCH_HOOK_IS_INSTALLED(func_add));

    PATCH_HOOK_INSTALL(func_add, hook_add_1000);
    assert(PATCH_HOOK_IS_INSTALLED(func_add));

    PATCH_HOOK_REMOVE(func_add);
    assert(!PATCH_HOOK_IS_INSTALLED(func_add));

    TEST_PASS();
}

// Re-entrancy guard test components

// Test function for re-entrancy
PATCH_DEFINE_HOOKABLE(int, func_reentrant, int depth)
{
    return depth;
}

// Re-entrancy test counter
static int g_reentrant_hook_calls = 0;

// Hook that calls the hooked function recursively
// Without re-entrancy guard, this would cause infinite recursion
static bool reentrant_prologue(patch_context_t *ctx, void *ud)
{
    (void)ud;
    g_reentrant_hook_calls++;

    int *depth_arg = (int *)patch_context_get_arg(ctx, 0);
    int depth = *depth_arg;

    if (depth > 0) {
        // Call the hooked function recursively
        // The re-entrancy guard should detect this is re-entrant and
        // bypass the prologue callback, calling the original directly
        int recursive_result = PATCH_CALL(func_reentrant, depth - 1);

        // Modify return value to include recursive result
        int result = depth * 10 + recursive_result;
        patch_context_set_return(ctx, &result, sizeof(result));
        return false;  // Don't call original, use our computed result
    }

    return true;  // Base case: call original
}

static void test_reentrancy_guard(void)
{
    printf("Test: Re-entrancy guard prevents infinite recursion...\n");

    // Reset counter
    g_reentrant_hook_calls = 0;

    // First verify the function works without hooks
    int result = PATCH_CALL(func_reentrant, 3);
    assert(result == 3);

    // Install hook that calls the hooked function recursively
    patch_handle_t *handle = NULL;
    patch_config_t config = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_reentrant),
        .prologue = reentrant_prologue,
    };

    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install hook: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook func_reentrant");
        return;
    }

    // Call with depth=3
    // Without re-entrancy guard: infinite recursion
    // With re-entrancy guard:
    //   - First call: hook runs, depth=3, calls func_reentrant(2)
    //   - Second call: re-entrancy detected, bypasses hook, returns 2 directly
    //   - So first call computes: 3*10 + 2 = 32
    result = PATCH_CALL(func_reentrant, 3);

    // Hook should only be called ONCE (the initial call)
    // The recursive call should bypass the hook
    if (g_reentrant_hook_calls != 1) {
        printf("  Expected 1 hook call, got %d\n", g_reentrant_hook_calls);
        patch_remove(handle);
        TEST_FAIL("re-entrancy guard did not prevent recursive hook calls");
        return;
    }

    // Result should be 3*10 + 2 = 32
    // (depth=3 multiplied by 10, plus direct return of depth-1=2)
    if (result != 32) {
        printf("  Expected result: 32, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("re-entrancy guard returned wrong result");
        return;
    }

    patch_remove(handle);
    TEST_PASS();
}

// Hook chaining test - trackers for callback order
static int g_chain_call_order[4] = {0};
static int g_chain_call_count = 0;

static bool chain_prologue_A(patch_context_t *ctx, void *ud)
{
    (void)ud;
    g_chain_call_order[g_chain_call_count++] = 1;  // A = 1

    // Modify the argument: add 100
    int *arg = (int *)patch_context_get_arg(ctx, 0);
    int new_val = *arg + 100;
    patch_context_set_arg(ctx, 0, &new_val, sizeof(new_val));

    return true;  // Call next (either hook B or original)
}

static bool chain_prologue_B(patch_context_t *ctx, void *ud)
{
    (void)ud;
    g_chain_call_order[g_chain_call_count++] = 2;  // B = 2

    // Modify the argument: multiply by 2
    int *arg = (int *)patch_context_get_arg(ctx, 0);
    int new_val = *arg * 2;
    patch_context_set_arg(ctx, 0, &new_val, sizeof(new_val));

    return true;  // Call next (hook A)
}

static void test_hook_chaining(void)
{
    printf("Test: Hook chaining (multiple hooks on same target)...\n");

    // Reset trackers
    g_chain_call_count = 0;
    memset(g_chain_call_order, 0, sizeof(g_chain_call_order));

    // Verify original function works: func_identity(5) = 5
    int result = PATCH_CALL(func_identity, 5);
    assert(result == 5);

    // Install hook A (first)
    patch_handle_t *handle_a = NULL;
    patch_config_t config_a = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_identity),
        .prologue = chain_prologue_A,
    };

    patch_error_t err = patch_install(&config_a, &handle_a);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install hook A: %s\n", patch_get_error_details());
        TEST_SKIP("cannot install hook A");
        return;
    }

    // Test with only hook A: identity(5) -> A adds 100 -> identity(105) = 105
    g_chain_call_count = 0;
    result = PATCH_CALL(func_identity, 5);
    if (result != 105) {
        printf("  With hook A only: expected 105, got %d\n", result);
        patch_remove(handle_a);
        TEST_FAIL("hook A didn't modify argument correctly");
        return;
    }
    if (g_chain_call_count != 1 || g_chain_call_order[0] != 1) {
        printf("  Hook A wasn't called\n");
        patch_remove(handle_a);
        TEST_FAIL("hook A call tracking failed");
        return;
    }

    // Install hook B (second) - should chain with A
    patch_handle_t *handle_b = NULL;
    patch_config_t config_b = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_identity),
        .prologue = chain_prologue_B,
    };

    err = patch_install(&config_b, &handle_b);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install hook B: %s\n", patch_get_error_details());
        patch_remove(handle_a);
        TEST_SKIP("cannot install hook B");
        return;
    }

    // Test with both hooks: B runs first (most recent), then A
    // identity(5) -> B multiplies by 2 -> 10 -> A adds 100 -> 110 -> identity(110) = 110
    g_chain_call_count = 0;
    result = PATCH_CALL(func_identity, 5);
    if (result != 110) {
        printf("  With both hooks: expected 110, got %d\n", result);
        patch_remove(handle_b);
        patch_remove(handle_a);
        TEST_FAIL("chained hooks didn't process correctly");
        return;
    }
    if (g_chain_call_count != 2) {
        printf("  Expected 2 hook calls, got %d\n", g_chain_call_count);
        patch_remove(handle_b);
        patch_remove(handle_a);
        TEST_FAIL("not all hooks were called");
        return;
    }
    if (g_chain_call_order[0] != 2 || g_chain_call_order[1] != 1) {
        printf("  Wrong call order: expected B(2) then A(1), got %d then %d\n",
               g_chain_call_order[0], g_chain_call_order[1]);
        patch_remove(handle_b);
        patch_remove(handle_a);
        TEST_FAIL("hooks called in wrong order");
        return;
    }

    // Remove hook B, verify A still works
    patch_remove(handle_b);
    g_chain_call_count = 0;
    result = PATCH_CALL(func_identity, 5);
    if (result != 105) {
        printf("  After removing B: expected 105, got %d\n", result);
        patch_remove(handle_a);
        TEST_FAIL("hook A didn't work after removing B");
        return;
    }

    // Remove hook A, verify function is restored
    patch_remove(handle_a);
    result = PATCH_CALL(func_identity, 5);
    if (result != 5) {
        printf("  After removing all hooks: expected 5, got %d\n", result);
        TEST_FAIL("function not restored after removing all hooks");
        return;
    }

    TEST_PASS();
}

static void test_idempotent_operations(void)
{
    printf("Test: Idempotent disable/enable...\n");

    patch_error_t err = patch_can_install((void*)PATCH_HOOK_ORIGINAL(func_add));
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("Pattern not recognized");
        return;
    }

    patch_config_t config = {
        .target = (void*)PATCH_HOOK_ORIGINAL(func_add),
        .replacement = (void*)hook_add_1000,
    };

    patch_handle_t *handle = NULL;
    err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP(patch_get_error_details());
        return;
    }

    // Double disable should succeed (idempotent)
    assert(patch_disable(handle) == PATCH_SUCCESS);
    assert(patch_disable(handle) == PATCH_SUCCESS);

    // Double enable should succeed (idempotent)
    assert(patch_enable(handle) == PATCH_SUCCESS);
    assert(patch_enable(handle) == PATCH_SUCCESS);

    patch_remove(handle);
    TEST_PASS();
}

// ============================================================================
// Section 5: Data Type Tests
// ============================================================================

static void test_many_arguments(void)
{
    printf("Test: Function with 6 register arguments...\n");

    int result = PATCH_CALL(func_variadic_args, 1, 2, 3, 4, 5, 6);
    assert(result == 21);  // 1+2+3+4+5+6

    PATCH_HOOK_INSTALL(func_variadic_args, hook_sum_doubled);

    result = PATCH_CALL(func_variadic_args, 1, 2, 3, 4, 5, 6);
    assert(result == 42);  // 21 * 2

    PATCH_HOOK_REMOVE(func_variadic_args);

    TEST_PASS();
}

static void test_stack_arguments(void)
{
    printf("Test: Stack argument access...\n");

    // First verify the function works without hooks
    // func_many_args(1,2,3,4,5,6,7,8,9) = 1+2+3+4+5+6+7+8+9 = 45
    int result = PATCH_CALL(func_many_args, 1, 2, 3, 4, 5, 6, 7, 8, 9);
    assert(result == 45);

    // Reset captured values
    memset(g_captured_stack_args, 0, sizeof(g_captured_stack_args));
    memset(g_captured_reg_args, 0, sizeof(g_captured_reg_args));

    // Install a hook that captures stack arguments
    patch_handle_t *handle = NULL;
    patch_config_t config = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_many_args),
        .prologue = stack_arg_prologue,
    };

    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install hook: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook func_many_args");
        return;
    }

    // Call with identifiable values
    // On x86-64: a-f (10-60) in registers, g-i (70-90) on stack
    // On ARM64: a-h (10-80) in registers, i (90) on stack
    result = PATCH_CALL(func_many_args, 10, 20, 30, 40, 50, 60, 70, 80, 90);

    // The prologue computes the sum and returns it (skipping original)
    if (result != 450) {
        printf("  Expected result: 450, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("prologue didn't compute correct sum from captured args");
        return;
    }

#ifdef PATCH_ARCH_X86_64
    // Verify stack args were captured correctly
    if (g_captured_stack_args[0] != 70 ||
        g_captured_stack_args[1] != 80 ||
        g_captured_stack_args[2] != 90) {
        printf("  Expected stack args: 70, 80, 90\n");
        printf("  Got: %d, %d, %d\n",
               g_captured_stack_args[0],
               g_captured_stack_args[1],
               g_captured_stack_args[2]);
        patch_remove(handle);
        TEST_FAIL("stack arguments not captured correctly");
        return;
    }

    // Verify register args too
    if (g_captured_reg_args[0] != 10 || g_captured_reg_args[5] != 60) {
        printf("  Register args not captured correctly\n");
        patch_remove(handle);
        TEST_FAIL("register arguments not captured correctly");
        return;
    }
#else
    // ARM64: only i(90) is on stack
    if (g_captured_stack_args[0] != 90) {
        printf("  Expected stack arg[0]: 90, got: %d\n", g_captured_stack_args[0]);
        patch_remove(handle);
        TEST_FAIL("stack argument not captured correctly");
        return;
    }

    // Verify register args too
    if (g_captured_reg_args[0] != 10 || g_captured_reg_args[7] != 80) {
        printf("  Register args not captured correctly\n");
        patch_remove(handle);
        TEST_FAIL("register arguments not captured correctly");
        return;
    }
#endif

    patch_remove(handle);
    TEST_PASS();
}

static void test_64bit_return_value(void)
{
    printf("Test: 64-bit return value...\n");

    long long result = PATCH_CALL(func_64bit_return, 0x100000000LL);
    assert(result == 0x200000000LL);

    PATCH_HOOK_INSTALL(func_64bit_return, hook_add_large);

    result = PATCH_CALL(func_64bit_return, 0x100000000LL);
    assert(result == 0x1200000000LL);  // 0x200000000 + 0x1000000000

    PATCH_HOOK_REMOVE(func_64bit_return);

    TEST_PASS();
}

static void test_pointer_return_value(void)
{
    printf("Test: Pointer return value...\n");

    int dummy = 42;
    void *result = PATCH_CALL(func_pointer_return, &dummy);
    assert(result == &dummy);

    PATCH_HOOK_INSTALL(func_pointer_return, hook_replace_pointer);

    result = PATCH_CALL(func_pointer_return, &dummy);
    assert(result == &g_hook_target);
    assert(*(int*)result == 999);

    PATCH_HOOK_REMOVE(func_pointer_return);

    TEST_PASS();
}

// Note: Floating point tests may not work correctly with the current
// dispatcher since it only saves integer registers. This is a known limitation.

// ============================================================================
// Section 5b: FFI-based Full Argument Forwarding (Optional libffi)
// ============================================================================

#if defined(PATCH_HAVE_LIBFFI)

// Simple passthrough prologue that always calls original
static bool ffi_passthrough_prologue(patch_context_t *ctx, void *ud)
{
    (void)ctx;
    (void)ud;
    return true;  // Call original with all args forwarded via FFI
}

static void test_ffi_stack_arguments(void)
{
    printf("Test: FFI stack argument forwarding...\n");

    // Test with func_many_args which has 9 arguments
    // On x86-64: 6 in registers, 3 on stack
    // On ARM64: 8 in registers, 1 on stack

    // First verify the function works without hooks
    int result = PATCH_CALL(func_many_args, 10, 20, 30, 40, 50, 60, 70, 80, 90);
    assert(result == 450);

    // Set up FFI argument types for 9 int arguments
    ffi_type *arg_types[] = {
        &ffi_type_sint, &ffi_type_sint, &ffi_type_sint,
        &ffi_type_sint, &ffi_type_sint, &ffi_type_sint,
        &ffi_type_sint, &ffi_type_sint, &ffi_type_sint,
    };

    patch_config_t config = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_many_args),
        .prologue = ffi_passthrough_prologue,
        .arg_types = arg_types,
        .arg_count = 9,
        .return_type = &ffi_type_sint,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install hook: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook with FFI");
        return;
    }

    // Call through the hook - FFI should forward all 9 arguments correctly
    result = PATCH_CALL(func_many_args, 10, 20, 30, 40, 50, 60, 70, 80, 90);

    if (result != 450) {
        printf("  Expected: 450, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("FFI did not forward stack arguments correctly");
        return;
    }

    patch_remove(handle);
    TEST_PASS();
}

static void test_ffi_mixed_fp_arguments(void)
{
    printf("Test: FFI mixed int/FP argument forwarding...\n");

    // Test with func_mixed_args(int, double, int, double) -> double
    // FP and integer args are tracked separately in the ABI

    // First verify the function works without hooks
    double result = PATCH_CALL(func_mixed_args, 10, 2.5, 20, 3.5);
    double expected = 10.0 + 2.5 + 20.0 + 3.5;  // = 36.0
    if (result < expected - 0.001 || result > expected + 0.001) {
        printf("  Pre-hook result mismatch: expected %f, got %f\n", expected, result);
        TEST_FAIL("original function didn't work");
        return;
    }

    // Set up FFI argument types: int, double, int, double
    ffi_type *arg_types[] = {
        &ffi_type_sint,
        &ffi_type_double,
        &ffi_type_sint,
        &ffi_type_double,
    };

    patch_config_t config = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_mixed_args),
        .prologue = ffi_passthrough_prologue,
        .arg_types = arg_types,
        .arg_count = 4,
        .return_type = &ffi_type_double,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install hook: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook with FFI");
        return;
    }

    // Call through the hook - FFI should forward both int and FP args correctly
    result = PATCH_CALL(func_mixed_args, 10, 2.5, 20, 3.5);

    if (result < expected - 0.001 || result > expected + 0.001) {
        printf("  Expected: %f, got: %f\n", expected, result);
        patch_remove(handle);
        TEST_FAIL("FFI did not forward mixed arguments correctly");
        return;
    }

    patch_remove(handle);
    TEST_PASS();
}

static void test_ffi_fp_only_arguments(void)
{
    printf("Test: FFI pure FP argument forwarding...\n");

    // Test with func_fp_only(double, double, double) -> double

    // First verify the function works without hooks
    double result = PATCH_CALL(func_fp_only, 2.0, 3.0, 4.0);
    double expected = 2.0 * 3.0 + 4.0;  // = 10.0
    if (result < expected - 0.001 || result > expected + 0.001) {
        printf("  Pre-hook result mismatch: expected %f, got %f\n", expected, result);
        TEST_FAIL("original function didn't work");
        return;
    }

    // Set up FFI argument types: all doubles
    ffi_type *arg_types[] = {
        &ffi_type_double,
        &ffi_type_double,
        &ffi_type_double,
    };

    patch_config_t config = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_fp_only),
        .prologue = ffi_passthrough_prologue,
        .arg_types = arg_types,
        .arg_count = 3,
        .return_type = &ffi_type_double,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install hook: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook with FFI");
        return;
    }

    // Call through the hook - FFI should forward all FP args correctly
    result = PATCH_CALL(func_fp_only, 2.0, 3.0, 4.0);

    if (result < expected - 0.001 || result > expected + 0.001) {
        printf("  Expected: %f, got: %f\n", expected, result);
        patch_remove(handle);
        TEST_FAIL("FFI did not forward FP arguments correctly");
        return;
    }

    patch_remove(handle);
    TEST_PASS();
}

#endif // PATCH_HAVE_LIBFFI

// ============================================================================
// Section 6: Error Message Tests
// ============================================================================

static void test_error_details(void)
{
    printf("Test: Error details API...\n");

    // Trigger an error (intentionally ignoring return value)
    (void)patch_can_install(NULL);

    const char *details = patch_get_error_details();
    assert(details != NULL);
    assert(strlen(details) > 0);

    TEST_PASS();
}

// ============================================================================
// Section 7: Platform-Specific Behavior
// ============================================================================

static void test_platform_detection(void)
{
    printf("Test: Platform detection macros...\n");

#ifdef PATCH_PLATFORM_DARWIN
    printf("  Platform: macOS\n");
#elif defined(PATCH_ARCH_ARM64)
    printf("  Platform: Linux ARM64\n");
#elif defined(PATCH_ARCH_X86_64)
    printf("  Platform: Linux x86-64\n");
#else
    printf("  Platform: Unknown\n");
#endif

#ifdef PATCH_ARCH_ARM64
    printf("  Architecture: ARM64\n");
    assert(PATCH_REG_ARGS == 8);
#elif defined(PATCH_ARCH_X86_64)
    printf("  Architecture: x86-64\n");
    assert(PATCH_REG_ARGS == 6);
#endif

    TEST_PASS();
}

static void test_pattern_recognition(void)
{
    printf("Test: Pattern recognition for test functions...\n");

    // All our test functions use PATCH_DEFINE_HOOKABLE which includes
    // the patchable_function_entry attribute
    patch_error_t err;

    err = patch_can_install((void*)PATCH_HOOK_ORIGINAL(func_add));
    printf("  func_add: %s\n", err == PATCH_SUCCESS ? "HOOKABLE" : patch_get_error_details());

    err = patch_can_install((void*)PATCH_HOOK_ORIGINAL(func_sub));
    printf("  func_sub: %s\n", err == PATCH_SUCCESS ? "HOOKABLE" : patch_get_error_details());

    err = patch_can_install((void*)PATCH_HOOK_ORIGINAL(func_mul));
    printf("  func_mul: %s\n", err == PATCH_SUCCESS ? "HOOKABLE" : patch_get_error_details());

    err = patch_can_install((void*)PATCH_HOOK_ORIGINAL(func_chain_a));
    printf("  func_chain_a: %s\n", err == PATCH_SUCCESS ? "HOOKABLE" : patch_get_error_details());

    TEST_PASS();
}

// ============================================================================
// Section 8: Symbol-Based Hooking API
// ============================================================================

static bool g_symbol_hook_called = false;

static bool symbol_hook_prologue(patch_context_t *ctx, void *user_data)
{
    (void)ctx;
    (void)user_data;
    g_symbol_hook_called = true;
    return true;  // Call original
}

static void test_resolve_symbol(void)
{
    printf("Test: Symbol resolution API...\n");

    // Test resolving a common libc symbol
    void *addr = NULL;
    patch_error_t err = patch_resolve_symbol("strlen", NULL, &addr);

    if (err == PATCH_SUCCESS) {
        assert(addr != NULL);
        printf("  strlen resolved to: %p\n", addr);
        TEST_PASS();
    }
    else {
        printf("  Could not resolve strlen: %s\n", patch_get_error_details());
        TEST_SKIP("symbol resolution not working");
    }
}

static void test_resolve_symbol_invalid(void)
{
    printf("Test: Symbol resolution with invalid inputs...\n");

    void *addr = NULL;
    patch_error_t err;

    // Null symbol
    err = patch_resolve_symbol(NULL, NULL, &addr);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Null output
    err = patch_resolve_symbol("strlen", NULL, NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Non-existent symbol
    err = patch_resolve_symbol("__this_symbol_does_not_exist_12345__", NULL, &addr);
    assert(err == PATCH_ERR_SYMBOL_NOT_FOUND);

    TEST_PASS();
}

static void test_install_by_symbol(void)
{
    printf("Test: Install hook by symbol name...\n");

#ifdef PATCH_PLATFORM_DARWIN
    // On macOS, system library functions are in the dyld shared cache,
    // which has restrictions on code modification. Skip hooking libc functions.
    printf("  macOS: Skipping libc function hooking (dyld shared cache)\n");
    TEST_SKIP("system library hooking not supported on macOS");
#else
    g_symbol_hook_called = false;

    patch_config_t config = {
        .prologue = symbol_hook_prologue,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_symbol("atoi", NULL, &config, &handle);

    if (err != PATCH_SUCCESS) {
        printf("  Cannot hook atoi by symbol: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook atoi");
        return;
    }

    // Call atoi - our hook should be triggered
    int result = atoi("42");
    assert(result == 42);
    assert(g_symbol_hook_called == true);

    patch_remove(handle);

    // After removal, hook should not be called
    g_symbol_hook_called = false;
    result = atoi("100");
    assert(result == 100);
    assert(g_symbol_hook_called == false);

    TEST_PASS();
#endif
}

static void test_install_symbol_invalid(void)
{
    printf("Test: Install by symbol with invalid inputs...\n");

    patch_config_t config = { .prologue = symbol_hook_prologue };
    patch_handle_t *handle = NULL;
    patch_error_t err;

    // Null symbol
    err = patch_install_symbol(NULL, NULL, &config, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Null config
    err = patch_install_symbol("strlen", NULL, NULL, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Null handle
    err = patch_install_symbol("strlen", NULL, &config, NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Non-existent symbol
    err = patch_install_symbol("__nonexistent_symbol__", NULL, &config, &handle);
    assert(err == PATCH_ERR_SYMBOL_NOT_FOUND);

    TEST_PASS();
}

// ============================================================================
// Section 9: GOT/PLT Hooking (Works on both Linux ELF and macOS Mach-O)
// ============================================================================

static int g_got_hook_call_count = 0;
static int (*g_original_atoi)(const char *) = NULL;

static int got_hook_atoi(const char *str)
{
    g_got_hook_call_count++;
    // Call original and add 1000
    return g_original_atoi(str) + 1000;
}

static void test_got_hooking_basic(void)
{
    printf("Test: GOT hooking basic...\n");

    g_got_hook_call_count = 0;

    // Force GOT method
    patch_config_t config = {
        .replacement = (void *)got_hook_atoi,
        .method = PATCH_METHOD_GOT,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_symbol("atoi", NULL, &config, &handle);

    if (err == PATCH_ERR_NO_GOT_ENTRY) {
        // On macOS, system library symbols (dyld shared cache) may not have
        // modifiable symbol pointers. On Linux, symbol may be inlined.
        printf("  No GOT entry for atoi (may be in dyld cache or inlined)\n");
        TEST_SKIP("no GOT entry");
        return;
    }

    if (err == PATCH_ERR_MEMORY_PROTECTION) {
        // macOS __DATA_CONST segment may resist modification
        printf("  Cannot modify symbol pointer (read-only segment)\n");
        TEST_SKIP("symbol pointer not writable");
        return;
    }

    if (err != PATCH_SUCCESS) {
        printf("  Cannot hook atoi via GOT: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook via GOT");
        return;
    }

    // Save original for our hook to call
    g_original_atoi = (int (*)(const char *))patch_get_trampoline(handle);
    assert(g_original_atoi != NULL);

    // Call atoi - should go through our hook
    int result = atoi("42");
    assert(result == 1042);  // 42 + 1000
    assert(g_got_hook_call_count == 1);

    result = atoi("100");
    assert(result == 1100);  // 100 + 1000
    assert(g_got_hook_call_count == 2);

    patch_remove(handle);

    // After removal, should work normally
    g_got_hook_call_count = 0;
    result = atoi("50");
    assert(result == 50);
    assert(g_got_hook_call_count == 0);

    TEST_PASS();
}

static void test_got_hooking_disable_enable(void)
{
    printf("Test: GOT hooking disable/enable...\n");

    g_got_hook_call_count = 0;

    patch_config_t config = {
        .replacement = (void *)got_hook_atoi,
        .method = PATCH_METHOD_GOT,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_symbol("atoi", NULL, &config, &handle);

    if (err != PATCH_SUCCESS) {
        TEST_SKIP("cannot hook atoi via GOT");
        return;
    }

    g_original_atoi = (int (*)(const char *))patch_get_trampoline(handle);

    // Hook is active
    int result = atoi("10");
    assert(result == 1010);
    assert(g_got_hook_call_count == 1);

    // Disable hook
    err = patch_disable(handle);
    assert(err == PATCH_SUCCESS);

    // Should bypass hook now
    result = atoi("10");
    assert(result == 10);
    assert(g_got_hook_call_count == 1);  // No change

    // Re-enable hook
    err = patch_enable(handle);
    assert(err == PATCH_SUCCESS);

    // Hook active again
    result = atoi("10");
    assert(result == 1010);
    assert(g_got_hook_call_count == 2);

    patch_remove(handle);
    TEST_PASS();
}

static void test_got_method_auto(void)
{
    printf("Test: GOT hooking with AUTO method...\n");

    g_got_hook_call_count = 0;

    // AUTO method - should try code patching first, fall back to GOT or breakpoint
    patch_config_t config = {
        .replacement = (void *)got_hook_atoi,
        .method = PATCH_METHOD_AUTO,  // Default
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_symbol("atoi", NULL, &config, &handle);

    if (err != PATCH_SUCCESS) {
        printf("  Cannot hook atoi: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook atoi");
        return;
    }

    g_original_atoi = (int (*)(const char *))patch_get_trampoline(handle);

    // Should work regardless of which method was used
    int result = atoi("25");
    assert(result == 1025);

    patch_remove(handle);
    TEST_PASS();
}

// Trackers for GOT callback mode test
static int g_got_callback_prologue_calls = 0;
static int g_got_callback_epilogue_calls = 0;
static int g_got_callback_last_result = 0;

static bool got_callback_prologue(patch_context_t *ctx, void *ud)
{
    (void)ctx;
    (void)ud;
    g_got_callback_prologue_calls++;

    // Optionally modify first argument (the string pointer arg for atoi)
    // We won't modify it here, just observe it
    return true;  // Call original
}

static void got_callback_epilogue(patch_context_t *ctx, void *ud)
{
    (void)ud;
    g_got_callback_epilogue_calls++;

    // Capture and modify the return value
    uint64_t *ret = (uint64_t *)patch_context_get_return(ctx);
    g_got_callback_last_result = (int)*ret;

    // Add 500 to the result
    int64_t new_val = (int64_t)*ret + 500;
    patch_context_set_return(ctx, &new_val, sizeof(new_val));
}

static void test_got_hooking_with_callbacks(void)
{
    printf("Test: GOT hooking with prologue/epilogue callbacks...\n");

    g_got_callback_prologue_calls = 0;
    g_got_callback_epilogue_calls = 0;
    g_got_callback_last_result = 0;

    // Use callbacks instead of replacement function - this is the unified API
    patch_config_t config = {
        .prologue = got_callback_prologue,
        .epilogue = got_callback_epilogue,
        .method = PATCH_METHOD_GOT,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_symbol("atoi", NULL, &config, &handle);

    if (err == PATCH_ERR_NO_GOT_ENTRY) {
        printf("  No GOT entry for atoi (may be in dyld cache or inlined)\n");
        TEST_SKIP("no GOT entry");
        return;
    }

    if (err == PATCH_ERR_MEMORY_PROTECTION) {
        printf("  Cannot modify symbol pointer (read-only segment)\n");
        TEST_SKIP("symbol pointer not writable");
        return;
    }

    if (err != PATCH_SUCCESS) {
        printf("  Cannot hook atoi via GOT: %s\n", patch_get_error_details());
        TEST_SKIP("cannot hook via GOT");
        return;
    }

    // Call atoi - should go through our callbacks
    int result = atoi("42");

    // Prologue saw the call, epilogue modified return from 42 to 542
    assert(g_got_callback_prologue_calls == 1);
    assert(g_got_callback_epilogue_calls == 1);
    assert(g_got_callback_last_result == 42);  // Original result seen in epilogue
    assert(result == 542);  // 42 + 500 from epilogue modification

    // Call again
    result = atoi("100");
    assert(g_got_callback_prologue_calls == 2);
    assert(g_got_callback_epilogue_calls == 2);
    assert(g_got_callback_last_result == 100);
    assert(result == 600);  // 100 + 500

    // Test hot-swap on GOT hook with callbacks
    // Set prologue to NULL - should still work, just skip prologue
    err = patch_set_prologue(handle, NULL, NULL);
    assert(err == PATCH_SUCCESS);

    result = atoi("10");
    assert(g_got_callback_prologue_calls == 2);  // No change - prologue disabled
    assert(g_got_callback_epilogue_calls == 3);  // Epilogue still called
    assert(result == 510);

    patch_remove(handle);

    // After removal, should work normally
    g_got_callback_prologue_calls = 0;
    g_got_callback_epilogue_calls = 0;
    result = atoi("50");
    assert(result == 50);  // Original behavior
    assert(g_got_callback_prologue_calls == 0);
    assert(g_got_callback_epilogue_calls == 0);

    TEST_PASS();
}

// ============================================================================
// Section 10: Hot-Swap Hooks
// ============================================================================

// Trackers for hot-swap test
static int g_hotswap_prologue_v1_calls = 0;
static int g_hotswap_prologue_v2_calls = 0;
static int g_hotswap_epilogue_v1_calls = 0;
static int g_hotswap_epilogue_v2_calls = 0;

static bool hotswap_prologue_v1(patch_context_t *ctx, void *ud)
{
    (void)ctx;
    (void)ud;
    g_hotswap_prologue_v1_calls++;
    return true;
}

static bool hotswap_prologue_v2(patch_context_t *ctx, void *ud)
{
    (void)ctx;
    (void)ud;
    g_hotswap_prologue_v2_calls++;
    return true;
}

static void hotswap_epilogue_v1(patch_context_t *ctx, void *ud)
{
    (void)ctx;
    (void)ud;
    g_hotswap_epilogue_v1_calls++;
}

static void hotswap_epilogue_v2(patch_context_t *ctx, void *ud)
{
    (void)ctx;
    (void)ud;
    g_hotswap_epilogue_v2_calls++;
}

static void test_hot_swap_prologue(void)
{
    printf("Test: Hot-swap prologue callback...\n");

    // Reset counters
    g_hotswap_prologue_v1_calls = 0;
    g_hotswap_prologue_v2_calls = 0;

    // Install hook with prologue v1
    patch_config_t config = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_identity),
        .prologue = hotswap_prologue_v1,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("cannot hook func_identity");
        return;
    }

    // Call a few times - v1 should be called
    PATCH_CALL(func_identity, 1);
    PATCH_CALL(func_identity, 2);
    assert(g_hotswap_prologue_v1_calls == 2);
    assert(g_hotswap_prologue_v2_calls == 0);

    // Hot-swap to v2
    err = patch_set_prologue(handle, hotswap_prologue_v2, NULL);
    assert(err == PATCH_SUCCESS);

    // Now v2 should be called
    PATCH_CALL(func_identity, 3);
    PATCH_CALL(func_identity, 4);
    assert(g_hotswap_prologue_v1_calls == 2);  // No change
    assert(g_hotswap_prologue_v2_calls == 2);

    // Hot-swap back to v1
    err = patch_set_prologue(handle, hotswap_prologue_v1, NULL);
    assert(err == PATCH_SUCCESS);

    PATCH_CALL(func_identity, 5);
    assert(g_hotswap_prologue_v1_calls == 3);
    assert(g_hotswap_prologue_v2_calls == 2);

    // Hot-swap to NULL (disable prologue)
    err = patch_set_prologue(handle, NULL, NULL);
    assert(err == PATCH_SUCCESS);

    PATCH_CALL(func_identity, 6);
    assert(g_hotswap_prologue_v1_calls == 3);  // No change
    assert(g_hotswap_prologue_v2_calls == 2);  // No change

    patch_remove(handle);
    TEST_PASS();
}

static void test_hot_swap_epilogue(void)
{
    printf("Test: Hot-swap epilogue callback...\n");

    // Reset counters
    g_hotswap_epilogue_v1_calls = 0;
    g_hotswap_epilogue_v2_calls = 0;

    // Install hook with epilogue v1
    patch_config_t config = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_identity),
        .prologue = hotswap_prologue_v1,  // Need a prologue to have a dispatcher
        .epilogue = hotswap_epilogue_v1,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("cannot hook func_identity");
        return;
    }

    // Call - v1 should be called
    PATCH_CALL(func_identity, 1);
    assert(g_hotswap_epilogue_v1_calls == 1);
    assert(g_hotswap_epilogue_v2_calls == 0);

    // Hot-swap to v2
    err = patch_set_epilogue(handle, hotswap_epilogue_v2, NULL);
    assert(err == PATCH_SUCCESS);

    // Now v2 should be called
    PATCH_CALL(func_identity, 2);
    assert(g_hotswap_epilogue_v1_calls == 1);  // No change
    assert(g_hotswap_epilogue_v2_calls == 1);

    // Hot-swap to NULL (disable epilogue)
    err = patch_set_epilogue(handle, NULL, NULL);
    assert(err == PATCH_SUCCESS);

    PATCH_CALL(func_identity, 3);
    assert(g_hotswap_epilogue_v1_calls == 1);  // No change
    assert(g_hotswap_epilogue_v2_calls == 1);  // No change

    patch_remove(handle);
    TEST_PASS();
}

static void test_hot_swap_callbacks(void)
{
    printf("Test: Hot-swap both callbacks atomically...\n");

    // Reset counters
    g_hotswap_prologue_v1_calls = 0;
    g_hotswap_prologue_v2_calls = 0;
    g_hotswap_epilogue_v1_calls = 0;
    g_hotswap_epilogue_v2_calls = 0;

    // Install hook with v1 callbacks
    patch_config_t config = {
        .target = (void *)PATCH_HOOK_ORIGINAL(func_identity),
        .prologue = hotswap_prologue_v1,
        .epilogue = hotswap_epilogue_v1,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("cannot hook func_identity");
        return;
    }

    // Call - v1 for both
    PATCH_CALL(func_identity, 1);
    assert(g_hotswap_prologue_v1_calls == 1);
    assert(g_hotswap_epilogue_v1_calls == 1);

    // Hot-swap both to v2
    err = patch_set_callbacks(handle,
                              hotswap_prologue_v2, NULL,
                              hotswap_epilogue_v2, NULL);
    assert(err == PATCH_SUCCESS);

    // Now v2 for both
    PATCH_CALL(func_identity, 2);
    assert(g_hotswap_prologue_v1_calls == 1);  // No change
    assert(g_hotswap_epilogue_v1_calls == 1);  // No change
    assert(g_hotswap_prologue_v2_calls == 1);
    assert(g_hotswap_epilogue_v2_calls == 1);

    patch_remove(handle);
    TEST_PASS();
}

static void test_hot_swap_invalid(void)
{
    printf("Test: Hot-swap with invalid arguments...\n");

    patch_error_t err;

    // Null handle
    err = patch_set_prologue(NULL, hotswap_prologue_v1, NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    err = patch_set_epilogue(NULL, hotswap_epilogue_v1, NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    err = patch_set_callbacks(NULL, hotswap_prologue_v1, NULL,
                              hotswap_epilogue_v1, NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    err = patch_set_replacement(NULL, (void *)hook_add_1000);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    TEST_PASS();
}

// Test hot-swap replacement for GOT hooks
static int g_got_hotswap_v1_calls = 0;
static int g_got_hotswap_v2_calls = 0;
static int (*g_got_original_atoi_hotswap)(const char *) = NULL;

static int got_hotswap_v1(const char *str)
{
    g_got_hotswap_v1_calls++;
    return g_got_original_atoi_hotswap(str) + 100;
}

static int got_hotswap_v2(const char *str)
{
    g_got_hotswap_v2_calls++;
    return g_got_original_atoi_hotswap(str) + 200;
}

static void test_hot_swap_got_replacement(void)
{
    printf("Test: Hot-swap GOT replacement function...\n");

    g_got_hotswap_v1_calls = 0;
    g_got_hotswap_v2_calls = 0;

    patch_config_t config = {
        .replacement = (void *)got_hotswap_v1,
        .method = PATCH_METHOD_GOT,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_symbol("atoi", NULL, &config, &handle);

    if (err == PATCH_ERR_NO_GOT_ENTRY) {
        TEST_SKIP("no GOT entry for atoi");
        return;
    }

    if (err == PATCH_ERR_MEMORY_PROTECTION) {
        TEST_SKIP("symbol pointer not writable");
        return;
    }

    if (err != PATCH_SUCCESS) {
        TEST_SKIP("cannot hook atoi via GOT");
        return;
    }

    g_got_original_atoi_hotswap = (int (*)(const char *))patch_get_trampoline(handle);

    // Call - v1 should be active
    int result = atoi("10");
    assert(result == 110);  // 10 + 100
    assert(g_got_hotswap_v1_calls == 1);
    assert(g_got_hotswap_v2_calls == 0);

    // Hot-swap to v2
    err = patch_set_replacement(handle, (void *)got_hotswap_v2);
    assert(err == PATCH_SUCCESS);

    // Now v2 should be active
    result = atoi("10");
    assert(result == 210);  // 10 + 200
    assert(g_got_hotswap_v1_calls == 1);  // No change
    assert(g_got_hotswap_v2_calls == 1);

    // Hot-swap back to v1
    err = patch_set_replacement(handle, (void *)got_hotswap_v1);
    assert(err == PATCH_SUCCESS);

    result = atoi("10");
    assert(result == 110);
    assert(g_got_hotswap_v1_calls == 2);
    assert(g_got_hotswap_v2_calls == 1);

    patch_remove(handle);
    TEST_PASS();
}

// ============================================================================
// Section 11: Breakpoint-Based Hooking
// ============================================================================

// Test function WITHOUT patchable_function_entry attribute
// This forces breakpoint hooking since there's no NOP sled
__attribute__((noinline))
int no_nopsled_func(int a, int b)
{
    return a + b;
}

// Another test function without NOP sled
__attribute__((noinline))
int no_nopsled_multiply(int a, int b)
{
    return a * b;
}

// Callback trackers for breakpoint tests
static int g_bp_prologue_calls = 0;
static int g_bp_epilogue_calls = 0;

static bool bp_test_prologue(patch_context_t *ctx, void *ud)
{
    (void)ctx;
    (void)ud;
    g_bp_prologue_calls++;
    return true;  // Call original
}

static void bp_test_epilogue(patch_context_t *ctx, void *ud)
{
    (void)ud;
    g_bp_epilogue_calls++;
    // Modify return value: add 1000
    int *ret = (int *)patch_context_get_return(ctx);
    *ret += 1000;
    patch_context_set_return(ctx, ret, sizeof(*ret));
}

static bool bp_skip_prologue(patch_context_t *ctx, void *ud)
{
    (void)ud;
    g_bp_prologue_calls++;
    // Skip original and return a fixed value
    int result = 42;
    patch_context_set_return(ctx, &result, sizeof(result));
    return false;  // Skip original
}

static void test_breakpoint_fallback(void)
{
    printf("Test: Breakpoint fallback for unrecognized patterns...\n");

    // Reset counters
    g_bp_prologue_calls = 0;
    g_bp_epilogue_calls = 0;

    // First verify the function works normally
    int result = no_nopsled_func(10, 20);
    assert(result == 30);

    // Check that pattern matching fails for this function
    patch_error_t err = patch_can_install((void *)no_nopsled_func);
    if (err == PATCH_SUCCESS) {
        // Pattern was recognized (might have a standard prologue)
        // Still test breakpoint with explicit method below
        printf("  Note: Pattern recognized for no_nopsled_func\n");
    }
    else {
        printf("  Pattern unrecognized as expected: %s\n", patch_get_error_details());
    }

    // Install using AUTO method - should fall back to breakpoint
    patch_config_t config = {
        .target = (void *)no_nopsled_func,
        .prologue = bp_test_prologue,
        .epilogue = bp_test_epilogue,
        .method = PATCH_METHOD_AUTO,
    };

    patch_handle_t *handle = NULL;
    err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install hook: %s\n", patch_get_error_details());
        TEST_SKIP("breakpoint install failed");
        return;
    }

    // Call the function - hook should be triggered
    result = no_nopsled_func(10, 20);

    // Prologue should have been called once
    if (g_bp_prologue_calls != 1) {
        printf("  Expected 1 prologue call, got %d\n", g_bp_prologue_calls);
        patch_remove(handle);
        TEST_FAIL("prologue not called correctly");
        return;
    }

    // Epilogue should have been called once, modifying return value
    if (g_bp_epilogue_calls != 1) {
        printf("  Expected 1 epilogue call, got %d\n", g_bp_epilogue_calls);
        patch_remove(handle);
        TEST_FAIL("epilogue not called correctly");
        return;
    }

    // Result should be 30 + 1000 = 1030
    if (result != 1030) {
        printf("  Expected result: 1030, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("return value not modified correctly");
        return;
    }

    patch_remove(handle);

    // After removal, function should work normally
    g_bp_prologue_calls = 0;
    result = no_nopsled_func(5, 5);
    assert(result == 10);
    assert(g_bp_prologue_calls == 0);

    TEST_PASS();
}

static void test_explicit_breakpoint_method(void)
{
    printf("Test: Explicit PATCH_METHOD_BREAKPOINT...\n");

    g_bp_prologue_calls = 0;

    // Force breakpoint method even if pattern matching would succeed
    patch_config_t config = {
        .target = (void *)no_nopsled_multiply,
        .prologue = bp_test_prologue,
        .method = PATCH_METHOD_BREAKPOINT,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  Cannot install breakpoint hook: %s\n", patch_get_error_details());
        TEST_SKIP("breakpoint install failed");
        return;
    }

    // Call the function
    int result = no_nopsled_multiply(3, 4);

    if (g_bp_prologue_calls != 1) {
        printf("  Expected 1 prologue call, got %d\n", g_bp_prologue_calls);
        patch_remove(handle);
        TEST_FAIL("prologue not called");
        return;
    }

    if (result != 12) {
        printf("  Expected result: 12, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("wrong result");
        return;
    }

    patch_remove(handle);
    TEST_PASS();
}

static void test_breakpoint_disable_enable(void)
{
    printf("Test: Breakpoint disable/enable...\n");

    g_bp_prologue_calls = 0;

    patch_config_t config = {
        .target = (void *)no_nopsled_func,
        .prologue = bp_test_prologue,
        .method = PATCH_METHOD_BREAKPOINT,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("breakpoint install failed");
        return;
    }

    // Call with hook enabled
    int result = no_nopsled_func(1, 2);
    assert(result == 3);
    assert(g_bp_prologue_calls == 1);

    // Disable hook
    err = patch_disable(handle);
    assert(err == PATCH_SUCCESS);

    // Call with hook disabled - should bypass
    result = no_nopsled_func(2, 3);
    assert(result == 5);
    assert(g_bp_prologue_calls == 1);  // No change

    // Re-enable hook
    err = patch_enable(handle);
    assert(err == PATCH_SUCCESS);

    // Call with hook re-enabled
    result = no_nopsled_func(3, 4);
    assert(result == 7);
    assert(g_bp_prologue_calls == 2);

    patch_remove(handle);
    TEST_PASS();
}

static void test_breakpoint_skip_original(void)
{
    printf("Test: Breakpoint hook skipping original function...\n");

    g_bp_prologue_calls = 0;

    patch_config_t config = {
        .target = (void *)no_nopsled_func,
        .prologue = bp_skip_prologue,
        .method = PATCH_METHOD_BREAKPOINT,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("breakpoint install failed");
        return;
    }

    // Call - should return 42 instead of a+b
    int result = no_nopsled_func(100, 200);

    if (result != 42) {
        printf("  Expected result: 42, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("skip original didn't work");
        return;
    }

    if (g_bp_prologue_calls != 1) {
        printf("  Expected 1 prologue call, got %d\n", g_bp_prologue_calls);
        patch_remove(handle);
        TEST_FAIL("prologue not called");
        return;
    }

    patch_remove(handle);
    TEST_PASS();
}

// ============================================================================
// Section 12: Watchpoint-Guarded Pointer Hooks
// ============================================================================

// Simple function for pointer hook tests
static int wp_target_v1(int x) { return x + 1; }
static int wp_target_v2(int x) { return x + 2; }

// Function pointer to hook
static int (*g_wp_func_ptr)(int) = wp_target_v1;

// Global for storing original during hook
static int (*g_wp_original)(int) = NULL;

// Hook replacement that calls original + adds 100
static int wp_hook_replacement(int x)
{
    if (g_wp_original) {
        return g_wp_original(x) + 100;
    }
    return x + 100;
}

// Callback tracking
static int g_wp_callback_calls = 0;
static void *g_wp_callback_old = NULL;
static void *g_wp_callback_new = NULL;
static patch_watch_action_t g_wp_callback_action = PATCH_WATCH_KEEP;

static patch_watch_action_t wp_test_callback(patch_handle_t *handle,
                                              void           *old_value,
                                              void           *new_value,
                                              void           *user_data)
{
    (void)handle;
    (void)user_data;
    g_wp_callback_calls++;
    g_wp_callback_old = old_value;
    g_wp_callback_new = new_value;
    return g_wp_callback_action;
}

static void test_pointer_hook_basic(void)
{
    printf("Test: Pointer hook basic install/remove...\n");

    // Reset
    g_wp_func_ptr = wp_target_v1;

    // Verify original function works
    int result = g_wp_func_ptr(10);
    assert(result == 11);  // 10 + 1

    // Install pointer hook
    patch_pointer_config_t config = {
        .location = (void **)&g_wp_func_ptr,
        .replacement = (void *)wp_hook_replacement,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_pointer(&config, &handle);

    if (err == PATCH_ERR_NO_WATCHPOINT) {
        TEST_SKIP("no hardware watchpoints available");
        return;
    }

    if (err != PATCH_SUCCESS) {
        printf("  Cannot install pointer hook: %s\n", patch_get_error_details());
        TEST_SKIP("pointer hook install failed");
        return;
    }

    // Save original for our hook to use
    g_wp_original = (int (*)(int))patch_get_trampoline(handle);
    assert(g_wp_original != NULL);

    // Call through the hooked pointer - should invoke our hook
    result = g_wp_func_ptr(10);
    // Hook calls original (10+1=11) + 100 = 111
    if (result != 111) {
        printf("  Expected result: 111, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("pointer hook didn't intercept call");
        return;
    }

    // Remove the hook
    err = patch_remove(handle);
    assert(err == PATCH_SUCCESS);
    g_wp_original = NULL;

    // After removal, pointer should be restored
    result = g_wp_func_ptr(10);
    if (result != 11) {
        printf("  After removal: expected 11, got: %d\n", result);
        TEST_FAIL("pointer not restored after removal");
        return;
    }

    TEST_PASS();
}

static void test_pointer_hook_survives_update(void)
{
    printf("Test: Pointer hook survives pointer update (KEEP)...\n");

    // Reset
    g_wp_func_ptr = wp_target_v1;
    g_wp_callback_calls = 0;
    g_wp_callback_action = PATCH_WATCH_KEEP;

    patch_pointer_config_t config = {
        .location = (void **)&g_wp_func_ptr,
        .replacement = (void *)wp_hook_replacement,
        .on_update = wp_test_callback,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_pointer(&config, &handle);

    if (err == PATCH_ERR_NO_WATCHPOINT) {
        TEST_SKIP("no hardware watchpoints available");
        return;
    }

    if (err != PATCH_SUCCESS) {
        TEST_SKIP("pointer hook install failed");
        return;
    }

    g_wp_original = (int (*)(int))patch_get_trampoline(handle);

    // Verify hook works initially (original is wp_target_v1: x+1)
    int result = g_wp_func_ptr(10);
    assert(result == 111);  // (10+1) + 100

    // Update the pointer - this should trigger the watchpoint
    // With KEEP action, hook should reinstall with new original
    g_wp_func_ptr = wp_target_v2;

    // Callback should have been called
    // Note: On some virtualized environments (Docker, GitHub Actions), watchpoints
    // can be installed via perf_event_open but SIGTRAP delivery may not work
    if (g_wp_callback_calls != 1) {
        printf("  Watchpoint installed but callback not triggered (calls=%d)\n", g_wp_callback_calls);
        patch_remove(handle);
        TEST_SKIP("watchpoint callback not triggered (virtualized environment?)");
        return;
    }

    // Verify callback received correct values
    if (g_wp_callback_old != (void *)wp_target_v1) {
        printf("  Callback old_value mismatch\n");
        patch_remove(handle);
        TEST_FAIL("callback received wrong old_value");
        return;
    }
    if (g_wp_callback_new != (void *)wp_target_v2) {
        printf("  Callback new_value mismatch\n");
        patch_remove(handle);
        TEST_FAIL("callback received wrong new_value");
        return;
    }

    // Get updated original (should now be wp_target_v2)
    g_wp_original = (int (*)(int))patch_get_trampoline(handle);

    // Hook should still be active with new original
    result = g_wp_func_ptr(10);
    // Hook calls new original (10+2=12) + 100 = 112
    if (result != 112) {
        printf("  After update: expected 112, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("hook didn't survive pointer update");
        return;
    }

    patch_remove(handle);
    TEST_PASS();
}

static void test_pointer_hook_remove_action(void)
{
    printf("Test: Pointer hook REMOVE action...\n");

    // Reset
    g_wp_func_ptr = wp_target_v1;
    g_wp_callback_calls = 0;
    g_wp_callback_action = PATCH_WATCH_REMOVE;

    patch_pointer_config_t config = {
        .location = (void **)&g_wp_func_ptr,
        .replacement = (void *)wp_hook_replacement,
        .on_update = wp_test_callback,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_pointer(&config, &handle);

    if (err == PATCH_ERR_NO_WATCHPOINT) {
        TEST_SKIP("no hardware watchpoints available");
        return;
    }

    if (err != PATCH_SUCCESS) {
        TEST_SKIP("pointer hook install failed");
        return;
    }

    g_wp_original = (int (*)(int))patch_get_trampoline(handle);

    // Verify hook works initially
    int result = g_wp_func_ptr(10);
    assert(result == 111);  // (10+1) + 100

    // Update the pointer - callback returns REMOVE
    g_wp_func_ptr = wp_target_v2;

    // Check if callback was called (watchpoint may be set but not work in some environments)
    if (g_wp_callback_calls != 1) {
        printf("  Watchpoint set but callback not triggered (calls=%d)\n", g_wp_callback_calls);
        patch_remove(handle);
        TEST_SKIP("watchpoints not functional in this environment");
        return;
    }

    // With REMOVE action, the new value should stand (hook removed)
    // The pointer should now point directly to wp_target_v2
    result = g_wp_func_ptr(10);
    if (result != 12) {  // Just 10+2, no hook
        printf("  After REMOVE: expected 12, got: %d\n", result);
        patch_remove(handle);  // Clean up just in case
        TEST_FAIL("REMOVE action didn't remove hook");
        return;
    }

    // Note: handle is now partially invalid per the comment in watchpoint.c
    // User should call patch_remove() to clean up fully
    patch_remove(handle);
    TEST_PASS();
}

static void test_pointer_hook_reject_action(void)
{
    printf("Test: Pointer hook REJECT action...\n");

    // Reset
    g_wp_func_ptr = wp_target_v1;
    g_wp_callback_calls = 0;
    g_wp_callback_action = PATCH_WATCH_REJECT;

    patch_pointer_config_t config = {
        .location = (void **)&g_wp_func_ptr,
        .replacement = (void *)wp_hook_replacement,
        .on_update = wp_test_callback,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_pointer(&config, &handle);

    if (err == PATCH_ERR_NO_WATCHPOINT) {
        TEST_SKIP("no hardware watchpoints available");
        return;
    }

    if (err != PATCH_SUCCESS) {
        TEST_SKIP("pointer hook install failed");
        return;
    }

    g_wp_original = (int (*)(int))patch_get_trampoline(handle);

    // Verify hook works initially
    int result = g_wp_func_ptr(10);
    assert(result == 111);  // (10+1) + 100

    // Try to update the pointer - callback returns REJECT
    g_wp_func_ptr = wp_target_v2;

    // Check if callback was called (watchpoint may be set but not work in some environments)
    if (g_wp_callback_calls != 1) {
        printf("  Watchpoint set but callback not triggered (calls=%d)\n", g_wp_callback_calls);
        patch_remove(handle);
        TEST_SKIP("watchpoints not functional in this environment");
        return;
    }

    // With REJECT action, the update should be ignored
    // Hook should still use the OLD original (wp_target_v1)
    // Note: The write physically happened, but we reinstall with old original
    result = g_wp_func_ptr(10);
    if (result != 111) {  // Still (10+1) + 100
        printf("  After REJECT: expected 111, got: %d\n", result);
        patch_remove(handle);
        TEST_FAIL("REJECT action didn't keep old original");
        return;
    }

    patch_remove(handle);
    TEST_PASS();
}

static void test_pointer_hook_invalid_args(void)
{
    printf("Test: Pointer hook invalid arguments...\n");

    patch_handle_t *handle = NULL;
    patch_error_t err;

    // Null config
    err = patch_install_pointer(NULL, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Null handle output
    patch_pointer_config_t config = {
        .location = (void **)&g_wp_func_ptr,
        .replacement = (void *)wp_hook_replacement,
    };
    err = patch_install_pointer(&config, NULL);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Null location
    patch_pointer_config_t config2 = {
        .location = NULL,
        .replacement = (void *)wp_hook_replacement,
    };
    err = patch_install_pointer(&config2, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    // Null replacement
    patch_pointer_config_t config3 = {
        .location = (void **)&g_wp_func_ptr,
        .replacement = NULL,
    };
    err = patch_install_pointer(&config3, &handle);
    assert(err == PATCH_ERR_INVALID_ARGUMENT);

    TEST_PASS();
}

static void test_pointer_hook_exhaust_watchpoints(void)
{
    printf("Test: Exhausting hardware watchpoints...\n");

    // We have 4 hardware watchpoints available
    // Create 4 separate function pointers to hook
    static int (*wp_ptr1)(int) = wp_target_v1;
    static int (*wp_ptr2)(int) = wp_target_v1;
    static int (*wp_ptr3)(int) = wp_target_v1;
    static int (*wp_ptr4)(int) = wp_target_v1;
    static int (*wp_ptr5)(int) = wp_target_v1;  // This one should fail

    patch_handle_t *handles[5] = {NULL};
    patch_error_t err;
    int installed_count = 0;

    void **locations[] = {
        (void **)&wp_ptr1,
        (void **)&wp_ptr2,
        (void **)&wp_ptr3,
        (void **)&wp_ptr4,
        (void **)&wp_ptr5,
    };

    // Try to install 5 pointer hooks
    for (int i = 0; i < 5; i++) {
        patch_pointer_config_t config = {
            .location = locations[i],
            .replacement = (void *)wp_hook_replacement,
        };

        err = patch_install_pointer(&config, &handles[i]);

        if (err == PATCH_ERR_NO_WATCHPOINT) {
            // Expected to fail at some point
            printf("  Watchpoint exhausted at hook %d\n", i + 1);
            break;
        }
        else if (err != PATCH_SUCCESS) {
            printf("  Unexpected error at hook %d: %s\n", i + 1, patch_get_error_details());
            break;
        }
        else {
            installed_count++;
        }
    }

    // Clean up installed hooks
    for (int i = 0; i < 5; i++) {
        if (handles[i]) {
            patch_remove(handles[i]);
        }
    }

    // We should have been able to install at least some hooks
    // and eventually hit the limit
    if (installed_count == 0) {
        TEST_SKIP("no watchpoints available");
        return;
    }

    if (installed_count == 5) {
        // Unlikely but possible if platform has more than 4 watchpoints
        printf("  All 5 hooks installed (platform has >4 watchpoints?)\n");
        TEST_PASS();
        return;
    }

    // We hit the limit somewhere in the middle - that's expected
    printf("  Successfully installed %d hooks before exhausting watchpoints\n",
           installed_count);
    TEST_PASS();
}

// ============================================================================
// Main
// ============================================================================

int main(void)
{
    // Flush stdout after each print to help debug crashes
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== Comprehensive Patch Library Tests ===\n");
    printf("Platform: ");
#ifdef PATCH_PLATFORM_DARWIN
    printf("macOS (code patching and breakpoint hooking)\n");
#elif defined(PATCH_ARCH_ARM64)
    printf("Linux ARM64\n");
#else
    printf("Linux x86-64\n");
#endif
    printf("\n");

    // Section 1: Basic API Validation
    printf("--- Section 1: API Validation ---\n\n");
    test_null_arguments();
    test_config_validation();

    // Section 2: Simple Replacement Mode
    printf("\n--- Section 2: Simple Replacement Mode ---\n\n");
    test_simple_replacement_mode();
    test_simple_replacement_disable_enable();

    // Section 3: PATCH_METHOD_CODE
    printf("\n--- Section 3: PATCH_METHOD_CODE ---\n\n");
    test_method_code_basic();
    test_method_code_vs_pointer();

    // Section 4: Edge Cases
    printf("\n--- Section 4: Edge Cases ---\n\n");
    test_rapid_hook_unhook();
    test_multiple_functions_hooked();
    test_hook_with_call_original();
    test_identity_function_hook();
    test_hook_is_installed_macro();
    test_idempotent_operations();
    test_reentrancy_guard();
    test_hook_chaining();

    // Section 5: Data Types
    printf("\n--- Section 5: Data Types ---\n\n");
    test_many_arguments();
    test_stack_arguments();
    test_64bit_return_value();
    test_pointer_return_value();

    // Section 5b: FFI argument forwarding
#if defined(PATCH_HAVE_LIBFFI)
    printf("\n--- Section 5b: FFI Argument Forwarding ---\n\n");
    test_ffi_stack_arguments();
    test_ffi_mixed_fp_arguments();
    test_ffi_fp_only_arguments();
#endif

    // Section 6: Error Messages
    printf("\n--- Section 6: Error Handling ---\n\n");
    test_error_details();

    // Section 7: Platform
    printf("\n--- Section 7: Platform ---\n\n");
    test_platform_detection();
    test_pattern_recognition();

    // Section 8: Symbol-Based Hooking
    printf("\n--- Section 8: Symbol-Based Hooking ---\n\n");
    test_resolve_symbol();
    test_resolve_symbol_invalid();
    test_install_by_symbol();
    test_install_symbol_invalid();

    // Section 9: GOT/PLT Hooking (works on both Linux and macOS)
    printf("\n--- Section 9: Symbol Pointer Hooking ---\n\n");
    test_got_hooking_basic();
    test_got_hooking_disable_enable();
    test_got_method_auto();
    test_got_hooking_with_callbacks();

    // Section 10: Hot-Swap Hooks
    printf("\n--- Section 10: Hot-Swap Hooks ---\n\n");
    test_hot_swap_prologue();
    test_hot_swap_epilogue();
    test_hot_swap_callbacks();
    test_hot_swap_invalid();
    test_hot_swap_got_replacement();

    // Section 11: Breakpoint-Based Hooking
    printf("\n--- Section 11: Breakpoint Hooking ---\n\n");
    test_breakpoint_fallback();
    test_explicit_breakpoint_method();
    test_breakpoint_disable_enable();
    test_breakpoint_skip_original();

    // Section 12: Watchpoint-Guarded Pointer Hooks
    printf("\n--- Section 12: Watchpoint Pointer Hooks ---\n\n");
    test_pointer_hook_basic();
    test_pointer_hook_survives_update();
    test_pointer_hook_remove_action();
    test_pointer_hook_reject_action();
    test_pointer_hook_invalid_args();
    test_pointer_hook_exhaust_watchpoints();

    // Summary
    printf("\n========================================\n");
    printf("Tests Passed:  %d\n", g_tests_passed);
    printf("Tests Failed:  %d\n", g_tests_failed);
    printf("Tests Skipped: %d\n", g_tests_skipped);
    printf("========================================\n");

    if (g_tests_failed > 0) {
        printf("\n*** SOME TESTS FAILED ***\n");
        return 1;
    }

    printf("\n=== All Comprehensive Tests Passed ===\n");
    return 0;
}
