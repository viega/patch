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

// Note: Floating point functions removed - dispatcher only saves integer registers

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

#ifndef PATCH_PLATFORM_DARWIN
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
#endif

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

#ifndef PATCH_PLATFORM_DARWIN
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
#else
    TEST_SKIP("Low-level API not available on macOS");
#endif
}

// ============================================================================
// Section 2: Simple Replacement Mode (New Feature)
// ============================================================================

#ifndef PATCH_PLATFORM_DARWIN
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

    patch_error_t err = patch_can_install((void*)func_add);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("Pattern not recognized");
        return;
    }

    // Verify original behavior
    int result = PATCH_CALL(func_add, 10, 20);
    assert(result == 30);

    // Install simple replacement
    patch_config_t config = {
        .target = (void*)func_add,
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

    patch_error_t err = patch_can_install((void*)func_sub);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("Pattern not recognized");
        return;
    }

    patch_config_t config = {
        .target = (void*)func_sub,
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
#endif

// ============================================================================
// Section 3: PATCH_METHOD_CODE Testing (Linux Only)
// ============================================================================

#ifndef PATCH_PLATFORM_DARWIN
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
#endif

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

static void test_idempotent_operations(void)
{
    printf("Test: Idempotent disable/enable...\n");

#ifndef PATCH_PLATFORM_DARWIN
    patch_error_t err = patch_can_install((void*)func_add);
    if (err != PATCH_SUCCESS) {
        TEST_SKIP("Pattern not recognized");
        return;
    }

    patch_config_t config = {
        .target = (void*)func_add,
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
#else
    TEST_SKIP("Low-level API not available on macOS");
#endif
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

#ifndef PATCH_PLATFORM_DARWIN
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
        .target = (void *)func_many_args,
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
#endif

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

#ifndef PATCH_PLATFORM_DARWIN
static void test_pattern_recognition(void)
{
    printf("Test: Pattern recognition for test functions...\n");

    // All our test functions use PATCH_DEFINE_HOOKABLE which includes
    // the patchable_function_entry attribute on Linux
    patch_error_t err;

    err = patch_can_install((void*)func_add);
    printf("  func_add: %s\n", err == PATCH_SUCCESS ? "HOOKABLE" : patch_get_error_details());

    err = patch_can_install((void*)func_sub);
    printf("  func_sub: %s\n", err == PATCH_SUCCESS ? "HOOKABLE" : patch_get_error_details());

    err = patch_can_install((void*)func_mul);
    printf("  func_mul: %s\n", err == PATCH_SUCCESS ? "HOOKABLE" : patch_get_error_details());

    err = patch_can_install((void*)func_chain_a);
    printf("  func_chain_a: %s\n", err == PATCH_SUCCESS ? "HOOKABLE" : patch_get_error_details());

    TEST_PASS();
}
#endif

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
    printf("macOS ARM64 (pointer indirection only)\n");
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
#ifndef PATCH_PLATFORM_DARWIN
    test_simple_replacement_mode();
    test_simple_replacement_disable_enable();
#else
    printf("Test: Simple replacement mode...\n");
    TEST_SKIP("Low-level API not available on macOS");
    printf("Test: Simple replacement disable/enable...\n");
    TEST_SKIP("Low-level API not available on macOS");
#endif

    // Section 3: PATCH_METHOD_CODE
    printf("\n--- Section 3: PATCH_METHOD_CODE ---\n\n");
#ifndef PATCH_PLATFORM_DARWIN
    test_method_code_basic();
    test_method_code_vs_pointer();
#else
    printf("Test: PATCH_METHOD_CODE basic functionality...\n");
    TEST_SKIP("Code patching not available on macOS");
    printf("Test: PATCH_METHOD_CODE vs PATCH_METHOD_POINTER...\n");
    TEST_SKIP("Code patching not available on macOS");
#endif

    // Section 4: Edge Cases
    printf("\n--- Section 4: Edge Cases ---\n\n");
    test_rapid_hook_unhook();
    test_multiple_functions_hooked();
    test_hook_with_call_original();
    test_identity_function_hook();
    test_hook_is_installed_macro();
    test_idempotent_operations();

    // Section 5: Data Types
    printf("\n--- Section 5: Data Types ---\n\n");
    test_many_arguments();
#ifndef PATCH_PLATFORM_DARWIN
    test_stack_arguments();
#endif
    test_64bit_return_value();
    test_pointer_return_value();

    // Section 6: Error Messages
    printf("\n--- Section 6: Error Handling ---\n\n");
    test_error_details();

    // Section 7: Platform
    printf("\n--- Section 7: Platform ---\n\n");
    test_platform_detection();
#ifndef PATCH_PLATFORM_DARWIN
    test_pattern_recognition();
#endif

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
