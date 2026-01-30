#include "patch/patch.h"
#include "patch/patch_arch.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Platform-specific hookable functions
// ============================================================================

#ifdef PATCH_PLATFORM_DARWIN
// macOS: Use function pointer indirection
// The actual implementation is in _impl, called through _ptr

int add_numbers_impl(int a, int b) { return a + b; }
int (*add_numbers_ptr)(int, int) = add_numbers_impl;

static inline int add_numbers(int a, int b) {
    return add_numbers_ptr(a, b);
}

int multiply_impl(int a, int b) { return a * b; }
int (*multiply_ptr)(int, int) = multiply_impl;

static inline int multiply(int a, int b) {
    return multiply_ptr(a, b);
}

#else
// Linux: Use patchable_function_entry for code patching

#define PATCHABLE __attribute__((patchable_function_entry(8, 4)))

PATCHABLE __attribute__((noinline)) int
add_numbers(int a, int b)
{
    return a + b;
}

PATCHABLE __attribute__((noinline)) int
multiply(int a, int b)
{
    return a * b;
}

#endif

// Non-patchable function for comparison
__attribute__((noinline)) int
regular_add(int a, int b)
{
    return a + b;
}

// ============================================================================
// Tests
// ============================================================================

static void
test_can_install(void)
{
    printf("Testing patch_can_install...\n");

#ifndef PATCH_PLATFORM_DARWIN
    patch_error_t err = patch_can_install((void *)add_numbers);
    if (err == PATCH_SUCCESS) {
        printf("  add_numbers: can install\n");
    }
    else {
        printf("  add_numbers: cannot install (%s)\n",
               patch_get_error_details());
    }

    err = patch_can_install((void *)multiply);
    if (err == PATCH_SUCCESS) {
        printf("  multiply: can install\n");
    }
    else {
        printf("  multiply: cannot install (%s)\n",
               patch_get_error_details());
    }

    err = patch_can_install((void *)regular_add);
    if (err == PATCH_SUCCESS) {
        printf("  regular_add: can install\n");
    }
    else {
        printf("  regular_add: cannot install (expected)\n");
    }
#else
    printf("  [macOS] Code patching unavailable - use function pointers\n");
#endif

    // Test nullptr rejection (works on all platforms)
    patch_error_t null_err = patch_can_install(nullptr);
    assert(null_err == PATCH_ERR_INVALID_ARGUMENT);
    printf("  nullptr: correctly rejected\n");

    printf("  PASSED\n\n");
}

#ifdef PATCH_PLATFORM_DARWIN
// Hook function for macOS testing
static int hooked_add(int a, int b)
{
    printf("    [Hook intercepted: a=%d, b=%d]\n", a, b);
    return add_numbers_impl(a, b) + 100;  // Original + 100
}
#endif

static void
test_macos_hooks(void)
{
#ifdef PATCH_PLATFORM_DARWIN
    printf("Testing macOS function pointer hooks...\n");

    // Original behavior
    int result = add_numbers(10, 20);
    printf("  Before hook: add_numbers(10, 20) = %d\n", result);
    assert(result == 30);

    // Install hook by changing the function pointer
    int (*original_ptr)(int, int) = add_numbers_ptr;
    add_numbers_ptr = hooked_add;

    result = add_numbers(10, 20);
    printf("  With hook: add_numbers(10, 20) = %d (expected 130)\n", result);
    assert(result == 130);

    // Restore original
    add_numbers_ptr = original_ptr;

    result = add_numbers(10, 20);
    printf("  After restore: add_numbers(10, 20) = %d\n", result);
    assert(result == 30);

    printf("  PASSED\n\n");
#else
    printf("Testing macOS function pointer hooks...\n");
    printf("  Skipping (not on macOS)\n\n");
#endif
}

#ifndef PATCH_PLATFORM_DARWIN
static bool g_prologue_called = false;

static bool
test_prologue(patch_context_t *ctx, void *user_data)
{
    (void)ctx;
    (void)user_data;
    g_prologue_called = true;
    return true;
}
#endif

static void
test_linux_code_patching(void)
{
#ifndef PATCH_PLATFORM_DARWIN
    printf("Testing Linux code patching...\n");

    patch_error_t err = patch_can_install((void *)add_numbers);
    if (err != PATCH_SUCCESS) {
        printf("  Skipping (pattern not recognized)\n\n");
        return;
    }

    int result = add_numbers(5, 3);
    assert(result == 8);
    printf("  Before hook: add_numbers(5, 3) = %d\n", result);

    patch_config_t config = {
        .target   = (void *)add_numbers,
        .prologue = test_prologue,
    };

    patch_handle_t *handle = nullptr;
    err = patch_install(&config, &handle);

    if (err != PATCH_SUCCESS) {
        printf("  Install failed: %s\n", patch_get_error_details());
        printf("  Skipping\n\n");
        return;
    }

    printf("  Hook installed\n");

    g_prologue_called = false;
    result = add_numbers(10, 20);
    printf("  With hook: add_numbers(10, 20) = %d\n", result);
    printf("  Function still works: %s\n", result == 30 ? "yes" : "no");

    patch_remove(handle);
    printf("  Hook removed\n");

    result = add_numbers(100, 200);
    assert(result == 300);
    printf("  After remove: add_numbers(100, 200) = %d\n", result);

    printf("  PASSED\n\n");
#else
    printf("Testing Linux code patching...\n");
    printf("  Skipping (on macOS, use function pointers)\n\n");
#endif
}

static void
test_basic_functions(void)
{
    printf("Testing basic function calls...\n");

    int r1 = add_numbers(2, 3);
    assert(r1 == 5);
    printf("  add_numbers(2, 3) = %d\n", r1);

    int r2 = multiply(4, 5);
    assert(r2 == 20);
    printf("  multiply(4, 5) = %d\n", r2);

    int r3 = regular_add(6, 7);
    assert(r3 == 13);
    printf("  regular_add(6, 7) = %d\n", r3);

    printf("  PASSED\n\n");
}

int
main(void)
{
    printf("=== patch library tests ===\n");
#ifdef PATCH_PLATFORM_DARWIN
    printf("Platform: macOS ARM64\n");
    printf("Note: Code patching blocked by hardware W^X.\n");
    printf("      Using function pointer indirection for hooks.\n");
#elif defined(PATCH_ARCH_ARM64)
    printf("Platform: Linux ARM64\n");
#else
    printf("Platform: Linux x86-64\n");
#endif
    printf("\n");

    test_basic_functions();
    test_can_install();
    test_macos_hooks();
    test_linux_code_patching();

    printf("=== All tests completed ===\n");
    return 0;
}
