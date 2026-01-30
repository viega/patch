#include "patch/patch.h"
#include "patch/patch_hook.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Hookable functions using unified macros
// ============================================================================

// Define hookable functions - works on both macOS and Linux
PATCH_DEFINE_HOOKABLE(int, add_numbers, int a, int b)
{
    return a + b;
}

PATCH_DEFINE_HOOKABLE(int, multiply, int a, int b)
{
    return a * b;
}

// Non-patchable function for comparison
__attribute__((noinline)) int
regular_add(int a, int b)
{
    return a + b;
}

// ============================================================================
// Hook functions
// ============================================================================

// Hook that adds 100 to the result
static int
hooked_add(int a, int b)
{
    printf("    [Hook intercepted: a=%d, b=%d]\n", a, b);
    return PATCH_CALL_ORIGINAL(add_numbers, a, b) + 100;
}

// Hook that doubles the result
static int
hooked_multiply(int a, int b)
{
    printf("    [Multiply hook: a=%d, b=%d]\n", a, b);
    return PATCH_CALL_ORIGINAL(multiply, a, b) * 2;
}

// ============================================================================
// Tests
// ============================================================================

static void
test_basic_functions(void)
{
    printf("Testing basic function calls...\n");

    int r1 = PATCH_CALL(add_numbers, 2, 3);
    assert(r1 == 5);
    printf("  add_numbers(2, 3) = %d\n", r1);

    int r2 = PATCH_CALL(multiply, 4, 5);
    assert(r2 == 20);
    printf("  multiply(4, 5) = %d\n", r2);

    int r3 = regular_add(6, 7);
    assert(r3 == 13);
    printf("  regular_add(6, 7) = %d\n", r3);

    printf("  PASSED\n\n");
}

static void
test_unified_hooks(void)
{
    printf("Testing unified hook interface...\n");

    // Verify not hooked initially
    assert(!PATCH_HOOK_IS_INSTALLED(add_numbers));
    assert(!PATCH_HOOK_IS_INSTALLED(multiply));

    // Test add_numbers hook
    int result = PATCH_CALL(add_numbers, 10, 20);
    printf("  Before hook: add_numbers(10, 20) = %d\n", result);
    assert(result == 30);

    // Install hook using unified macro
    PATCH_HOOK_INSTALL(add_numbers, hooked_add);
    assert(PATCH_HOOK_IS_INSTALLED(add_numbers));

    result = PATCH_CALL(add_numbers, 10, 20);
    printf("  With hook: add_numbers(10, 20) = %d (expected 130)\n", result);
    assert(result == 130);

    // Remove hook using unified macro
    PATCH_HOOK_REMOVE(add_numbers);
    assert(!PATCH_HOOK_IS_INSTALLED(add_numbers));

    result = PATCH_CALL(add_numbers, 10, 20);
    printf("  After remove: add_numbers(10, 20) = %d\n", result);
    assert(result == 30);

    printf("  PASSED\n\n");
}

static void
test_multiple_hooks(void)
{
    printf("Testing multiple hooks...\n");

    // Hook both functions
    PATCH_HOOK_INSTALL(add_numbers, hooked_add);
    PATCH_HOOK_INSTALL(multiply, hooked_multiply);

    int r1 = PATCH_CALL(add_numbers, 5, 5);
    printf("  add_numbers(5, 5) = %d (expected 110)\n", r1);
    assert(r1 == 110);  // (5+5) + 100

    int r2 = PATCH_CALL(multiply, 3, 4);
    printf("  multiply(3, 4) = %d (expected 24)\n", r2);
    assert(r2 == 24);  // (3*4) * 2

    // Remove both
    PATCH_HOOK_REMOVE(add_numbers);
    PATCH_HOOK_REMOVE(multiply);

    r1 = PATCH_CALL(add_numbers, 5, 5);
    r2 = PATCH_CALL(multiply, 3, 4);
    assert(r1 == 10);
    assert(r2 == 12);
    printf("  After remove: add=%d, multiply=%d\n", r1, r2);

    printf("  PASSED\n\n");
}

#ifndef PATCH_PLATFORM_DARWIN
static void
test_hook_method_selection(void)
{
    printf("Testing hook method selection (Linux)...\n");

    // Test pointer method explicitly
    PATCH_HOOK_INSTALL(add_numbers, hooked_add, PATCH_METHOD_POINTER);

    int result = PATCH_CALL(add_numbers, 7, 8);
    printf("  With PATCH_METHOD_POINTER: add_numbers(7, 8) = %d\n", result);
    assert(result == 115);  // (7+8) + 100

    PATCH_HOOK_REMOVE(add_numbers);

    result = PATCH_CALL(add_numbers, 7, 8);
    assert(result == 15);
    printf("  After remove: %d\n", result);

    printf("  PASSED\n\n");
}
#endif

static void
test_can_install(void)
{
    printf("Testing patch_can_install...\n");

#ifndef PATCH_PLATFORM_DARWIN
    // On Linux, we can check if code patching would work
    patch_error_t err = patch_can_install((void *)add_numbers);
    if (err == PATCH_SUCCESS) {
        printf("  add_numbers: code patching available (NOP sled detected)\n");
    }
    else {
        printf("  add_numbers: code patching unavailable (%s)\n",
               patch_get_error_details());
    }

    err = patch_can_install((void *)regular_add);
    if (err == PATCH_SUCCESS) {
        printf("  regular_add: can install\n");
    }
    else {
        printf("  regular_add: cannot install (expected - no NOP sled)\n");
    }
#else
    printf("  [macOS] Code patching unavailable - unified macros use pointers\n");
#endif

    // Test nullptr rejection (works on all platforms)
    patch_error_t null_err = patch_can_install(nullptr);
    assert(null_err == PATCH_ERR_INVALID_ARGUMENT);
    printf("  nullptr: correctly rejected\n");

    printf("  PASSED\n\n");
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

static void
test_low_level_api(void)
{
    printf("Testing low-level patch API (Linux)...\n");

    patch_error_t err = patch_can_install((void *)add_numbers);
    if (err != PATCH_SUCCESS) {
        printf("  Skipping (pattern not recognized)\n\n");
        return;
    }

    int result = PATCH_CALL(add_numbers, 5, 3);
    assert(result == 8);
    printf("  Before hook: add_numbers(5, 3) = %d\n", result);

    patch_config_t config = {
        .target   = (void *)add_numbers,
        .prologue = test_prologue,
    };

    patch_handle_t *handle = nullptr;
    err                    = patch_install(&config, &handle);

    if (err != PATCH_SUCCESS) {
        printf("  Install failed: %s\n", patch_get_error_details());
        printf("  Skipping\n\n");
        return;
    }

    printf("  Prologue hook installed via low-level API\n");

    g_prologue_called = false;
    result            = PATCH_CALL(add_numbers, 10, 20);
    printf("  With hook: add_numbers(10, 20) = %d\n", result);
    printf("  Prologue called: %s\n", g_prologue_called ? "yes" : "no");

    patch_remove(handle);
    printf("  Hook removed\n");

    result = PATCH_CALL(add_numbers, 100, 200);
    assert(result == 300);
    printf("  After remove: add_numbers(100, 200) = %d\n", result);

    printf("  PASSED\n\n");
}
#endif

int
main(void)
{
    printf("=== patch library tests ===\n");
#ifdef PATCH_PLATFORM_DARWIN
    printf("Platform: macOS ARM64\n");
    printf("Note: Hardware W^X - unified macros use pointer indirection.\n");
#elif defined(PATCH_ARCH_ARM64)
    printf("Platform: Linux ARM64\n");
#else
    printf("Platform: Linux x86-64\n");
#endif
    printf("\n");

    test_basic_functions();
    test_unified_hooks();
    test_multiple_hooks();

#ifndef PATCH_PLATFORM_DARWIN
    test_hook_method_selection();
    test_low_level_api();
#endif

    test_can_install();

    printf("=== All tests completed ===\n");
    return 0;
}
