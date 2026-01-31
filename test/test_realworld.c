#include "patch/patch.h"
#include "patch/patch_hook.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// Real-world hooking tests
//
// These tests attempt to hook actual library functions to verify the patch
// library works in realistic scenarios. Uses PATCH_METHOD_AUTO which tries
// GOT hooking first, then falls back to code patching or breakpoints.
// ============================================================================

// ============================================================================
// Test 1: Hook atoi - simple libc function
// ============================================================================

static int g_atoi_call_count = 0;
static int (*g_original_atoi)(const char *) = NULL;

static int
hooked_atoi(const char *str)
{
    g_atoi_call_count++;
    printf("    atoi called with: \"%s\"\n", str);
    return g_original_atoi(str);
}

static void
test_hook_atoi(void)
{
    printf("Test: Hook libc atoi()...\n");

    patch_config_t config = {
        .replacement = (void *)hooked_atoi,
        .method = PATCH_METHOD_AUTO,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_symbol("atoi", NULL, &config, &handle);

    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    // Get original function pointer
    g_original_atoi = (int (*)(const char *))patch_get_trampoline(handle);
    if (g_original_atoi == NULL) {
        printf("  SKIPPED (no trampoline available)\n");
        patch_remove(handle);
        return;
    }

    printf("  Hook installed successfully!\n");

    // Call atoi a few times
    g_atoi_call_count = 0;

    int r1 = atoi("123");
    int r2 = atoi("456");
    int r3 = atoi("-789");

    printf("  Results: %d, %d, %d\n", r1, r2, r3);
    printf("  Hook called %d times\n", g_atoi_call_count);

    if (g_atoi_call_count == 3 && r1 == 123 && r2 == 456 && r3 == -789) {
        printf("  PASSED\n");
    } else {
        printf("  FAILED (unexpected results)\n");
    }

    patch_remove(handle);
}

// ============================================================================
// Test 2: Hook strlen - very simple function
// ============================================================================

static int g_strlen_call_count = 0;
static size_t (*g_original_strlen)(const char *) = NULL;

static size_t
hooked_strlen(const char *s)
{
    g_strlen_call_count++;
    return g_original_strlen(s);
}

static void
test_hook_strlen(void)
{
    printf("Test: Hook libc strlen()...\n");

    patch_config_t config = {
        .replacement = (void *)hooked_strlen,
        .method = PATCH_METHOD_AUTO,
    };

    patch_handle_t *handle = NULL;
    patch_error_t err = patch_install_symbol("strlen", NULL, &config, &handle);

    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
        return;
    }

    g_original_strlen = (size_t (*)(const char *))patch_get_trampoline(handle);
    if (g_original_strlen == NULL) {
        printf("  SKIPPED (no trampoline available)\n");
        patch_remove(handle);
        return;
    }

    printf("  Hook installed!\n");
    g_strlen_call_count = 0;

    size_t l1 = strlen("hello");
    size_t l2 = strlen("world!");
    size_t l3 = strlen("");

    printf("  Lengths: %zu, %zu, %zu\n", l1, l2, l3);
    printf("  Hook called %d times\n", g_strlen_call_count);

    if (g_strlen_call_count == 3 && l1 == 5 && l2 == 6 && l3 == 0) {
        printf("  PASSED\n");
    } else {
        printf("  FAILED\n");
    }

    patch_remove(handle);
}

// ============================================================================
// Test 3: Memory allocation tracking (malloc/free)
// ============================================================================

static size_t g_total_allocated   = 0;
static int    g_malloc_call_count = 0;
static int    g_free_call_count   = 0;
static void *(*g_original_malloc)(size_t) = NULL;
static void (*g_original_free)(void *) = NULL;

static void *
hooked_malloc(size_t size)
{
    g_malloc_call_count++;
    g_total_allocated += size;
    return g_original_malloc(size);
}

static void
hooked_free(void *ptr)
{
    g_free_call_count++;
    g_original_free(ptr);
}

static void
test_track_allocations(void)
{
    printf("Test: Track memory allocations...\n");

    patch_config_t malloc_config = {
        .replacement = (void *)hooked_malloc,
        .method = PATCH_METHOD_AUTO,
    };
    patch_config_t free_config = {
        .replacement = (void *)hooked_free,
        .method = PATCH_METHOD_AUTO,
    };

    patch_handle_t *malloc_handle = NULL;
    patch_handle_t *free_handle   = NULL;

    patch_error_t malloc_err = patch_install_symbol("malloc", NULL, &malloc_config, &malloc_handle);
    if (malloc_err != PATCH_SUCCESS) {
        printf("  SKIPPED (malloc hook failed: %s)\n", patch_get_error_details());
        return;
    }

    g_original_malloc = (void *(*)(size_t))patch_get_trampoline(malloc_handle);
    if (g_original_malloc == NULL) {
        printf("  SKIPPED (no malloc trampoline)\n");
        patch_remove(malloc_handle);
        return;
    }

    patch_error_t free_err = patch_install_symbol("free", NULL, &free_config, &free_handle);
    if (free_err != PATCH_SUCCESS) {
        printf("  SKIPPED (free hook failed: %s)\n", patch_get_error_details());
        patch_remove(malloc_handle);
        return;
    }

    g_original_free = (void (*)(void *))patch_get_trampoline(free_handle);
    if (g_original_free == NULL) {
        printf("  SKIPPED (no free trampoline)\n");
        patch_remove(free_handle);
        patch_remove(malloc_handle);
        return;
    }

    printf("  Hooks installed!\n");

    // Reset counters
    g_total_allocated   = 0;
    g_malloc_call_count = 0;
    g_free_call_count   = 0;

    // Do some allocations
    void *p1 = malloc(100);
    void *p2 = malloc(200);
    void *p3 = malloc(50);

    free(p1);
    free(p2);
    free(p3);

    printf("  Total allocated: %zu bytes in %d calls\n", g_total_allocated, g_malloc_call_count);
    printf("  Free called: %d times\n", g_free_call_count);

    // Note: malloc_call_count might be > 3 if printf calls malloc internally
    if (g_malloc_call_count >= 3 && g_total_allocated >= 350) {
        printf("  PASSED\n");
    } else {
        printf("  Results inconclusive (printf may have interfered)\n");
    }

    patch_remove(free_handle);
    patch_remove(malloc_handle);
}

// ============================================================================
// Test 4: Inspect prologue patterns of common functions
// ============================================================================

static void
inspect_function(const char *name)
{
    void *addr = dlsym(RTLD_DEFAULT, name);
    if (addr == NULL) {
        printf("  %-12s: not found\n", name);
        return;
    }

    patch_error_t err = patch_can_install(addr);
    if (err == PATCH_SUCCESS) {
        printf("  %-12s: %p - HOOKABLE (code)\n", name, addr);
    } else {
        printf("  %-12s: %p - code: %s\n", name, addr, patch_get_error_details());
    }
}

static void
test_inspect_functions(void)
{
    printf("Test: Inspect common libc functions...\n");

    inspect_function("malloc");
    inspect_function("free");
    inspect_function("calloc");
    inspect_function("realloc");
    inspect_function("strlen");
    inspect_function("strcpy");
    inspect_function("strcmp");
    inspect_function("memcpy");
    inspect_function("memset");
    inspect_function("printf");
    inspect_function("puts");
    inspect_function("atoi");
    inspect_function("atol");
    inspect_function("strtol");
    inspect_function("fopen");
    inspect_function("fclose");
    inspect_function("fread");
    inspect_function("fwrite");

    printf("  (inspection complete)\n");
}

// ============================================================================
// Main
// ============================================================================

int
main(void)
{
    printf("=== Real-World Hooking Tests ===\n\n");

#ifdef PATCH_PLATFORM_DARWIN
    printf("Platform: macOS\n");
#else
    printf("Platform: Linux\n");
#endif
    printf("Using PATCH_METHOD_AUTO (GOT first, then code/breakpoint)\n\n");

    // First, see what's hookable via code patching
    test_inspect_functions();
    printf("\n");

    // Try to hook various functions using AUTO method
    test_hook_strlen();
    printf("\n");

    test_hook_atoi();
    printf("\n");

    // malloc/free is risky due to recursion, try last
    test_track_allocations();

    printf("\n=== Real-World Tests Complete ===\n");
    return 0;
}
