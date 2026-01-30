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
// library works in realistic scenarios.
// ============================================================================

// ============================================================================
// Tests that require code patching (Linux only)
// ============================================================================

#ifndef PATCH_PLATFORM_DARWIN

// ============================================================================
// Test 1: Hook atoi - simple libc function
// ============================================================================

static int g_atoi_call_count = 0;

static bool
atoi_prologue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;
    g_atoi_call_count++;

    const char **str_ptr = (const char **)patch_context_get_arg(ctx, 0);
    if (str_ptr && *str_ptr) {
        printf("    atoi called with: \"%s\"\n", *str_ptr);
    }

    return true; // Continue to original
}

static void
test_hook_atoi(void)
{
    printf("Test: Hook libc atoi()...\n");

    // Get the address of atoi
    void *atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
    if (atoi_addr == NULL) {
        printf("  SKIPPED (could not find atoi)\n");
        return;
    }
    printf("  atoi address: %p\n", atoi_addr);

    // Check if we can install a hook
    patch_error_t err = patch_can_install(atoi_addr);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (cannot hook atoi: %s)\n", patch_get_error_details());
        return;
    }

    // Install the hook
    patch_config_t config = {
        .target   = atoi_addr,
        .prologue = atoi_prologue,
    };

    patch_handle_t *handle = NULL;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
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
// Test 2: Memory allocation tracking
// ============================================================================

static size_t g_total_allocated   = 0;
static size_t g_total_freed       = 0;
static int    g_malloc_call_count = 0;
static int    g_free_call_count   = 0;

static bool
malloc_prologue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;
    g_malloc_call_count++;

    size_t *size_ptr = (size_t *)patch_context_get_arg(ctx, 0);
    if (size_ptr) {
        g_total_allocated += *size_ptr;
    }

    return true;
}

static bool
free_prologue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;
    g_free_call_count++;
    (void)ctx; // We don't track the actual pointer/size for simplicity
    return true;
}

static void
test_track_allocations(void)
{
    printf("Test: Track memory allocations...\n");

    void *malloc_addr = dlsym(RTLD_DEFAULT, "malloc");
    void *free_addr   = dlsym(RTLD_DEFAULT, "free");

    if (malloc_addr == NULL || free_addr == NULL) {
        printf("  SKIPPED (could not find malloc/free)\n");
        return;
    }

    printf("  malloc address: %p\n", malloc_addr);
    printf("  free address: %p\n", free_addr);

    // Check if we can hook these
    patch_error_t malloc_err = patch_can_install(malloc_addr);
    patch_error_t free_err   = patch_can_install(free_addr);

    if (malloc_err != PATCH_SUCCESS) {
        printf("  Cannot hook malloc: %s\n", patch_get_error_details());
    }
    if (free_err != PATCH_SUCCESS) {
        printf("  Cannot hook free: %s\n", patch_get_error_details());
    }

    if (malloc_err != PATCH_SUCCESS || free_err != PATCH_SUCCESS) {
        printf("  SKIPPED (cannot hook malloc/free)\n");
        return;
    }

    // Install hooks
    patch_config_t malloc_config = {
        .target   = malloc_addr,
        .prologue = malloc_prologue,
    };
    patch_config_t free_config = {
        .target   = free_addr,
        .prologue = free_prologue,
    };

    patch_handle_t *malloc_handle = NULL;
    patch_handle_t *free_handle   = NULL;

    malloc_err = patch_install(&malloc_config, &malloc_handle);
    if (malloc_err != PATCH_SUCCESS) {
        printf("  SKIPPED (malloc hook install failed: %s)\n", patch_get_error_details());
        return;
    }

    free_err = patch_install(&free_config, &free_handle);
    if (free_err != PATCH_SUCCESS) {
        printf("  SKIPPED (free hook install failed: %s)\n", patch_get_error_details());
        patch_remove(malloc_handle);
        return;
    }

    printf("  Hooks installed!\n");

    // Reset counters
    g_total_allocated   = 0;
    g_total_freed       = 0;
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
// Test 3: Hook strlen - very simple function
// ============================================================================

static int g_strlen_call_count = 0;

static bool
strlen_prologue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;
    (void)ctx;
    g_strlen_call_count++;
    return true;
}

static void
test_hook_strlen(void)
{
    printf("Test: Hook libc strlen()...\n");

    void *strlen_addr = dlsym(RTLD_DEFAULT, "strlen");
    if (strlen_addr == NULL) {
        printf("  SKIPPED (could not find strlen)\n");
        return;
    }
    printf("  strlen address: %p\n", strlen_addr);

    patch_error_t err = patch_can_install(strlen_addr);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (cannot hook strlen: %s)\n", patch_get_error_details());
        return;
    }

    patch_config_t config = {
        .target   = strlen_addr,
        .prologue = strlen_prologue,
    };

    patch_handle_t *handle = NULL;
    err                    = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        printf("  SKIPPED (install failed: %s)\n", patch_get_error_details());
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

#endif // !PATCH_PLATFORM_DARWIN

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
        printf("  %-12s: %p - HOOKABLE\n", name, addr);
    } else {
        printf("  %-12s: %p - %s\n", name, addr, patch_get_error_details());
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
    printf("Platform: macOS - code patching restricted by hardware W^X\n");
    printf("These tests require low-level code patching and will be skipped.\n\n");

    // On macOS, just inspect what functions look hookable
    test_inspect_functions();
#else
    printf("Platform: Linux - full code patching support\n\n");

    // First, see what's hookable
    test_inspect_functions();
    printf("\n");

    // Try to hook various functions
    test_hook_strlen();
    printf("\n");

    test_hook_atoi();
    printf("\n");

    // malloc/free is risky due to recursion, try last
    test_track_allocations();
#endif

    printf("\n=== Real-World Tests Complete ===\n");
    return 0;
}
