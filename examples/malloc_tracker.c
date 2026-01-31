/**
 * @file malloc_tracker.c
 * @brief Memory allocation tracking example.
 *
 * This example demonstrates:
 * - Hooking libc functions (malloc, free)
 * - Tracking allocations with a simple counter
 * - Measuring total memory usage
 *
 * Build:
 *   cc -std=gnu23 -I../include malloc_tracker.c -L../build -lpatch -o malloc_tracker
 *
 * Note: This example works on Linux only. On macOS, hooking libc functions
 * requires different techniques (DYLD_INSERT_LIBRARIES).
 */

#include "patch/patch.h"  // For patch_can_install, patch_install, patch_get_trampoline
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#ifdef PATCH_PLATFORM_LINUX

// Statistics
static _Atomic size_t g_total_allocated = 0;
static _Atomic size_t g_total_freed = 0;
static _Atomic size_t g_allocation_count = 0;
static _Atomic size_t g_free_count = 0;

// Store malloc handle for calling original
static patch_handle_t *g_malloc_handle = NULL;
static patch_handle_t *g_free_handle = NULL;

// Our malloc replacement
static void *tracked_malloc(size_t size)
{
    // Call original malloc via trampoline
    void *(*original_malloc)(size_t) = patch_get_trampoline(g_malloc_handle);
    void *ptr = original_malloc(size);

    if (ptr != NULL) {
        g_total_allocated += size;
        g_allocation_count++;
    }

    return ptr;
}

// Our free replacement
static void tracked_free(void *ptr)
{
    if (ptr != NULL) {
        g_free_count++;
        // Note: We can't track the exact size being freed without
        // maintaining our own allocation table. This is simplified.
    }

    // Call original free via trampoline
    void (*original_free)(void *) = patch_get_trampoline(g_free_handle);
    original_free(ptr);
}

static void print_stats(void)
{
    printf("\n--- Memory Statistics ---\n");
    printf("Allocations: %zu\n", g_allocation_count);
    printf("Frees: %zu\n", g_free_count);
    printf("Total allocated: %zu bytes\n", g_total_allocated);
    printf("Outstanding: %zu allocations\n", g_allocation_count - g_free_count);
    printf("-------------------------\n");
}

int main(void)
{
    printf("=== Malloc Tracker Example ===\n\n");

    // Check if we can hook malloc
    patch_error_t err = patch_can_install(malloc);
    if (err != PATCH_SUCCESS) {
        printf("Cannot hook malloc: %s\n", patch_get_error_details());
        printf("This usually means malloc wasn't compiled with -fpatchable-function-entry\n");
        return 1;
    }

    // Install malloc hook
    patch_config_t malloc_config = {
        .target = (void *)malloc,
        .replacement = (void *)tracked_malloc,
    };
    err = patch_install(&malloc_config, &g_malloc_handle);
    if (err != PATCH_SUCCESS) {
        printf("Failed to hook malloc: %s\n", patch_get_error_details());
        return 1;
    }
    printf("Hooked malloc successfully\n");

    // Install free hook
    patch_config_t free_config = {
        .target = (void *)free,
        .replacement = (void *)tracked_free,
    };
    err = patch_install(&free_config, &g_free_handle);
    if (err != PATCH_SUCCESS) {
        printf("Failed to hook free: %s\n", patch_get_error_details());
        patch_remove(g_malloc_handle);
        return 1;
    }
    printf("Hooked free successfully\n\n");

    // Do some allocations
    printf("Performing allocations...\n");

    void *p1 = malloc(100);
    void *p2 = malloc(200);
    void *p3 = malloc(50);

    printf("Allocated 3 blocks (100 + 200 + 50 = 350 bytes)\n");
    print_stats();

    free(p1);
    free(p2);
    printf("Freed 2 blocks\n");
    print_stats();

    // Allocate more
    void *p4 = malloc(1000);
    printf("Allocated 1 more block (1000 bytes)\n");
    print_stats();

    // Clean up
    free(p3);
    free(p4);

    // Remove hooks
    patch_remove(g_malloc_handle);
    patch_remove(g_free_handle);

    printf("\nFinal statistics after cleanup:\n");
    print_stats();

    printf("=== Example Complete ===\n");
    return 0;
}

#else // macOS

int main(void)
{
    printf("=== Malloc Tracker Example ===\n\n");
    printf("Note: Hooking libc functions like malloc requires runtime code patching,\n");
    printf("which is not available on macOS due to hardware W^X enforcement.\n\n");
    printf("On macOS, use DYLD_INSERT_LIBRARIES for malloc interposition:\n");
    printf("  DYLD_INSERT_LIBRARIES=./libmymalloc.dylib ./myprogram\n\n");
    printf("=== Example Complete ===\n");
    return 0;
}

#endif
