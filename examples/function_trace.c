/**
 * @file function_trace.c
 * @brief Function tracing example using prologue/epilogue callbacks.
 *
 * This example demonstrates:
 * - Using the low-level API with prologue and epilogue callbacks
 * - Inspecting function arguments
 * - Inspecting return values
 * - Measuring function execution time
 *
 * Build:
 *   cc -std=gnu23 -I../include function_trace.c -L../build -lpatch -o function_trace
 */

#include "patch/patch.h"
#include "patch/patch_hook.h"
#include <stdio.h>
#include <time.h>

#ifndef PATCH_PLATFORM_DARWIN
// Thread-local storage for timing (Linux only)
static _Thread_local struct timespec g_start_time;
static _Thread_local int g_call_depth = 0;
#endif

// Define some hookable functions
PATCH_DEFINE_HOOKABLE(int, compute, int x, int y)
{
    // Simulate some work
    int result = 0;
    for (int i = 0; i < 1000; i++) {
        result += x * y;
    }
    return result / 1000;
}

PATCH_DEFINE_HOOKABLE(int, factorial, int n)
{
    if (n <= 1) return 1;
    return n * PATCH_CALL(factorial, n - 1);
}

#ifndef PATCH_PLATFORM_DARWIN
// Print indentation for call depth
static void print_indent(void)
{
    for (int i = 0; i < g_call_depth; i++) {
        printf("  ");
    }
}

// Prologue callback - called before function executes
static bool trace_prologue(patch_context_t *ctx, void *user_data)
{
    const char *func_name = (const char *)user_data;

    // Get arguments
    int *arg0 = (int *)patch_context_get_arg(ctx, 0);
    int *arg1 = (int *)patch_context_get_arg(ctx, 1);

    print_indent();
    if (arg1 != NULL) {
        printf("-> %s(%d, %d)\n", func_name, *arg0, arg1 ? *arg1 : 0);
    }
    else {
        printf("-> %s(%d)\n", func_name, *arg0);
    }

    g_call_depth++;
    clock_gettime(CLOCK_MONOTONIC, &g_start_time);

    return true; // Continue to original function
}

// Epilogue callback - called after function returns
static void trace_epilogue(patch_context_t *ctx, void *user_data)
{
    const char *func_name = (const char *)user_data;

    struct timespec end_time;
    clock_gettime(CLOCK_MONOTONIC, &end_time);

    long elapsed_ns = (end_time.tv_sec - g_start_time.tv_sec) * 1000000000L +
                      (end_time.tv_nsec - g_start_time.tv_nsec);

    int *result = (int *)patch_context_get_return(ctx);

    g_call_depth--;
    print_indent();
    printf("<- %s returned %d (%.3f us)\n", func_name, *result, elapsed_ns / 1000.0);
}
#endif // PATCH_PLATFORM_DARWIN

int main(void)
{
    printf("=== Function Trace Example ===\n\n");

#ifdef PATCH_PLATFORM_DARWIN
    printf("Note: Low-level API not available on macOS.\n");
    printf("Using pointer indirection only.\n\n");

    // On macOS, we can still use the macro interface
    printf("Calling compute(7, 8) = %d\n", PATCH_CALL(compute, 7, 8));
    printf("Calling factorial(5) = %d\n", PATCH_CALL(factorial, 5));
#else
    // Install tracing hooks using low-level API
    patch_handle_t *compute_handle = NULL;
    patch_handle_t *factorial_handle = NULL;

    // Hook compute()
    patch_config_t compute_config = {
        .target = (void *)compute,
        .prologue = trace_prologue,
        .epilogue = trace_epilogue,
        .prologue_user_data = (void *)"compute",
        .epilogue_user_data = (void *)"compute",
    };

    patch_error_t err = patch_install(&compute_config, &compute_handle);
    if (err != PATCH_SUCCESS) {
        printf("Failed to hook compute: %s\n", patch_get_error_details());
        return 1;
    }

    // Hook factorial()
    patch_config_t factorial_config = {
        .target = (void *)factorial,
        .prologue = trace_prologue,
        .epilogue = trace_epilogue,
        .prologue_user_data = (void *)"factorial",
        .epilogue_user_data = (void *)"factorial",
    };

    err = patch_install(&factorial_config, &factorial_handle);
    if (err != PATCH_SUCCESS) {
        printf("Failed to hook factorial: %s\n", patch_get_error_details());
        patch_remove(compute_handle);
        return 1;
    }

    printf("Tracing enabled. Calling functions:\n\n");

    // Call traced functions
    printf("compute(7, 8):\n");
    int result1 = PATCH_CALL(compute, 7, 8);
    printf("Final result: %d\n\n", result1);

    printf("factorial(5):\n");
    int result2 = PATCH_CALL(factorial, 5);
    printf("Final result: %d\n\n", result2);

    // Clean up
    patch_remove(compute_handle);
    patch_remove(factorial_handle);
#endif

    printf("=== Example Complete ===\n");
    return 0;
}
