/**
 * @file argument_modify.c
 * @brief Example of modifying function arguments and return values.
 *
 * This example demonstrates:
 * - Modifying arguments in a prologue callback
 * - Modifying return values in an epilogue callback
 * - Skipping the original function and providing a fake return value
 *
 * Build:
 *   cc -std=gnu23 -I../include argument_modify.c -L../build -lpatch -o argument_modify
 */

#include "patch/patch.h"
#include "patch/patch_hook.h"
#include <stdio.h>
#include <stdbool.h>

// Define a hookable function
PATCH_DEFINE_HOOKABLE(int, divide, int a, int b)
{
    printf("    [original] divide(%d, %d)\n", a, b);
    if (b == 0) {
        return -1; // Error
    }
    return a / b;
}

#ifndef PATCH_PLATFORM_DARWIN
// Prologue that doubles the first argument
static bool double_first_arg(patch_context_t *ctx, void *user_data)
{
    (void)user_data;

    int *a = (int *)patch_context_get_arg(ctx, 0);
    printf("    [hook] doubling first arg: %d -> %d\n", *a, *a * 2);

    int new_a = *a * 2;
    patch_context_set_arg(ctx, 0, &new_a, sizeof(new_a));

    return true; // Continue to original
}

// Prologue that prevents division by zero
static bool safe_divide_prologue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;

    int *b = (int *)patch_context_get_arg(ctx, 1);

    if (*b == 0) {
        printf("    [hook] preventing division by zero!\n");

        // Set a return value and skip the original function
        int error_result = 0;
        patch_context_set_return(ctx, &error_result, sizeof(error_result));
        return false; // Skip original
    }

    return true; // Continue to original
}

// Epilogue that adds 1000 to the result
static void add_1000_epilogue(patch_context_t *ctx, void *user_data)
{
    (void)user_data;

    int *result = (int *)patch_context_get_return(ctx);
    printf("    [hook] adding 1000 to result: %d -> %d\n", *result, *result + 1000);

    int new_result = *result + 1000;
    patch_context_set_return(ctx, &new_result, sizeof(new_result));
}
#endif // PATCH_PLATFORM_DARWIN

int main(void)
{
    printf("=== Argument Modification Example ===\n\n");

#ifdef PATCH_PLATFORM_DARWIN
    printf("Note: Low-level API not available on macOS.\n");
    printf("Showing unmodified behavior only.\n\n");

    printf("divide(10, 2) = %d\n", PATCH_CALL(divide, 10, 2));
    printf("divide(10, 0) = %d\n", PATCH_CALL(divide, 10, 0));
#else
    patch_handle_t *handle = NULL;
    patch_error_t err;

    // Example 1: Double the first argument
    printf("Example 1: Double first argument\n");
    printf("---------------------------------\n");

    patch_config_t config1 = {
        .target = (void *)divide,
        .prologue = double_first_arg,
    };

    err = patch_install(&config1, &handle);
    if (err != PATCH_SUCCESS) {
        printf("Failed: %s\n", patch_get_error_details());
        return 1;
    }

    printf("  divide(10, 2):\n");
    int result = PATCH_CALL(divide, 10, 2);
    printf("  Result: %d (expected 10, because 10*2/2 = 10)\n\n", result);

    patch_remove(handle);

    // Example 2: Prevent division by zero
    printf("Example 2: Safe division (prevent div by zero)\n");
    printf("-----------------------------------------------\n");

    patch_config_t config2 = {
        .target = (void *)divide,
        .prologue = safe_divide_prologue,
    };

    err = patch_install(&config2, &handle);
    if (err != PATCH_SUCCESS) {
        printf("Failed: %s\n", patch_get_error_details());
        return 1;
    }

    printf("  divide(10, 2):\n");
    result = PATCH_CALL(divide, 10, 2);
    printf("  Result: %d\n\n", result);

    printf("  divide(10, 0):\n");
    result = PATCH_CALL(divide, 10, 0);
    printf("  Result: %d (safely returned 0 instead of crashing)\n\n", result);

    patch_remove(handle);

    // Example 3: Modify return value
    printf("Example 3: Add 1000 to return value\n");
    printf("------------------------------------\n");

    patch_config_t config3 = {
        .target = (void *)divide,
        .epilogue = add_1000_epilogue,
    };

    err = patch_install(&config3, &handle);
    if (err != PATCH_SUCCESS) {
        printf("Failed: %s\n", patch_get_error_details());
        return 1;
    }

    printf("  divide(20, 4):\n");
    result = PATCH_CALL(divide, 20, 4);
    printf("  Result: %d (5 + 1000 = 1005)\n\n", result);

    patch_remove(handle);

    // Example 4: Both prologue and epilogue
    printf("Example 4: Double arg AND add 1000\n");
    printf("-----------------------------------\n");

    patch_config_t config4 = {
        .target = (void *)divide,
        .prologue = double_first_arg,
        .epilogue = add_1000_epilogue,
    };

    err = patch_install(&config4, &handle);
    if (err != PATCH_SUCCESS) {
        printf("Failed: %s\n", patch_get_error_details());
        return 1;
    }

    printf("  divide(10, 2):\n");
    result = PATCH_CALL(divide, 10, 2);
    printf("  Result: %d (20/2 + 1000 = 1010)\n\n", result);

    patch_remove(handle);
#endif

    printf("=== Example Complete ===\n");
    return 0;
}
