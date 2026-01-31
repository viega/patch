/**
 * @file basic_hook.c
 * @brief Basic function hooking example using the unified macro interface.
 *
 * This example demonstrates:
 * - Defining hookable functions with PATCH_DEFINE_HOOKABLE
 * - Calling functions with PATCH_CALL
 * - Installing hooks with PATCH_HOOK_INSTALL
 * - Calling the original function from within a hook
 * - Removing hooks with PATCH_HOOK_REMOVE
 *
 * Build:
 *   cc -std=gnu23 -I../include basic_hook.c -L../build -lpatch -o basic_hook
 */

#include "patch/patch_hook.h"
#include <stdio.h>

// Define a hookable function that adds two numbers
PATCH_DEFINE_HOOKABLE(int, add, int a, int b)
{
    return a + b;
}

// Define a hookable function that multiplies two numbers
PATCH_DEFINE_HOOKABLE(int, multiply, int a, int b)
{
    return a * b;
}

// Hook that logs the call and adds 100 to the result
int add_hook(int a, int b)
{
    printf("  [hook] add(%d, %d) called\n", a, b);
    int result = PATCH_CALL_ORIGINAL(add, a, b);
    printf("  [hook] original returned %d, adding 100\n", result);
    return result + 100;
}

// Hook that doubles both inputs before calling original
int multiply_hook(int a, int b)
{
    printf("  [hook] multiply(%d, %d) -> multiply(%d, %d)\n", a, b, a * 2, b * 2);
    return PATCH_CALL_ORIGINAL(multiply, a * 2, b * 2);
}

int main(void)
{
    printf("=== Basic Hook Example ===\n\n");

    // Call functions without hooks
    printf("Without hooks:\n");
    printf("  add(2, 3) = %d\n", PATCH_CALL(add, 2, 3));
    printf("  multiply(4, 5) = %d\n", PATCH_CALL(multiply, 4, 5));

    // Install hooks
    printf("\nInstalling hooks...\n");
    PATCH_HOOK_INSTALL(add, add_hook);
    PATCH_HOOK_INSTALL(multiply, multiply_hook);

    // Call functions with hooks
    printf("\nWith hooks:\n");
    printf("  add(2, 3) = %d\n", PATCH_CALL(add, 2, 3));
    printf("  multiply(4, 5) = %d\n", PATCH_CALL(multiply, 4, 5));

    // Check if hooks are installed
    printf("\nHook status:\n");
    printf("  add is hooked: %s\n", PATCH_HOOK_IS_INSTALLED(add) ? "yes" : "no");
    printf("  multiply is hooked: %s\n", PATCH_HOOK_IS_INSTALLED(multiply) ? "yes" : "no");

    // Remove hooks
    printf("\nRemoving hooks...\n");
    PATCH_HOOK_REMOVE(add);
    PATCH_HOOK_REMOVE(multiply);

    // Call functions after removing hooks
    printf("\nAfter removing hooks:\n");
    printf("  add(2, 3) = %d\n", PATCH_CALL(add, 2, 3));
    printf("  multiply(4, 5) = %d\n", PATCH_CALL(multiply, 4, 5));

    printf("\n=== Example Complete ===\n");
    return 0;
}
