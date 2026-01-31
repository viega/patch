#pragma once

/**
 * @file patch_hook.h
 * @brief Unified macro interface for runtime function hooking.
 *
 * This header provides portable macros for defining and hooking functions
 * at runtime. It abstracts platform differences:
 *
 * - **macOS**: Uses function pointer indirection (hardware W^X blocks code
 *   modification on Apple Silicon)
 * - **Linux**: Supports both code patching (via NOP sleds) and pointer
 *   indirection
 *
 * ## Quick Start
 *
 * @code
 * #include "patch/patch_hook.h"
 *
 * // 1. Define a hookable function
 * PATCH_DEFINE_HOOKABLE(int, add, int a, int b) {
 *     return a + b;
 * }
 *
 * // 2. Call it using PATCH_CALL
 * int result = PATCH_CALL(add, 2, 3);  // returns 5
 *
 * // 3. Write a hook with the same signature
 * int my_hook(int a, int b) {
 *     printf("Intercepted: %d + %d\n", a, b);
 *     return PATCH_CALL_ORIGINAL(add, a, b) + 100;
 * }
 *
 * // 4. Install the hook
 * PATCH_HOOK_INSTALL(add, my_hook);
 *
 * // 5. Calls now go through the hook
 * result = PATCH_CALL(add, 2, 3);  // prints "Intercepted: 2 + 3", returns 105
 *
 * // 6. Remove the hook
 * PATCH_HOOK_REMOVE(add);
 * @endcode
 *
 * ## Hook Methods (Linux Only)
 *
 * On Linux, you can specify the hooking method:
 *
 * @code
 * // Pointer indirection (like macOS) - simpler, always works
 * PATCH_HOOK_INSTALL(add, my_hook, PATCH_METHOD_POINTER);
 *
 * // Code patching via NOP sled - more powerful, requires patchable function
 * PATCH_HOOK_INSTALL(add, my_hook, PATCH_METHOD_CODE);
 * @endcode
 *
 * On macOS, the method argument is ignored (always uses pointer indirection).
 *
 * @see patch.h for the low-level API with prologue/epilogue callbacks
 */

#include "patch/patch.h"
#include "patch/patch_arch.h"

/* =========================================================================
 * Hook Method Constants
 * ========================================================================= */

/**
 * @defgroup hook_methods Hook Methods
 * @brief Constants for selecting the hooking mechanism.
 *
 * These can be passed as the optional third argument to PATCH_HOOK_INSTALL().
 * On macOS, all methods resolve to pointer indirection due to hardware W^X.
 * @{
 */

/**
 * @brief Use platform default method.
 *
 * - macOS: Pointer indirection
 * - Linux: Pointer indirection (for unified behavior)
 */
#define PATCH_METHOD_AUTO 0

/**
 * @brief Use function pointer indirection.
 *
 * Works on all platforms. The hookable function calls through a global
 * function pointer, which is swapped to install/remove hooks.
 *
 * Pros: Simple, always works, no memory protection changes needed.
 * Cons: Requires using PATCH_CALL() instead of direct function calls.
 */
#define PATCH_METHOD_POINTER 1

/**
 * @brief Use direct code patching (Linux only).
 *
 * Overwrites the function's NOP sled with a jump to the hook. Requires
 * the function to be compiled with `patchable_function_entry(8, 4)`.
 *
 * Pros: Direct calls work without PATCH_CALL(), more flexible.
 * Cons: Requires NOP sled, not available on macOS ARM64.
 *
 * @note On macOS, this falls back to PATCH_METHOD_POINTER.
 */
#define PATCH_METHOD_CODE 2

/** @} */ // end of hook_methods

/* =========================================================================
 * Internal: Macro Overloading Support
 * ========================================================================= */

// These macros enable PATCH_HOOK_INSTALL to accept 2 or 3 arguments.
// Implementation detail - do not use directly.

#define PATCH__NARG_(_1, _2, _3, N, ...) N
#define PATCH__NARG(...)                 PATCH__NARG_(__VA_ARGS__, 3, 2, 1)
#define PATCH__CAT_(a, b)                a##b
#define PATCH__CAT(a, b)                 PATCH__CAT_(a, b)
#define PATCH__INSTALL_DISPATCH(...) \
    PATCH__CAT(PATCH__HOOK_INSTALL, PATCH__NARG(__VA_ARGS__))(__VA_ARGS__)

/* =========================================================================
 * Platform-Specific Implementation: macOS
 * ========================================================================= */

#ifdef PATCH_PLATFORM_DARWIN

/*
 * macOS Implementation Notes:
 *
 * Apple Silicon enforces hardware W^X (Write XOR Execute), making it
 * impossible to modify code pages at runtime. All hooks use function
 * pointer indirection:
 *
 * - PATCH_DEFINE_HOOKABLE creates: name_impl (actual code), name_ptr (pointer)
 * - PATCH_CALL invokes through name_ptr
 * - PATCH_HOOK_INSTALL swaps name_ptr to point to the hook
 * - The hook can call name_impl to invoke the original
 */

/**
 * @brief Declare a hookable function (for use in headers).
 *
 * Use this in header files to declare functions defined with
 * PATCH_DEFINE_HOOKABLE in source files.
 *
 * @param ret  Return type of the function.
 * @param name Function name (without quotes).
 * @param ...  Parameter list (types and names).
 *
 * @code
 * // In header:
 * PATCH_DECLARE_HOOKABLE(int, calculate, int x, int y);
 *
 * // In source:
 * PATCH_DEFINE_HOOKABLE(int, calculate, int x, int y) {
 *     return x * y;
 * }
 * @endcode
 */
#define PATCH_DECLARE_HOOKABLE(ret, name, ...) \
    ret name##_impl(__VA_ARGS__);              \
    extern ret (*name##_ptr)(__VA_ARGS__)

/**
 * @brief Define a hookable function.
 *
 * Creates a function that can be hooked at runtime. On macOS, this generates:
 * - `name_impl`: The actual function implementation
 * - `name_ptr`: A function pointer (initially pointing to name_impl)
 *
 * Follow this macro with the function body in braces.
 *
 * @param ret  Return type of the function.
 * @param name Function name (without quotes).
 * @param ...  Parameter list (types and names).
 *
 * @code
 * PATCH_DEFINE_HOOKABLE(int, add, int a, int b) {
 *     return a + b;
 * }
 * @endcode
 */
#define PATCH_DEFINE_HOOKABLE(ret, name, ...)                   \
    ret name##_impl(__VA_ARGS__);                               \
    ret (*name##_ptr)(__VA_ARGS__)               = name##_impl; \
    static ret (*name##__saved_ptr)(__VA_ARGS__) = nullptr;     \
    ret name##_impl(__VA_ARGS__)

/**
 * @brief Call a hookable function.
 *
 * Use this macro instead of calling the function directly. It ensures
 * the call goes through the hook mechanism.
 *
 * @param name Function name.
 * @param ...  Arguments to pass to the function.
 *
 * @return The function's return value (possibly modified by a hook).
 *
 * @code
 * int result = PATCH_CALL(add, 2, 3);
 * @endcode
 */
#define PATCH_CALL(name, ...) name##_ptr(__VA_ARGS__)

/**
 * @brief Get the original (unhooked) function.
 *
 * Returns a reference to the original function implementation, bypassing
 * any installed hook. Use this within a hook to call the original.
 *
 * @param name Function name.
 *
 * @return The original function (can be called directly).
 *
 * @code
 * int my_hook(int a, int b) {
 *     int original_result = PATCH_HOOK_ORIGINAL(add)(a, b);
 *     return original_result + 100;
 * }
 * @endcode
 */
#define PATCH_HOOK_ORIGINAL(name) name##_impl

// Internal: 2-argument version (no method specified)
#define PATCH__HOOK_INSTALL2(name, hook) \
    do {                                 \
        name##__saved_ptr = name##_ptr;  \
        name##_ptr        = (hook);      \
    } while (0)

// Internal: 3-argument version (method specified but ignored on macOS)
#define PATCH__HOOK_INSTALL3(name, hook, method) \
    do {                                         \
        (void)(method);                          \
        name##__saved_ptr = name##_ptr;          \
        name##_ptr        = (hook);              \
    } while (0)

/**
 * @brief Install a hook on a function.
 *
 * Redirects calls to the named function through the specified hook function.
 * The hook must have the same signature as the original.
 *
 * @param name   Function name (defined with PATCH_DEFINE_HOOKABLE).
 * @param hook   Hook function with matching signature.
 * @param method (Optional) Hook method - ignored on macOS.
 *
 * @code
 * PATCH_HOOK_INSTALL(add, my_hook);
 * PATCH_HOOK_INSTALL(add, my_hook, PATCH_METHOD_POINTER);  // Explicit method
 * @endcode
 *
 * @note Only one hook can be active at a time. Installing a new hook
 *       overwrites the previous one.
 */
#define PATCH_HOOK_INSTALL(...) PATCH__INSTALL_DISPATCH(__VA_ARGS__)

/**
 * @brief Remove a hook and restore the original function.
 *
 * After removal, PATCH_CALL will invoke the original function directly.
 *
 * @param name Function name.
 *
 * @code
 * PATCH_HOOK_REMOVE(add);
 * @endcode
 */
#define PATCH_HOOK_REMOVE(name)                    \
    do {                                           \
        if (name##__saved_ptr) {                   \
            name##_ptr        = name##__saved_ptr; \
            name##__saved_ptr = nullptr;           \
        }                                          \
    } while (0)

/**
 * @brief Check if a hook is currently installed.
 *
 * @param name Function name.
 *
 * @return true if hooked, false otherwise.
 *
 * @code
 * if (PATCH_HOOK_IS_INSTALLED(add)) {
 *     printf("add() is hooked\n");
 * }
 * @endcode
 */
#define PATCH_HOOK_IS_INSTALLED(name) (name##__saved_ptr != nullptr)

/**
 * @brief Get the current hook function.
 *
 * @param name Function name.
 *
 * @return Pointer to the hook function, or nullptr if not hooked.
 */
#define PATCH_HOOK_GET_CURRENT(name) \
    (name##__saved_ptr ? name##_ptr : nullptr)

#else /* Linux */

/* =========================================================================
 * Platform-Specific Implementation: Linux
 * ========================================================================= */

/*
 * Linux Implementation Notes:
 *
 * Linux supports both pointer indirection (like macOS) and direct code
 * patching. Code patching requires functions to be compiled with
 * patchable_function_entry(8, 4), which inserts NOP instructions that
 * can be safely overwritten with a jump.
 *
 * The unified interface defaults to pointer indirection for simplicity
 * and cross-platform consistency.
 */

/**
 * @brief Attribute for creating patchable functions.
 *
 * This attribute inserts NOP instructions before and at the function entry
 * point, creating a "landing pad" that can be safely overwritten with a
 * jump instruction for code patching.
 *
 * Format: patchable_function_entry(total_nops, nops_before_entry)
 *
 * Architecture requirements:
 * - x86-64: Need 5+ bytes at entry for JMP rel32
 * - ARM64: Need 8+ bytes at entry (2 NOPs) to clearly distinguish from
 *          functions that happen to start with a single NOP
 */
#ifdef PATCH_ARCH_X86_64
// x86-64: 16 single-byte NOPs total, 8 before entry = 8 at entry
#define PATCH_PATCHABLE __attribute__((patchable_function_entry(16, 8)))
#else
// ARM64: 4 four-byte NOPs total, 2 before entry = 2 at entry (8 bytes)
#define PATCH_PATCHABLE __attribute__((patchable_function_entry(4, 2)))
#endif

/**
 * @brief Declare a hookable function (for use in headers).
 *
 * @param ret  Return type of the function.
 * @param name Function name (without quotes).
 * @param ...  Parameter list (types and names).
 */
#define PATCH_DECLARE_HOOKABLE(ret, name, ...)                       \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__); \
    extern ret (*name##_ptr)(__VA_ARGS__)

/**
 * @brief Define a hookable function.
 *
 * Creates a function with a NOP sled that can be hooked at runtime.
 * On Linux, this generates:
 * - `name`: The actual function with NOP sled
 * - `name_ptr`: A function pointer for the pointer method
 *
 * @param ret  Return type of the function.
 * @param name Function name (without quotes).
 * @param ...  Parameter list (types and names).
 */
#define PATCH_DEFINE_HOOKABLE(ret, name, ...)                                               \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__);                        \
    ret (*name##_ptr)(__VA_ARGS__)                                     = name;              \
    static ret (*name##__saved_ptr)(__VA_ARGS__)                       = nullptr;           \
    static patch_handle_t                        *name##__patch_handle = nullptr;           \
    static int                                    name##__hook_method  = PATCH_METHOD_AUTO; \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__)

/**
 * @brief Call a hookable function.
 *
 * @param name Function name.
 * @param ...  Arguments to pass to the function.
 * @return The function's return value.
 */
#define PATCH_CALL(name, ...)     name##_ptr(__VA_ARGS__)

/**
 * @brief Get the original (unhooked) function.
 *
 * @param name Function name.
 * @return The original function.
 */
#define PATCH_HOOK_ORIGINAL(name) name

// Internal: 2-argument version (uses default method)
#define PATCH__HOOK_INSTALL2(name, hook)             \
    patch__hook_install((void **)&name##_ptr,        \
                        (void *)name,                \
                        (void *)(hook),              \
                        (void **)&name##__saved_ptr, \
                        &name##__patch_handle,       \
                        &name##__hook_method,        \
                        PATCH_METHOD_AUTO)

// Internal: 3-argument version (explicit method)
#define PATCH__HOOK_INSTALL3(name, hook, method)     \
    patch__hook_install((void **)&name##_ptr,        \
                        (void *)name,                \
                        (void *)(hook),              \
                        (void **)&name##__saved_ptr, \
                        &name##__patch_handle,       \
                        &name##__hook_method,        \
                        (method))

/**
 * @brief Install a hook on a function.
 *
 * @param name   Function name (defined with PATCH_DEFINE_HOOKABLE).
 * @param hook   Hook function with matching signature.
 * @param method (Optional) Hook method: PATCH_METHOD_POINTER or PATCH_METHOD_CODE.
 */
#define PATCH_HOOK_INSTALL(...) PATCH__INSTALL_DISPATCH(__VA_ARGS__)

/**
 * @brief Remove a hook and restore the original function.
 *
 * @param name Function name.
 */
#define PATCH_HOOK_REMOVE(name)                     \
    patch__hook_remove((void **)&name##_ptr,        \
                       (void *)name,                \
                       (void **)&name##__saved_ptr, \
                       &name##__patch_handle,       \
                       &name##__hook_method)

/**
 * @brief Check if a hook is currently installed.
 *
 * @param name Function name.
 * @return true if hooked, false otherwise.
 */
#define PATCH_HOOK_IS_INSTALLED(name) \
    (name##__saved_ptr != nullptr || name##__patch_handle != nullptr)

/**
 * @brief Get the current hook function (pointer method only).
 *
 * @param name Function name.
 * @return Pointer to the hook function, or nullptr if not hooked.
 */
#define PATCH_HOOK_GET_CURRENT(name) \
    (name##__saved_ptr ? (void *)name##_ptr : nullptr)

/* -------------------------------------------------------------------------
 * Internal: Hook Management Functions (Linux only)
 * ------------------------------------------------------------------------- */

// These are internal implementation details. Do not call directly.

static inline void
patch__hook_install(void           **ptr_loc,
                    void            *original,
                    void            *hook,
                    void           **saved_ptr,
                    patch_handle_t **handle,
                    int             *method_used,
                    int              requested_method)
{
    int method = requested_method;
    if (method == PATCH_METHOD_AUTO) {
        method = PATCH_METHOD_POINTER;
    }

    *method_used = method;

    if (method == PATCH_METHOD_POINTER) {
        *saved_ptr = *ptr_loc;
        *ptr_loc   = hook;
    }
    else if (method == PATCH_METHOD_CODE) {
        // Use the low-level API with simple replacement mode.
        // This patches the actual function code with a jump to the hook.
        patch_config_t config = {
            .target      = original,
            .replacement = hook,
        };

        patch_error_t err = patch_install(&config, handle);
        if (err == PATCH_SUCCESS) {
            // Also update pointer for PATCH_CALL to work
            *saved_ptr = *ptr_loc;
            *ptr_loc   = hook;
        }
        else {
            // Code patching failed - fall back to pointer method
            *saved_ptr   = *ptr_loc;
            *ptr_loc     = hook;
            *handle      = nullptr;
            *method_used = PATCH_METHOD_POINTER;
        }
    }
}

static inline void
patch__hook_remove(void           **ptr_loc,
                   void            *original,
                   void           **saved_ptr,
                   patch_handle_t **handle,
                   int             *method_used)
{
    if (*method_used == PATCH_METHOD_POINTER) {
        if (*saved_ptr) {
            *ptr_loc   = *saved_ptr;
            *saved_ptr = nullptr;
        }
    }
    else if (*method_used == PATCH_METHOD_CODE) {
        if (*handle) {
            patch_remove(*handle);
            *handle = nullptr;
        }
        // Also restore pointer
        if (*saved_ptr) {
            *ptr_loc   = *saved_ptr;
            *saved_ptr = nullptr;
        }
    }

    *method_used = PATCH_METHOD_AUTO;
    (void)original;
}

#endif /* PATCH_PLATFORM_DARWIN / Linux */

/* =========================================================================
 * Convenience Macros (All Platforms)
 * ========================================================================= */

/**
 * @brief Call the original function from within a hook.
 *
 * Convenience macro that combines PATCH_HOOK_ORIGINAL with a function call.
 *
 * @param name Function name.
 * @param ...  Arguments to pass to the original function.
 *
 * @return The original function's return value.
 *
 * @code
 * int my_hook(int a, int b) {
 *     printf("Before: a=%d, b=%d\n", a, b);
 *     int result = PATCH_CALL_ORIGINAL(add, a, b);
 *     printf("After: result=%d\n", result);
 *     return result + 100;
 * }
 * @endcode
 */
#define PATCH_CALL_ORIGINAL(name, ...) PATCH_HOOK_ORIGINAL(name)(__VA_ARGS__)
