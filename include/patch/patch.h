#pragma once

/**
 * @file patch.h
 * @brief Runtime function hooking library for x86-64 and ARM64.
 *
 * This library provides runtime function hooking (detours) on Linux and macOS.
 * It supports inserting callbacks at function prologues and epilogues, with
 * the ability to inspect/modify arguments and return values.
 *
 * ## Quick Start
 *
 * For simple function replacement, use the high-level macros in patch_hook.h:
 * @code
 * #include "patch/patch_hook.h"
 *
 * PATCH_DEFINE_HOOKABLE(int, add, int a, int b) { return a + b; }
 *
 * int my_hook(int a, int b) {
 *     return PATCH_CALL_ORIGINAL(add, a, b) + 100;
 * }
 *
 * PATCH_HOOK_INSTALL(add, my_hook);
 * @endcode
 *
 * For advanced use (prologue/epilogue callbacks with argument inspection),
 * use the low-level API in this header directly.
 *
 * ## Platform Notes
 *
 * - **Linux**: Full support for runtime code patching via NOP sleds
 *   (patchable_function_entry attribute).
 * - **macOS**: Hardware W^X on Apple Silicon prevents code modification.
 *   Use function pointer indirection via patch_hook.h macros instead.
 *
 * @see patch_hook.h for the recommended high-level macro interface
 * @see patch_arch.h for architecture detection macros
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Error codes returned by patch functions.
 *
 * Most functions return PATCH_SUCCESS (0) on success, or one of these
 * error codes on failure. Use patch_get_error_details() to get a
 * human-readable description of the most recent error.
 */
typedef enum {
    /** Operation completed successfully. */
    PATCH_SUCCESS = 0,

    /** Function prologue pattern not recognized. The function may not have
     *  been compiled with patchable_function_entry or uses an unknown
     *  prologue sequence. */
    PATCH_ERR_PATTERN_UNRECOGNIZED,

    /** Function epilogue pattern not recognized (for epilogue hooks). */
    PATCH_ERR_EPILOGUE_UNRECOGNIZED,

    /** Not enough space in the function prologue for the detour jump.
     *  Functions need at least 5 bytes (x86-64) or 4 bytes (ARM64). */
    PATCH_ERR_INSUFFICIENT_SPACE,

    /** Failed to change memory protection. On macOS ARM64, this is expected
     *  for code pages due to hardware W^X enforcement. */
    PATCH_ERR_MEMORY_PROTECTION,

    /** Failed to allocate memory for trampoline or internal structures. */
    PATCH_ERR_ALLOCATION_FAILED,

    /** Target function is already patched. Remove existing patch first. */
    PATCH_ERR_ALREADY_PATCHED,

    /** Target function is not currently patched. */
    PATCH_ERR_NOT_PATCHED,

    /** Current CPU architecture is not supported. */
    PATCH_ERR_UNSUPPORTED_ARCH,

    /** Invalid argument passed to function (e.g., nullptr). */
    PATCH_ERR_INVALID_ARGUMENT,

    /** Internal error (bug in the library). */
    PATCH_ERR_INTERNAL,
} patch_error_t;

/**
 * @brief Opaque handle to an installed patch.
 *
 * Returned by patch_install() and used to remove, disable, or enable the patch.
 * The handle remains valid until patch_remove() is called.
 */
typedef struct patch_handle patch_handle_t;

/**
 * @brief Opaque context passed to prologue/epilogue callbacks.
 *
 * Provides access to function arguments, return values, and the original
 * function. Valid only for the duration of the callback.
 */
typedef struct patch_context patch_context_t;

/**
 * @brief Prologue callback function type.
 *
 * Called before the original function executes. Can inspect and modify
 * arguments, or skip the original function entirely.
 *
 * @param ctx       Context for accessing arguments and return value.
 * @param user_data User-provided data from patch_config_t.prologue_user_data.
 *
 * @return true to proceed to the original function, false to skip it.
 *         If returning false, you should set a return value using
 *         patch_context_set_return().
 *
 * @see patch_context_get_arg()
 * @see patch_context_set_arg()
 * @see patch_context_set_return()
 */
typedef bool (*patch_prologue_fn)(patch_context_t *ctx, void *user_data);

/**
 * @brief Epilogue callback function type.
 *
 * Called after the original function returns. Can inspect arguments
 * (which may have been modified by the function) and modify the return value.
 *
 * @param ctx       Context for accessing arguments and return value.
 * @param user_data User-provided data from patch_config_t.epilogue_user_data.
 *
 * @see patch_context_get_arg()
 * @see patch_context_get_return()
 * @see patch_context_set_return()
 */
typedef void (*patch_epilogue_fn)(patch_context_t *ctx, void *user_data);

/**
 * @brief Configuration for installing a patch.
 *
 * There are two modes of operation:
 *
 * **Simple mode** (set `replacement`): Direct function replacement.
 * Calls to target are redirected to replacement. Faster than callback mode
 * since no dispatcher stub is generated.
 *
 * @code
 * patch_config_t config = {
 *     .target = (void *)original_func,
 *     .replacement = (void *)my_replacement,
 * };
 * @endcode
 *
 * **Callback mode** (set `prologue` and/or `epilogue`): Advanced hooking
 * with argument inspection. Calls to target go through a dispatcher that
 * invokes callbacks before/after the original function.
 *
 * @code
 * patch_config_t config = {
 *     .target = (void *)my_function,
 *     .prologue = my_prologue_hook,
 *     .prologue_user_data = &my_context,
 * };
 * @endcode
 *
 * You cannot mix both modes (i.e., don't set replacement and callbacks).
 */
typedef struct {
    /** Target function to patch. Must point to the start of the function. */
    void *target;

    /**
     * Simple replacement mode: direct replacement function.
     * When set, calls to target are redirected directly to this function
     * without going through the dispatcher. The replacement receives the
     * same arguments as target and must have the same signature.
     *
     * Use patch_get_trampoline() on the handle to call the original.
     *
     * Mutually exclusive with prologue/epilogue callbacks.
     */
    void *replacement;

    /** Callback invoked before the original function (may be nullptr). */
    patch_prologue_fn prologue;

    /** Callback invoked after the original function (may be nullptr). */
    patch_epilogue_fn epilogue;

    /** User data passed to prologue callback. */
    void *prologue_user_data;

    /** User data passed to epilogue callback. */
    void *epilogue_user_data;
} patch_config_t;

/**
 * @brief Check if a function can be patched.
 *
 * Tests whether the target function has a recognized prologue pattern
 * without actually modifying anything. Use this to gracefully handle
 * functions that cannot be patched.
 *
 * @param target Pointer to the function to check.
 *
 * @return PATCH_SUCCESS if the function can be patched,
 *         PATCH_ERR_PATTERN_UNRECOGNIZED if the prologue is not recognized,
 *         PATCH_ERR_INVALID_ARGUMENT if target is nullptr.
 *
 * @note On macOS ARM64, this may return PATCH_ERR_MEMORY_PROTECTION even
 *       for valid functions due to hardware restrictions. Use the
 *       patch_hook.h macros instead for cross-platform hooking.
 */
[[nodiscard]] patch_error_t patch_can_install(void *target);

/**
 * @brief Install a hook on a function.
 *
 * Installs prologue and/or epilogue callbacks on the target function.
 * The original function bytes are relocated to a trampoline, allowing
 * the original to be called from within callbacks.
 *
 * @param config Configuration specifying target and callbacks.
 * @param handle Output parameter receiving the patch handle.
 *
 * @return PATCH_SUCCESS on success, or an error code on failure.
 *         On failure, *handle is set to nullptr.
 *
 * @note The target function must have been compiled with
 *       patchable_function_entry(8, 4) or have a recognized prologue.
 *
 * @see patch_remove()
 * @see patch_disable()
 */
[[nodiscard]] patch_error_t patch_install(const patch_config_t *config,
                                          patch_handle_t      **handle);

/**
 * @brief Remove a patch and restore the original function.
 *
 * Removes the detour jump and frees all resources associated with the patch.
 * After this call, the handle is invalid and must not be used.
 *
 * @param handle Handle returned by patch_install().
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_INVALID_ARGUMENT if handle is nullptr.
 */
patch_error_t patch_remove(patch_handle_t *handle);

/**
 * @brief Temporarily disable a patch.
 *
 * Disables the patch so the original function runs without interception.
 * The patch can be re-enabled with patch_enable(). This is faster than
 * removing and reinstalling the patch.
 *
 * @param handle Handle returned by patch_install().
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_NOT_PATCHED if already disabled,
 *         PATCH_ERR_INVALID_ARGUMENT if handle is nullptr.
 *
 * @see patch_enable()
 */
patch_error_t patch_disable(patch_handle_t *handle);

/**
 * @brief Re-enable a previously disabled patch.
 *
 * @param handle Handle returned by patch_install().
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_ALREADY_PATCHED if already enabled,
 *         PATCH_ERR_INVALID_ARGUMENT if handle is nullptr.
 *
 * @see patch_disable()
 */
patch_error_t patch_enable(patch_handle_t *handle);

/**
 * @brief Get detailed error message for the last failure.
 *
 * Returns a human-readable string describing the most recent error
 * on the calling thread. The string is valid until the next patch
 * function call on the same thread.
 *
 * @return Error description string, or empty string if no error.
 */
[[nodiscard]] const char *patch_get_error_details(void);

/* =========================================================================
 * Context API - For use within prologue/epilogue callbacks
 * ========================================================================= */

/**
 * @brief Get a function argument by index.
 *
 * Returns a pointer to the storage location of the specified argument.
 * The pointer can be cast to the appropriate type and dereferenced.
 *
 * @param ctx   Context passed to the callback.
 * @param index Zero-based argument index.
 *
 * @return Pointer to argument storage, or nullptr if index is out of range.
 *
 * @code
 * bool my_prologue(patch_context_t *ctx, void *user_data) {
 *     int *first_arg = (int *)patch_context_get_arg(ctx, 0);
 *     printf("First argument: %d\n", *first_arg);
 *     return true;
 * }
 * @endcode
 *
 * @note Only register arguments are accessible (6 on x86-64, 8 on ARM64).
 *       Stack arguments are not currently supported.
 */
[[nodiscard]] void *patch_context_get_arg(patch_context_t *ctx, size_t index);

/**
 * @brief Modify a function argument.
 *
 * Changes the value of the specified argument before the original
 * function sees it. Only valid in prologue callbacks.
 *
 * @param ctx   Context passed to the callback.
 * @param index Zero-based argument index.
 * @param value Pointer to the new value.
 * @param size  Size of the value in bytes.
 *
 * @return true on success, false if index is out of range or size is invalid.
 */
bool patch_context_set_arg(patch_context_t *ctx, size_t index, const void *value, size_t size);

/**
 * @brief Get the function's return value.
 *
 * Returns a pointer to the return value storage. Only valid in epilogue
 * callbacks (after the original function has returned).
 *
 * @param ctx Context passed to the callback.
 *
 * @return Pointer to return value storage.
 *
 * @code
 * void my_epilogue(patch_context_t *ctx, void *user_data) {
 *     int *result = (int *)patch_context_get_return(ctx);
 *     printf("Function returned: %d\n", *result);
 * }
 * @endcode
 */
[[nodiscard]] void *patch_context_get_return(patch_context_t *ctx);

/**
 * @brief Set or modify the return value.
 *
 * In a prologue callback, use this when returning false to provide
 * the value that the caller will receive. In an epilogue callback,
 * use this to modify the actual return value.
 *
 * @param ctx   Context passed to the callback.
 * @param value Pointer to the new return value.
 * @param size  Size of the value in bytes.
 *
 * @code
 * bool my_prologue(patch_context_t *ctx, void *user_data) {
 *     int fake_result = 42;
 *     patch_context_set_return(ctx, &fake_result, sizeof(fake_result));
 *     return false;  // Skip original, return 42
 * }
 * @endcode
 */
void patch_context_set_return(patch_context_t *ctx,
                              const void      *value,
                              size_t           size);

/**
 * @brief Get a callable pointer to the original function.
 *
 * Returns a pointer to the trampoline that executes the original
 * function. Use this to call the original from within a hook.
 *
 * @param ctx Context passed to the callback.
 *
 * @return Function pointer that can be cast to the original signature.
 *
 * @code
 * bool my_prologue(patch_context_t *ctx, void *user_data) {
 *     typedef int (*orig_fn)(int, int);
 *     orig_fn original = (orig_fn)patch_context_get_original(ctx);
 *
 *     int *a = (int *)patch_context_get_arg(ctx, 0);
 *     int *b = (int *)patch_context_get_arg(ctx, 1);
 *
 *     int result = original(*a, *b);  // Call original
 *     printf("Original returned: %d\n", result);
 *
 *     return true;  // Also let normal flow continue
 * }
 * @endcode
 */
[[nodiscard]] void *patch_context_get_original(patch_context_t *ctx);

/**
 * @brief Get the trampoline (original function) from a patch handle.
 *
 * Returns a pointer to the trampoline that executes the original
 * function. This is primarily for use with simple replacement mode,
 * where there is no context object.
 *
 * @param handle Handle returned by patch_install().
 *
 * @return Function pointer that can be cast to the original signature,
 *         or nullptr if handle is invalid.
 *
 * @code
 * static patch_handle_t *g_handle;
 *
 * int my_replacement(int a, int b) {
 *     typedef int (*orig_fn)(int, int);
 *     orig_fn original = (orig_fn)patch_get_trampoline(g_handle);
 *     return original(a, b) + 100;
 * }
 *
 * patch_config_t config = {
 *     .target = (void *)add,
 *     .replacement = (void *)my_replacement,
 * };
 * patch_install(&config, &g_handle);
 * @endcode
 */
[[nodiscard]] void *patch_get_trampoline(patch_handle_t *handle);
