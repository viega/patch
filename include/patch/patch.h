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

#ifdef PATCH_HAVE_LIBFFI
#include <ffi.h>
#endif

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

    /** Symbol not found in specified library or process. */
    PATCH_ERR_SYMBOL_NOT_FOUND,

    /** No GOT entry found for the symbol (when PATCH_METHOD_GOT requested). */
    PATCH_ERR_NO_GOT_ENTRY,

    /** Failed to install signal handler for breakpoint hooking. */
    PATCH_ERR_SIGNAL_HANDLER,

    /** No hardware watchpoints available (all debug registers in use). */
    PATCH_ERR_NO_WATCHPOINT,
} patch_error_t;

/**
 * @brief Hooking method selection.
 *
 * Controls how a function is hooked. AUTO (the default) tries GOT hooking
 * first for imported symbols, falling back to code patching.
 */
typedef enum {
    /** Automatic selection: try GOT first, fall back to code patching,
     *  then fall back to breakpoint hooking. */
    PATCH_METHOD_AUTO = 0,

    /** Force GOT/PLT hooking. Fails if no GOT entry exists for the symbol.
     *  Only works for imported functions (calls through PLT). */
    PATCH_METHOD_GOT,

    /** Force code patching. Modifies the function's prologue directly.
     *  Works for any function with a recognized prologue pattern. */
    PATCH_METHOD_CODE,

    /** Force breakpoint-based hooking. Uses INT3 (x86-64) or BRK (ARM64)
     *  instruction with a SIGTRAP handler. Works on any function but has
     *  higher overhead due to signal handling per call. */
    PATCH_METHOD_BREAKPOINT,
} patch_method_t;

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

    /**
     * Hooking method selection (default: PATCH_METHOD_AUTO).
     *
     * - PATCH_METHOD_AUTO: Try GOT hooking first (for imported symbols),
     *   fall back to code patching if no GOT entry found.
     * - PATCH_METHOD_GOT: Force GOT hooking, fail if no GOT entry.
     * - PATCH_METHOD_CODE: Force code patching.
     *
     * GOT hooking only works with patch_install_symbol(), not patch_install().
     */
    patch_method_t method;

#ifdef PATCH_HAVE_LIBFFI
    /**
     * Optional: FFI type information for full argument forwarding.
     * When provided, all arguments (including stack args) are forwarded
     * to the original function when prologue returns true.
     *
     * Set to nullptr to use default register-only forwarding.
     */
    ffi_type **arg_types; /**< Array of argument types */
    ffi_type  *return_type; /**< Return type (nullptr = ffi_type_uint64) */
    size_t     arg_count;   /**< Number of arguments */
#endif
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
 *       For additional arguments passed on the stack, use patch_context_get_stack_arg().
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
 * @brief Get a floating-point argument by index.
 *
 * Returns a pointer to the storage location of the specified FP argument.
 * The pointer can be cast to float* or double* and dereferenced.
 *
 * @param ctx   Context passed to the callback.
 * @param index Zero-based FP argument index (0-7 on both architectures).
 *
 * @return Pointer to 128-bit FP argument storage, or nullptr if out of range.
 *
 * @code
 * bool my_prologue(patch_context_t *ctx, void *user_data) {
 *     double *first_fp = (double *)patch_context_get_fp_arg(ctx, 0);
 *     printf("First FP argument: %f\n", *first_fp);
 *     return true;
 * }
 * @endcode
 *
 * @note FP arguments use separate registers from integer arguments.
 *       A function like `void foo(int a, double b)` has `a` in integer
 *       arg 0 and `b` in FP arg 0.
 */
[[nodiscard]] void *patch_context_get_fp_arg(patch_context_t *ctx, size_t index);

/**
 * @brief Modify a floating-point argument.
 *
 * Changes the value of the specified FP argument before the original
 * function sees it. Only valid in prologue callbacks.
 *
 * @param ctx   Context passed to the callback.
 * @param index Zero-based FP argument index.
 * @param value Pointer to the new value (float, double, or 128-bit vector).
 * @param size  Size of the value in bytes (4, 8, or 16).
 *
 * @return true on success, false if index is out of range.
 */
bool patch_context_set_fp_arg(patch_context_t *ctx, size_t index, const void *value, size_t size);

/**
 * @brief Get a stack argument by index.
 *
 * Returns a pointer to a function argument that was passed on the stack
 * (beyond the register arguments). On x86-64 SysV ABI, stack arguments
 * start after the 6 register arguments. On ARM64 AAPCS64, stack arguments
 * start after the 8 register arguments.
 *
 * @param ctx   Context passed to the callback.
 * @param index Zero-based stack argument index (0 = first stack arg).
 *
 * @return Pointer to the stack argument, or nullptr if ctx is nullptr.
 *
 * @code
 * // For a function: void foo(int a, int b, int c, int d, int e, int f, int g)
 * // On x86-64: a-f are in registers (index 0-5), g is on stack (index 0)
 * bool my_prologue(patch_context_t *ctx, void *user_data) {
 *     int *seventh_arg = (int *)patch_context_get_stack_arg(ctx, 0);
 *     if (seventh_arg) {
 *         printf("Seventh argument: %d\n", *seventh_arg);
 *     }
 *     return true;
 * }
 * @endcode
 *
 * @warning Stack arguments point directly into the caller's stack frame.
 *          Modifying them affects the caller's memory. This is different
 *          from register arguments which are copied into the context.
 *
 * @note The returned pointer is only valid during the prologue callback.
 *       The epilogue callback receives a different stack pointer.
 *
 * @warning **Limitation**: If the prologue callback returns true (allowing
 *          the original function to be called), stack arguments are NOT
 *          forwarded to the original. Only register arguments are passed.
 *          To handle functions with stack arguments, either:
 *          1. Return false and compute/provide the result yourself, or
 *          2. Use simple replacement mode with patch_get_trampoline() and
 *             manually forward all arguments including stack arguments.
 */
[[nodiscard]] void *patch_context_get_stack_arg(patch_context_t *ctx, size_t index);

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

/* =========================================================================
 * Symbol Resolution API - For hooking by symbol name
 * ========================================================================= */

/**
 * @brief Resolve a symbol to an address.
 *
 * Looks up a symbol by name in the specified library or the current process.
 * This uses dlsym (POSIX) to perform the lookup.
 *
 * @param symbol  Symbol name to resolve.
 * @param library Library path (nullptr for current process/all loaded libraries).
 * @param address Output parameter receiving the symbol address.
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_SYMBOL_NOT_FOUND if the symbol cannot be resolved,
 *         PATCH_ERR_INVALID_ARGUMENT if symbol or address is nullptr.
 *
 * @code
 * void *addr;
 * if (patch_resolve_symbol("malloc", nullptr, &addr) == PATCH_SUCCESS) {
 *     printf("malloc is at %p\n", addr);
 * }
 *
 * // From a specific library
 * if (patch_resolve_symbol("SSL_read", "libssl.so", &addr) == PATCH_SUCCESS) {
 *     printf("SSL_read is at %p\n", addr);
 * }
 * @endcode
 */
[[nodiscard]] patch_error_t patch_resolve_symbol(const char *symbol,
                                                 const char *library,
                                                 void      **address);

/**
 * @brief Install a hook on a function by symbol name.
 *
 * Resolves the symbol to an address using dlsym and then installs the hook.
 * This is a convenience function equivalent to:
 *
 * @code
 * void *target;
 * patch_resolve_symbol(symbol, library, &target);
 * config.target = target;
 * patch_install(&config, handle);
 * @endcode
 *
 * @param symbol  Symbol name of the function to hook.
 * @param library Library path containing the symbol (nullptr for current process).
 * @param config  Configuration specifying callbacks (target field is ignored/overwritten).
 * @param handle  Output parameter receiving the patch handle.
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_SYMBOL_NOT_FOUND if the symbol cannot be resolved,
 *         PATCH_ERR_INVALID_ARGUMENT if symbol, config, or handle is nullptr,
 *         or other error codes from patch_install().
 *
 * @code
 * bool my_prologue(patch_context_t *ctx, void *user_data) {
 *     printf("malloc called!\n");
 *     return true;
 * }
 *
 * patch_config_t config = { .prologue = my_prologue };
 * patch_handle_t *handle;
 *
 * patch_error_t err = patch_install_symbol("malloc", nullptr, &config, &handle);
 * if (err == PATCH_SUCCESS) {
 *     // malloc is now hooked
 * }
 * @endcode
 *
 * @note The library handle from dlopen (if library is specified) is kept
 *       open for the lifetime of the patch. It is closed when patch_remove()
 *       is called.
 */
[[nodiscard]] patch_error_t patch_install_symbol(const char          *symbol,
                                                 const char          *library,
                                                 const patch_config_t *config,
                                                 patch_handle_t      **handle);

/* =========================================================================
 * Hot-Swap API - Change callbacks without removing the hook
 * ========================================================================= */

/**
 * @brief Change a hook's prologue callback without removing the hook.
 *
 * Atomically updates the prologue callback. There is no window where calls
 * bypass the hook - the old callback handles calls until the exact moment
 * the new one takes over.
 *
 * @param handle    Handle returned by patch_install().
 * @param prologue  New prologue callback (may be nullptr to disable).
 * @param user_data New user data for the prologue callback.
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_INVALID_ARGUMENT if handle is nullptr,
 *         PATCH_ERR_INVALID_ARGUMENT if this is a GOT hook (use replacement mode).
 *
 * @code
 * // Change logging level without missing any calls
 * patch_set_prologue(handle, verbose_logging ? detailed_log : brief_log, NULL);
 * @endcode
 *
 * @note Only valid for hooks installed with prologue/epilogue callbacks,
 *       not for simple replacement mode or GOT hooks.
 */
patch_error_t patch_set_prologue(patch_handle_t   *handle,
                                 patch_prologue_fn prologue,
                                 void             *user_data);

/**
 * @brief Change a hook's epilogue callback without removing the hook.
 *
 * Atomically updates the epilogue callback.
 *
 * @param handle    Handle returned by patch_install().
 * @param epilogue  New epilogue callback (may be nullptr to disable).
 * @param user_data New user data for the epilogue callback.
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_INVALID_ARGUMENT if handle is nullptr,
 *         PATCH_ERR_INVALID_ARGUMENT if this is a GOT hook.
 *
 * @note Only valid for hooks installed with prologue/epilogue callbacks.
 */
patch_error_t patch_set_epilogue(patch_handle_t   *handle,
                                 patch_epilogue_fn epilogue,
                                 void             *user_data);

/**
 * @brief Change both prologue and epilogue callbacks atomically.
 *
 * Updates both callbacks in a single operation. Useful when the callbacks
 * depend on each other and must be updated together.
 *
 * @param handle          Handle returned by patch_install().
 * @param prologue        New prologue callback (may be nullptr).
 * @param prologue_data   New user data for prologue.
 * @param epilogue        New epilogue callback (may be nullptr).
 * @param epilogue_data   New user data for epilogue.
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_INVALID_ARGUMENT if handle is nullptr,
 *         PATCH_ERR_INVALID_ARGUMENT if this is a GOT hook.
 */
patch_error_t patch_set_callbacks(patch_handle_t   *handle,
                                  patch_prologue_fn prologue,
                                  void             *prologue_data,
                                  patch_epilogue_fn epilogue,
                                  void             *epilogue_data);

/**
 * @brief Change a GOT hook's replacement function.
 *
 * For GOT hooks, atomically updates the replacement function pointer.
 * The old function handles calls until the exact moment the new one takes over.
 *
 * @param handle      Handle returned by patch_install() with PATCH_METHOD_GOT.
 * @param replacement New replacement function.
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_INVALID_ARGUMENT if handle or replacement is nullptr,
 *         PATCH_ERR_INVALID_ARGUMENT if this is not a GOT hook.
 *
 * @note Only valid for GOT hooks. For code-patched hooks, you must use
 *       patch_remove() and patch_install() to change the replacement.
 */
patch_error_t patch_set_replacement(patch_handle_t *handle, void *replacement);

/* =========================================================================
 * Watchpoint-Guarded Pointer Hooks - Hook function pointers with auto-repair
 * ========================================================================= */

/**
 * @brief Action to take when a watched function pointer is updated.
 *
 * When the program writes to a hooked function pointer, the watchpoint
 * callback returns one of these values to control what happens next.
 */
typedef enum {
    /**
     * Keep the hook, update the cached original.
     * The new value is saved as the "original" function, and the detour
     * is reinstalled. This is the default behavior when no callback is set.
     */
    PATCH_WATCH_KEEP,

    /**
     * Remove the hook, let the new value stand.
     * The watchpoint is cleared and the program's write takes effect.
     * The hook handle becomes invalid.
     */
    PATCH_WATCH_REMOVE,

    /**
     * Keep the hook and the old original, ignore the update.
     * The detour is reinstalled pointing to the same original as before.
     * The program's attempted write is effectively reverted.
     */
    PATCH_WATCH_REJECT,
} patch_watch_action_t;

/**
 * @brief Callback invoked when a watched function pointer is updated.
 *
 * @param handle    The handle for this pointer hook.
 * @param old_value The previous "original" function (what we were calling through).
 * @param new_value What the program tried to write to the pointer.
 * @param user_data User-provided data from patch_pointer_config_t.user_data.
 *
 * @return Action to take (KEEP, REMOVE, or REJECT).
 *
 * @note This callback runs in a signal handler context. Avoid calling
 *       non-async-signal-safe functions (malloc, printf, etc.).
 */
typedef patch_watch_action_t (*patch_watch_callback_t)(patch_handle_t *handle,
                                                       void           *old_value,
                                                       void           *new_value,
                                                       void           *user_data);

/**
 * @brief Configuration for installing a watchpoint-guarded pointer hook.
 *
 * This hooks a function pointer (e.g., vtable entry, callback pointer, GOT slot)
 * and uses a hardware watchpoint to detect when the program updates the pointer.
 * When an update is detected, the hook is automatically reinstalled (by default)
 * or an optional callback decides what to do.
 *
 * @code
 * // Hook a vtable entry
 * patch_pointer_config_t config = {
 *     .location = &obj->vtable->method,
 *     .replacement = my_hook,
 * };
 * patch_handle_t *handle;
 * patch_install_pointer(&config, &handle);
 *
 * // Now if someone does: obj->vtable->method = other_impl;
 * // The hook automatically reinstalls with other_impl as the new "original"
 * @endcode
 */
typedef struct {
    /**
     * Address of the function pointer to hook.
     * This is a pointer to a pointer (e.g., &vtable[3], &callback).
     */
    void **location;

    /**
     * Replacement function. Calls to the pointer will invoke this function.
     * Use patch_get_trampoline() to call the original.
     */
    void *replacement;

    /**
     * Optional callback invoked when the pointer is updated.
     * If nullptr, defaults to PATCH_WATCH_KEEP behavior.
     */
    patch_watch_callback_t on_update;

    /** User data passed to the on_update callback. */
    void *user_data;
} patch_pointer_config_t;

/**
 * @brief Install a watchpoint-guarded hook on a function pointer.
 *
 * This installs a hook on a function pointer (vtable entry, callback, etc.)
 * that is protected by a hardware watchpoint. If the program updates the
 * pointer, the hook is automatically reinstalled.
 *
 * @param config Configuration specifying the pointer location and replacement.
 * @param handle Output parameter receiving the patch handle.
 *
 * @return PATCH_SUCCESS on success,
 *         PATCH_ERR_NO_WATCHPOINT if all hardware watchpoints are in use,
 *         PATCH_ERR_INVALID_ARGUMENT if config, location, replacement, or handle is nullptr,
 *         PATCH_ERR_MEMORY_PROTECTION if the pointer location cannot be written.
 *
 * @code
 * // Example: Hook a C++ vtable entry
 * MyClass *obj = get_object();
 * void **vtable = *(void ***)obj;  // First word of object is vtable pointer
 *
 * patch_pointer_config_t config = {
 *     .location = &vtable[3],      // Hook method at index 3
 *     .replacement = my_hook,
 *     .on_update = my_callback,    // Optional: called if vtable is swapped
 * };
 *
 * patch_handle_t *handle;
 * patch_error_t err = patch_install_pointer(&config, &handle);
 * @endcode
 *
 * @note Uses hardware debug registers (DR0-DR3 on x86-64, DBGWVR on ARM64).
 *       Only 4 watchpoints are available. Returns PATCH_ERR_NO_WATCHPOINT
 *       when exhausted.
 *
 * @note The on_update callback runs in signal handler context. Keep it minimal.
 *
 * @see patch_remove() to remove the hook and free the watchpoint.
 * @see patch_get_trampoline() to call the original function.
 */
[[nodiscard]] patch_error_t patch_install_pointer(const patch_pointer_config_t *config,
                                                  patch_handle_t              **handle);
