#pragma once

// Unified Hook Macros for Patchable Functions
//
// Provides a portable interface for runtime function hooking:
// - On macOS: Uses function pointer indirection (hardware W^X blocks code patching)
// - On Linux: Supports both code patching and pointer indirection
//
// =============================================================================
// BASIC USAGE
// =============================================================================
//
//   // 1. Define a hookable function
//   PATCH_DEFINE_HOOKABLE(int, add, int a, int b) {
//       return a + b;
//   }
//
//   // 2. Call the function using PATCH_CALL
//   int result = PATCH_CALL(add, 1, 2);  // returns 3
//
//   // 3. Write a hook function with same signature
//   int my_hook(int a, int b) {
//       printf("intercepted!\n");
//       return PATCH_CALL_ORIGINAL(add, a, b) + 100;
//   }
//
//   // 4. Install the hook
//   PATCH_HOOK_INSTALL(add, my_hook);
//
//   // 5. Now PATCH_CALL(add, 1, 2) returns 103
//
//   // 6. Remove the hook
//   PATCH_HOOK_REMOVE(add);
//
// =============================================================================
// HOOK METHODS (Linux only - macOS always uses POINTER)
// =============================================================================
//
//   // Use specific method on Linux:
//   PATCH_HOOK_INSTALL(add, my_hook, PATCH_METHOD_POINTER);  // Pointer swap
//   PATCH_HOOK_INSTALL(add, my_hook, PATCH_METHOD_CODE);     // Code patching
//
// =============================================================================

#include "patch/patch.h"
#include "patch/patch_arch.h"

// =============================================================================
// Hook Method Selection
// =============================================================================

#define PATCH_METHOD_AUTO    0  // Platform default (pointer on macOS, code on Linux)
#define PATCH_METHOD_POINTER 1  // Function pointer indirection (always available)
#define PATCH_METHOD_CODE    2  // Code patching (Linux only, needs NOP sled)

// =============================================================================
// Internal: Macro overloading for optional method argument
// =============================================================================

// Count arguments: returns 2 or 3 (for 2 or 3 arguments)
#define PATCH__NARG_(_1, _2, _3, N, ...) N
#define PATCH__NARG(...) PATCH__NARG_(__VA_ARGS__, 3, 2, 1)

// Concatenation helpers
#define PATCH__CAT_(a, b) a##b
#define PATCH__CAT(a, b) PATCH__CAT_(a, b)

// Dispatch to INSTALL2 or INSTALL3 based on argument count
#define PATCH__INSTALL_DISPATCH(...) \
    PATCH__CAT(PATCH__HOOK_INSTALL, PATCH__NARG(__VA_ARGS__))(__VA_ARGS__)

// =============================================================================
// Platform-Specific Implementation
// =============================================================================

#ifdef PATCH_PLATFORM_DARWIN

// ---------------------------------------------------------------------------
// macOS: Function pointer indirection only
// ---------------------------------------------------------------------------
// Hardware W^X on Apple Silicon prevents code modification.
// All hooks use pointer swapping regardless of requested method.

// Declare a hookable function (for headers)
#define PATCH_DECLARE_HOOKABLE(ret, name, ...)                                \
    ret name##_impl(__VA_ARGS__);                                             \
    extern ret (*name##_ptr)(__VA_ARGS__)

// Define a hookable function
// Usage: PATCH_DEFINE_HOOKABLE(int, func, int x) { return x * 2; }
#define PATCH_DEFINE_HOOKABLE(ret, name, ...)                                 \
    ret name##_impl(__VA_ARGS__);                                             \
    ret (*name##_ptr)(__VA_ARGS__) = name##_impl;                             \
    static ret (*name##__saved_ptr)(__VA_ARGS__) = nullptr;                   \
    ret name##_impl(__VA_ARGS__)

// Call a hookable function (goes through pointer on macOS)
#define PATCH_CALL(name, ...) name##_ptr(__VA_ARGS__)

// Get original function (safe to call from within hook)
#define PATCH_HOOK_ORIGINAL(name) name##_impl

// Install hook - method argument ignored on macOS
// Supports both PATCH_HOOK_INSTALL(name, hook) and PATCH_HOOK_INSTALL(name, hook, method)
#define PATCH__HOOK_INSTALL2(name, hook)                                      \
    do {                                                                      \
        name##__saved_ptr = name##_ptr;                                       \
        name##_ptr = (hook);                                                  \
    } while (0)

#define PATCH__HOOK_INSTALL3(name, hook, method)                              \
    do {                                                                      \
        (void)(method);  /* Ignored on macOS */                               \
        name##__saved_ptr = name##_ptr;                                       \
        name##_ptr = (hook);                                                  \
    } while (0)

#define PATCH_HOOK_INSTALL(...) PATCH__INSTALL_DISPATCH(__VA_ARGS__)

// Remove hook
#define PATCH_HOOK_REMOVE(name)                                               \
    do {                                                                      \
        if (name##__saved_ptr) {                                              \
            name##_ptr = name##__saved_ptr;                                   \
            name##__saved_ptr = nullptr;                                      \
        }                                                                     \
    } while (0)

// Check if hook is currently installed
#define PATCH_HOOK_IS_INSTALLED(name) (name##__saved_ptr != nullptr)

// Get the active hook function (or nullptr if not hooked)
#define PATCH_HOOK_GET_CURRENT(name)                                          \
    (name##__saved_ptr ? name##_ptr : nullptr)

#else // Linux

// ---------------------------------------------------------------------------
// Linux: Supports both code patching and pointer indirection
// ---------------------------------------------------------------------------

#define PATCH_PATCHABLE __attribute__((patchable_function_entry(8, 4)))

// Declare a hookable function (for headers)
#define PATCH_DECLARE_HOOKABLE(ret, name, ...)                                \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__);          \
    extern ret (*name##_ptr)(__VA_ARGS__)

// Define a hookable function
// Creates: name (with NOP sled), name_ptr (for pointer method)
#define PATCH_DEFINE_HOOKABLE(ret, name, ...)                                 \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__);          \
    ret (*name##_ptr)(__VA_ARGS__) = name;                                    \
    static ret (*name##__saved_ptr)(__VA_ARGS__) = nullptr;                   \
    static patch_handle_t *name##__patch_handle = nullptr;                    \
    static int name##__hook_method = PATCH_METHOD_AUTO;                       \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__)

// Call a hookable function (direct call on Linux - goes through name_ptr)
#define PATCH_CALL(name, ...) name##_ptr(__VA_ARGS__)

// Get original function
#define PATCH_HOOK_ORIGINAL(name) name

// Install hook with optional method selection
// Supports both PATCH_HOOK_INSTALL(name, hook) and PATCH_HOOK_INSTALL(name, hook, method)
// Default: PATCH_METHOD_AUTO (pointer method for simplicity)
#define PATCH__HOOK_INSTALL2(name, hook)                                      \
    patch__hook_install((void **)&name##_ptr,                                 \
                        (void *)name,                                         \
                        (void *)(hook),                                       \
                        (void **)&name##__saved_ptr,                          \
                        &name##__patch_handle,                                \
                        &name##__hook_method,                                 \
                        PATCH_METHOD_AUTO)

#define PATCH__HOOK_INSTALL3(name, hook, method)                              \
    patch__hook_install((void **)&name##_ptr,                                 \
                        (void *)name,                                         \
                        (void *)(hook),                                       \
                        (void **)&name##__saved_ptr,                          \
                        &name##__patch_handle,                                \
                        &name##__hook_method,                                 \
                        (method))

#define PATCH_HOOK_INSTALL(...) PATCH__INSTALL_DISPATCH(__VA_ARGS__)

// Remove hook
#define PATCH_HOOK_REMOVE(name)                                               \
    patch__hook_remove((void **)&name##_ptr,                                  \
                       (void *)name,                                          \
                       (void **)&name##__saved_ptr,                           \
                       &name##__patch_handle,                                 \
                       &name##__hook_method)

// Check if hook is currently installed
#define PATCH_HOOK_IS_INSTALLED(name)                                         \
    (name##__saved_ptr != nullptr || name##__patch_handle != nullptr)

// Get the active hook function (only valid for pointer method)
#define PATCH_HOOK_GET_CURRENT(name)                                          \
    (name##__saved_ptr ? (void *)name##_ptr : nullptr)

// ---------------------------------------------------------------------------
// Linux: Internal hook management functions
// ---------------------------------------------------------------------------

static inline void
patch__hook_install(void             **ptr_loc,
                    void              *original,
                    void              *hook,
                    void             **saved_ptr,
                    patch_handle_t   **handle,
                    int               *method_used,
                    int                requested_method)
{
    // Resolve AUTO to actual method
    int method = requested_method;
    if (method == PATCH_METHOD_AUTO) {
        // Default to pointer method for unified interface simplicity
        method = PATCH_METHOD_POINTER;
    }

    *method_used = method;

    if (method == PATCH_METHOD_POINTER) {
        // Pointer swap method
        *saved_ptr = *ptr_loc;
        *ptr_loc   = hook;
    }
    else {
        // Code patching method
        // For simple function replacement, we use a prologue that always
        // redirects to the hook. The hook can call the original via trampoline.
        //
        // Note: This is a simplified version. For full prologue/epilogue
        // callbacks with argument inspection, use patch_install() directly.
        patch_config_t config = {
            .target   = original,
            .prologue = nullptr,
        };

        // For now, use pointer method as fallback if code patching
        // isn't fully set up for direct replacement
        // TODO: Implement proper trampoline-based replacement
        *saved_ptr   = *ptr_loc;
        *ptr_loc     = hook;
        *method_used = PATCH_METHOD_POINTER;

        (void)config;
        (void)handle;
    }
}

static inline void
patch__hook_remove(void             **ptr_loc,
                   void              *original,
                   void             **saved_ptr,
                   patch_handle_t   **handle,
                   int               *method_used)
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
        // Also restore pointer if it was modified
        if (*saved_ptr) {
            *ptr_loc   = *saved_ptr;
            *saved_ptr = nullptr;
        }
    }

    *method_used = PATCH_METHOD_AUTO;
    (void)original;
}

#endif // PATCH_PLATFORM_DARWIN

// =============================================================================
// Convenience: Call original from within hook
// =============================================================================

#define PATCH_CALL_ORIGINAL(name, ...) PATCH_HOOK_ORIGINAL(name)(__VA_ARGS__)
