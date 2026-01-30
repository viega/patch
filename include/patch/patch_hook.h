#pragma once

// Portable hook macros for patchable functions
//
// On Linux: Uses patchable_function_entry for direct code patching
// On macOS: Uses function pointer indirection (code patching blocked by hardware)
//
// Usage:
//   // In header or at file scope:
//   PATCH_DECLARE_HOOKABLE(int, my_function, int a, int b);
//
//   // In source file:
//   PATCH_DEFINE_HOOKABLE(int, my_function, int a, int b) {
//       return a + b;
//   }
//
//   // To call:
//   int result = my_function(10, 20);
//
//   // On macOS, to hook:
//   my_function_ptr = my_hook;  // Redirect to your hook
//   my_function_ptr = my_function_impl;  // Restore original

#include "patch/patch_arch.h"

#ifdef PATCH_PLATFORM_DARWIN

// macOS: Use function pointer indirection for hookability
// The actual function is named _impl, and a global function pointer provides indirection

#define PATCH_DECLARE_HOOKABLE(ret, name, ...)                      \
    ret name##_impl(__VA_ARGS__);                                   \
    extern ret (*name##_ptr)(__VA_ARGS__);                          \
    static inline ret name(__VA_ARGS__)

#define PATCH_DEFINE_HOOKABLE(ret, name, ...)                       \
    ret name##_impl(__VA_ARGS__);                                   \
    ret (*name##_ptr)(__VA_ARGS__) = name##_impl;                   \
    static inline ret name(__VA_ARGS__) {                           \
        return name##_ptr

#define PATCH_HOOKABLE_END(...) (__VA_ARGS__); }                    \
    ret name##_impl(__VA_ARGS__)

// Simpler version: just declare the function and its hook pointer
#define PATCH_FUNC_HOOKABLE(ret, name, ...)                         \
    ret name##_impl(__VA_ARGS__);                                   \
    ret (*name##_ptr)(__VA_ARGS__) = name##_impl

#else

// Linux: Use patchable_function_entry for direct code patching
#define PATCH_PATCHABLE __attribute__((patchable_function_entry(8, 4)))

#define PATCH_DECLARE_HOOKABLE(ret, name, ...)                      \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__)

#define PATCH_DEFINE_HOOKABLE(ret, name, ...)                       \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__)

// No-op on Linux
#define PATCH_FUNC_HOOKABLE(ret, name, ...)                         \
    PATCH_PATCHABLE __attribute__((noinline)) ret name(__VA_ARGS__)

#endif
