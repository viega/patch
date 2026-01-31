# patch - Runtime Function Hooking Library

A C23 library for runtime function hooking on x86-64 and ARM64, supporting Linux and macOS.

## Features

- **Simple replacement**: Direct function replacement with trampoline access
- **Prologue/epilogue callbacks**: Advanced hooks with argument and return value inspection
- **Unified macro interface**: Portable hooking that works across platforms
- **Pattern recognition**: Automatic detection of compiler-generated prologues
- **Patchable function entry**: Full support for `__attribute__((patchable_function_entry))`

## Quick Start

### Using the Macro Interface (Recommended)

The easiest way to use the library is through the unified macro interface:

```c
#include "patch/patch_hook.h"

// 1. Define a hookable function
PATCH_DEFINE_HOOKABLE(int, add, int a, int b) {
    return a + b;
}

// 2. Write a hook with the same signature
int my_hook(int a, int b) {
    printf("add(%d, %d) called\n", a, b);
    return PATCH_CALL_ORIGINAL(add, a, b) + 100;
}

int main(void) {
    // 3. Call the function normally
    int result = PATCH_CALL(add, 2, 3);  // returns 5

    // 4. Install the hook
    PATCH_HOOK_INSTALL(add, my_hook);

    // 5. Calls now go through the hook
    result = PATCH_CALL(add, 2, 3);  // prints "add(2, 3) called", returns 105

    // 6. Remove when done
    PATCH_HOOK_REMOVE(add);

    return 0;
}
```

### Hook Methods (Linux)

On Linux, you can choose between pointer indirection and code patching:

```c
// Pointer indirection (default, like macOS)
PATCH_HOOK_INSTALL(add, my_hook, PATCH_METHOD_POINTER);

// Code patching via NOP sled (more powerful)
PATCH_HOOK_INSTALL(add, my_hook, PATCH_METHOD_CODE);
```

## Low-Level API

For more control, use the low-level API directly.

### Simple Replacement Mode

Replace a function directly, with access to the original via trampoline:

```c
#include "patch/patch.h"

static patch_handle_t *g_handle = NULL;

int my_replacement(int a, int b) {
    // Get the original function via trampoline
    typedef int (*orig_fn)(int, int);
    orig_fn original = (orig_fn)patch_get_trampoline(g_handle);

    // Call original and modify result
    return original(a, b) + 100;
}

int main(void) {
    patch_config_t config = {
        .target = (void *)add,
        .replacement = (void *)my_replacement,
    };

    patch_error_t err = patch_install(&config, &g_handle);
    if (err != PATCH_SUCCESS) {
        fprintf(stderr, "Failed: %s\n", patch_get_error_details());
        return 1;
    }

    add(2, 3);  // Calls my_replacement, which calls original

    patch_remove(g_handle);
    return 0;
}
```

### Callback Mode

For argument inspection and modification, use prologue/epilogue callbacks:

```c
bool my_prologue(patch_context_t *ctx, void *user_data) {
    // Inspect arguments
    int *arg0 = (int *)patch_context_get_arg(ctx, 0);
    printf("First argument: %d\n", *arg0);

    // Modify arguments
    int new_value = *arg0 * 2;
    patch_context_set_arg(ctx, 0, &new_value, sizeof(new_value));

    // Return true to call original, false to skip it
    return true;
}

void my_epilogue(patch_context_t *ctx, void *user_data) {
    // Inspect return value
    int *result = (int *)patch_context_get_return(ctx);
    printf("Returned: %d\n", *result);

    // Modify return value
    int new_result = *result + 1000;
    patch_context_set_return(ctx, &new_result, sizeof(new_result));
}

int main(void) {
    patch_config_t config = {
        .target = (void *)my_function,
        .prologue = my_prologue,
        .epilogue = my_epilogue,
        .prologue_user_data = NULL,
        .epilogue_user_data = NULL,
    };

    patch_handle_t *handle;
    patch_install(&config, &handle);

    my_function(42);  // Callbacks are invoked

    patch_remove(handle);
    return 0;
}
```

## Platform Notes

### Linux

Full support for runtime patching via code modification. Both pointer indirection and code patching are available.

### macOS

Due to hardware W^X (write XOR execute) enforcement on Apple Silicon, **runtime code modification is not supported**. The library automatically uses pointer indirection via the unified macro interface.

For hooking:
1. Use `PATCH_DEFINE_HOOKABLE` to create hookable functions
2. Use `PATCH_HOOK_INSTALL/REMOVE` for hook management
3. Calls must go through `PATCH_CALL()` for hooks to work

## Building

Requires Clang 18+ with C23 support:

```bash
# macOS
CC=/usr/local/bin/clang meson setup build
meson compile -C build
meson test -C build

# Linux (Docker)
./scripts/test-docker.sh
```

## API Reference

### Unified Macro Interface

| Macro | Description |
|-------|-------------|
| `PATCH_DEFINE_HOOKABLE(ret, name, ...)` | Define a hookable function |
| `PATCH_DECLARE_HOOKABLE(ret, name, ...)` | Declare (for headers) |
| `PATCH_CALL(name, ...)` | Call a hookable function |
| `PATCH_CALL_ORIGINAL(name, ...)` | Call original from within hook |
| `PATCH_HOOK_ORIGINAL(name)` | Get original function pointer |
| `PATCH_HOOK_INSTALL(name, hook [, method])` | Install a hook |
| `PATCH_HOOK_REMOVE(name)` | Remove a hook |
| `PATCH_HOOK_IS_INSTALLED(name)` | Check if hooked |

### Core Functions

| Function | Description |
|----------|-------------|
| `patch_can_install(target)` | Check if function can be hooked |
| `patch_install(config, &handle)` | Install hook |
| `patch_remove(handle)` | Remove hook and free resources |
| `patch_disable(handle)` | Temporarily disable hook |
| `patch_enable(handle)` | Re-enable disabled hook |
| `patch_get_trampoline(handle)` | Get callable original function |
| `patch_get_error_details()` | Get human-readable error message |

### Configuration Structure

```c
typedef struct {
    void *target;              // Function to hook

    // Simple replacement mode (mutually exclusive with callbacks)
    void *replacement;         // Direct replacement function

    // Callback mode (mutually exclusive with replacement)
    patch_prologue_fn prologue;     // Called before original
    patch_epilogue_fn epilogue;     // Called after original
    void *prologue_user_data;
    void *epilogue_user_data;

#ifdef PATCH_HAVE_LIBFFI
    // Optional: FFI type info for full argument forwarding
    ffi_type **arg_types;      // Array of argument types
    ffi_type  *return_type;    // Return type (default: ffi_type_uint64)
    size_t     arg_count;      // Number of arguments
#endif
} patch_config_t;
```

### Context Functions (for callbacks)

| Function | Description |
|----------|-------------|
| `patch_context_get_arg(ctx, index)` | Get argument pointer |
| `patch_context_set_arg(ctx, index, value, size)` | Modify argument |
| `patch_context_get_return(ctx)` | Get return value pointer |
| `patch_context_set_return(ctx, value, size)` | Set return value |
| `patch_context_get_original(ctx)` | Get trampoline to original |

### Error Codes

| Code | Description |
|------|-------------|
| `PATCH_SUCCESS` | Operation succeeded |
| `PATCH_ERR_PATTERN_UNRECOGNIZED` | Prologue not recognized |
| `PATCH_ERR_INSUFFICIENT_SPACE` | Prologue too small |
| `PATCH_ERR_MEMORY_PROTECTION` | Cannot modify memory |
| `PATCH_ERR_ALLOCATION_FAILED` | Out of memory |
| `PATCH_ERR_INVALID_ARGUMENT` | NULL or invalid parameter |
| `PATCH_ERR_INTERNAL` | Library bug |

## Recognized Prologue Patterns

### x86-64

| Pattern | Description |
|---------|-------------|
| Patchable entry | NOP sled from `patchable_function_entry` |
| ENDBR64 | CET-enabled functions |
| Frame setup | `push rbp; mov rbp, rsp` |
| No-frame | Optimized with callee-saved pushes |
| Sub RSP | Leaf functions with stack allocation |

### ARM64

| Pattern | Description |
|---------|-------------|
| Patchable entry | NOP sled (2+ NOPs) |
| BTI | Branch target identification |
| PAC | Pointer authentication (`paciasp`) |
| Frame setup | `stp x29, x30, [sp, #-N]!` |
| Leaf | `sub sp, sp, #N` |

## Architecture

```
patch/
├── include/patch/
│   ├── patch.h           # Low-level API
│   ├── patch_arch.h      # Architecture detection
│   └── patch_hook.h      # Unified macro interface
├── src/
│   ├── patch.c           # Core implementation
│   ├── trampoline.c      # Original function relocation
│   ├── dispatcher.c      # Callback dispatch stubs
│   ├── arch/             # x86_64.c, arm64.c
│   ├── platform/         # darwin.c, linux.c
│   └── pattern/          # Pattern registration
└── test/
    ├── test_basic.c
    ├── test_hooks.c
    ├── test_realworld.c
    ├── test_comprehensive.c
    └── TESTING.md
```

## Optional libffi Support

When libffi is available, you can enable full argument forwarding for functions with:
- **Floating-point arguments** (float, double)
- **Stack arguments** (beyond register count: 6 on x86-64, 8 on ARM64)
- **Mixed int/FP arguments**

### Building with libffi

```bash
# Auto-detect (enabled if found)
meson setup build

# Require libffi
meson setup build -Duse_libffi=true
```

### Usage

```c
#include "patch/patch.h"

// Function: double compute(int n, double x, double y, ..., double z)  // 9 args
bool my_prologue(patch_context_t *ctx, void *ud) {
    // Inspect all arguments including FP and stack args
    return true;  // Call original - FFI forwards all args correctly
}

#ifdef PATCH_HAVE_LIBFFI
ffi_type *arg_types[] = {
    &ffi_type_sint, &ffi_type_double, &ffi_type_double,
    &ffi_type_double, &ffi_type_double, &ffi_type_double,
    &ffi_type_double, &ffi_type_double, &ffi_type_double,
};

patch_config_t config = {
    .target = (void *)compute,
    .prologue = my_prologue,
    .arg_types = arg_types,
    .arg_count = 9,
    .return_type = &ffi_type_double,
};
#endif
```

Without libffi, only register arguments are forwarded when the prologue returns `true`.

## Thread Safety

The library provides the following thread-safety guarantees:

- **Install/remove/enable/disable**: These operations are serialized with a global mutex, making them safe to call from multiple threads concurrently.
- **Concurrent hook execution**: Multiple threads can execute through the same hook simultaneously.
- **Limitation**: Removing a hook while another thread is executing through it is NOT safe. Ensure no threads are calling the hooked function before removing it, or use appropriate synchronization in your code.

## Limitations

- **macOS code patching**: Not available due to hardware restrictions
- **FP/stack args without libffi**: Only register arguments forwarded to original
- **Use-after-remove**: Calling a function while its hook is being removed is undefined behavior

## License

MIT License - see LICENSE file.
