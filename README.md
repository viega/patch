# patch - Runtime Function Hooking Library

A C23 library for runtime function hooking on x86-64 and ARM64, supporting ELF (Linux) and Mach-O (macOS).

## Features

- **Prologue detours**: Hook function entry points with argument inspection
- **Epilogue detours**: Hook function returns with return value modification (planned)
- **Pattern recognition**: Automatic detection of compiler-generated prologues
- **Patchable function entry**: Full support for `__attribute__((patchable_function_entry))`
- **Cross-platform**: Linux and macOS support
- **Cross-architecture**: x86-64 and ARM64

## Platform Notes

### Linux
Full support for runtime patching. Functions can be hooked regardless of how they were compiled, as long as the prologue pattern is recognized.

### macOS
Due to hardware W^X (write XOR execute) enforcement on Apple Silicon and code signing requirements, **runtime patching of arbitrary code is not supported**.

**Recommended approach on macOS:**
1. Use `__attribute__((patchable_function_entry(N)))` on functions you want to hook
2. This inserts NOP instructions that can be safely overwritten
3. Even with this, you need appropriate entitlements for hardened runtime

For dynamic libraries, consider using interposition or DYLD_INSERT_LIBRARIES instead.

## Building

Requires Clang 22+ with C23 support:

```bash
CC=/usr/local/bin/clang meson setup build
meson compile -C build
meson test -C build
```

## Usage

### Making Functions Patchable

For reliable hooking, mark target functions with the patchable attribute:

```c
#define PATCHABLE __attribute__((patchable_function_entry(8, 4)))

PATCHABLE int my_function(int x) {
    return x * 2;
}
```

This inserts 8 NOP instructions (4 before entry, 4 at entry), providing safe space for the hook.

### Installing a Hook

```c
#include <patch/patch.h>

bool my_prologue(patch_context_t *ctx, void *user_data) {
    // Called before original function runs
    // Return true to proceed, false to skip original
    return true;
}

int main(void) {
    // Check if function can be hooked
    if (patch_can_install((void *)my_function) != PATCH_SUCCESS) {
        fprintf(stderr, "Cannot hook: %s\n", patch_get_error_details());
        return 1;
    }

    // Install hook
    patch_config_t config = {
        .target = (void *)my_function,
        .prologue = my_prologue,
    };

    patch_handle_t *handle;
    patch_error_t err = patch_install(&config, &handle);
    if (err != PATCH_SUCCESS) {
        fprintf(stderr, "Install failed: %s\n", patch_get_error_details());
        return 1;
    }

    // Call hooked function
    my_function(42);

    // Remove hook when done
    patch_remove(handle);
    return 0;
}
```

### Calling Original Function

From within a hook callback, get the trampoline to call the original:

```c
bool my_prologue(patch_context_t *ctx, void *user_data) {
    // Get original function
    int (*original)(int) = patch_context_get_original(ctx);

    // Call it
    int result = original(42);

    return true;  // Still run the normal path
}
```

## API Reference

### Error Codes

```c
typedef enum {
    PATCH_SUCCESS = 0,
    PATCH_ERR_PATTERN_UNRECOGNIZED,   // Prologue not matched
    PATCH_ERR_EPILOGUE_UNRECOGNIZED,  // Epilogue not matched
    PATCH_ERR_INSUFFICIENT_SPACE,     // Not enough bytes for patch
    PATCH_ERR_MEMORY_PROTECTION,      // mprotect/vm_protect failed
    PATCH_ERR_ALLOCATION_FAILED,
    PATCH_ERR_ALREADY_PATCHED,
    PATCH_ERR_NOT_PATCHED,
    PATCH_ERR_UNSUPPORTED_ARCH,
    PATCH_ERR_INVALID_ARGUMENT,
    PATCH_ERR_INTERNAL,
} patch_error_t;
```

### Core Functions

| Function | Description |
|----------|-------------|
| `patch_can_install(target)` | Check if function can be hooked |
| `patch_install(config, &handle)` | Install hook |
| `patch_remove(handle)` | Remove hook and free resources |
| `patch_disable(handle)` | Temporarily disable hook |
| `patch_enable(handle)` | Re-enable disabled hook |
| `patch_get_error_details()` | Get human-readable error message |

### Context Functions (for callbacks)

| Function | Description |
|----------|-------------|
| `patch_context_get_arg(ctx, index)` | Get argument pointer |
| `patch_context_set_arg(ctx, index, value, size)` | Modify argument |
| `patch_context_get_return(ctx)` | Get return value pointer |
| `patch_context_set_return(ctx, value, size)` | Set return value |
| `patch_context_get_original(ctx)` | Get trampoline to original |

## Recognized Patterns

### x86-64

- **Frame setup**: `push rbp; mov rbp, rsp; [sub rsp, N]`
- **ENDBR64**: CET-enabled prologues
- **No-frame**: Optimized code with callee-saved pushes
- **Patchable entry**: NOP sleds from `patchable_function_entry`

### ARM64

- **Frame setup**: `stp x29, x30, [sp, #-N]!; mov x29, sp`
- **PAC**: Pointer-authenticated prologues (`paciasp`/`pacibsp`)
- **BTI**: Branch target identification prologues
- **Leaf**: Functions starting with `sub sp, sp, #N`
- **Patchable entry**: NOP sleds from `patchable_function_entry`

## Architecture

```
patch/
├── include/patch/       # Public headers
├── src/
│   ├── arch/           # x86_64.c, arm64.c
│   ├── platform/       # darwin.c, linux.c
│   └── pattern/        # Prologue pattern matchers
└── test/
```

## License

MIT License - see LICENSE file.
