# CLAUDE.md - patch

Project-specific instructions for the function patching library.

See parent `../CLAUDE.md` for version control rules (jj workflow) and general C23 conventions.

## Project Purpose

Runtime function hooking library for x86-64 and ARM64 on Linux (ELF) and macOS (Mach-O).
Enables inserting detours at function prologues and epilogues with argument/return inspection.

## Architecture

### Module Organization

- `include/patch/` - Public headers only
- `src/` - Core implementation
- `src/arch/` - Architecture-specific code (x86_64.c, arm64.c)
- `src/platform/` - OS-specific code (linux.c, darwin.c)
- `src/pattern/` - Prologue/epilogue pattern matchers
- `test/` - Unit tests

### Key Design Decisions

1. **Pattern plugins**: Prologue recognition is modular. Each pattern handler has:
   - `match()` function that returns match details
   - Priority for ordering (higher = try first)
   - Auto-registration via constructor attribute

2. **Graceful failure**: `patch_can_install()` tests without modifying.
   `PATCH_ERR_PATTERN_UNRECOGNIZED` is not fatal - caller decides how to proceed.

3. **Trampoline-based**: Original function bytes are relocated to a trampoline,
   allowing the original to be called from within hooks.

4. **Thread-safe patching**: Uses atomic writes where possible (8-byte aligned on x86-64).

## Build

### Native (macOS)

```bash
CC=/usr/local/bin/clang meson setup build
meson compile -C build
meson test -C build
```

### Docker (Linux, multi-arch)

Test on Linux containers for both x86-64 and ARM64:

```bash
# Test both architectures
./scripts/test-docker.sh

# Test specific architecture
./scripts/test-docker.sh arm64
./scripts/test-docker.sh amd64

# Interactive shell for debugging
docker compose run --rm shell
```

## Adding New Patterns

1. Create `src/pattern/<arch>_<compiler>.c`
2. Define a `pattern_handler_t` with match function
3. Register via `__attribute__((constructor))` or explicit init

Example:
```c
static bool
match_gcc_o0(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    // Check for: push rbp; mov rbp, rsp; sub rsp, N
    if (avail < 8) return false;
    if (code[0] != 0x55) return false;  // push rbp
    // ... more checks
    out->matched = true;
    out->pattern_name = "gcc_o0_x86_64";
    out->prologue_size = offset;
    return true;
}

static pattern_handler_t handler = {
    .name = "gcc_o0_x86_64",
    .priority = 90,
    .match = match_gcc_o0,
};

__attribute__((constructor))
static void register_pattern(void) {
    pattern_register(&handler);
}
```

## Testing Patterns

Compile test functions at various optimization levels and verify matching:

```bash
# Create test functions at different -O levels
/usr/local/bin/clang -O0 -c test_funcs.c -o test_o0.o
/usr/local/bin/clang -O2 -c test_funcs.c -o test_o2.o

# Disassemble to see actual prologues
objdump -d test_o0.o | head -30
```

## Platform Notes

### macOS (Darwin)
- Use `vm_protect()` for memory protection changes
- Use `sys_icache_invalidate()` for ARM64 icache flush
- **CRITICAL**: Apple Silicon enforces hardware W^X - you cannot make code pages writable
- Runtime patching of signed code is not supported on macOS ARM64
- **Recommended approach**: Use `__attribute__((patchable_function_entry(N)))` on functions you control

### Linux
- Use `mprotect()` for memory protection
- Use `__builtin___clear_cache()` for ARM64 icache flush
- Check `/proc/self/maps` for current page protections
- Full runtime patching support on both x86-64 and ARM64

## Patchable Functions

For portable patching that works on all platforms, use the patchable function entry attribute:

```c
// Insert 8 NOPs: 4 before entry, 4 at entry point
#define PATCHABLE __attribute__((patchable_function_entry(8, 4)))

PATCHABLE int my_function(int x) {
    return x * 2;
}
```

This approach:
- Works on Linux and macOS (x86-64 and ARM64)
- Provides safe NOP sled that can be overwritten
- Is the only reliable method on macOS ARM64
- Has highest pattern matching priority

## Code Style

- All public symbols: `patch_` prefix
- Internal symbols: `patch__` prefix (double underscore)
- Pattern handlers: `pattern_<arch>_<compiler>_<opt>`
- Platform functions: `platform_<action>()`
- Architecture functions: `arch_<action>()`

## Error Handling

- Return `patch_error_t` from all fallible operations
- Set detailed error message via internal `set_error_details()`
- Caller retrieves with `patch_get_error_details()`
- Never abort/assert on user input - return errors gracefully

## Assembly Style

When writing inline assembly:
- Use Intel syntax with `.intel_syntax noprefix`
- Clearly document register usage
- Preserve all callee-saved registers
- Account for red zone on x86-64 System V ABI
