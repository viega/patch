# CLAUDE.md - patch

Project-specific instructions for the function patching library.

See parent `../CLAUDE.md` for version control rules (jj workflow) and general C23 conventions.

## Project Purpose

Runtime function hooking library for x86-64 and ARM64 on Linux (ELF) and macOS (Mach-O).
Enables inserting detours at function prologues and epilogues with argument/return inspection.

Key features:
- **Hook chaining**: Multiple hooks on the same target, executed in reverse installation order
- **Re-entrancy guard**: Prevents infinite recursion when hook code calls the hooked function
- **FFI support**: Optional libffi integration for full argument forwarding (including stack and FP args)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           PUBLIC API                                     │
│  patch_can_install() → patch_install() → patch_enable/disable/remove()  │
│  patch_context_get_arg/set_arg/get_return/set_return()                  │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         UNIFIED MACRO LAYER                              │
│  PATCH_DEFINE_HOOKABLE / PATCH_CALL / PATCH_HOOK_INSTALL/REMOVE         │
│  (Abstracts platform differences: pointer indirection vs code patching) │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────┐
          ▼                         ▼                         ▼
┌─────────────────┐     ┌─────────────────────┐     ┌─────────────────┐
│  PATTERN LAYER  │     │  DISPATCHER LAYER   │     │ TRAMPOLINE LAYER│
│  x86_64_common  │     │  Generated stubs    │     │ Relocated code  │
│  arm64_common   │     │  that call C helper │     │ + jump back     │
│  registry.c     │     │  patch__dispatch_   │     │                 │
└─────────────────┘     │  full()             │     └─────────────────┘
                        └─────────────────────┘
          │                         │                         │
          ▼                         ▼                         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         ARCHITECTURE LAYER                               │
│  arch_decode_insn() - instruction decoding                              │
│  arch_relocate() - fix PC-relative instructions                         │
│  arch_write_jump() - write branch/jump to target                        │
│  arch_min_prologue_size() - minimum patchable size                      │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          PLATFORM LAYER                                  │
│  platform_alloc_near() - allocate executable memory near target         │
│  platform_protect() - change memory protection (RW/RX/RWX)              │
│  platform_write_code() - atomically write to code pages                 │
│  platform_flush_icache() - invalidate instruction cache (ARM64)         │
└─────────────────────────────────────────────────────────────────────────┘
```

## Module Organization

```
patch/
├── include/patch/
│   ├── patch.h           # Public low-level API
│   ├── patch_arch.h      # Architecture detection macros
│   └── patch_hook.h      # Unified macro interface
├── src/
│   ├── patch.c           # Main API implementation
│   ├── patch_internal.h  # Internal declarations
│   ├── trampoline.c      # Trampoline creation/destruction
│   ├── dispatcher.c      # Generated dispatcher stubs
│   ├── arch/
│   │   ├── arch.h        # Architecture interface
│   │   ├── x86_64.c      # x86-64 instruction handling
│   │   └── arm64.c       # ARM64 instruction handling
│   ├── platform/
│   │   ├── platform.h    # Platform interface
│   │   ├── linux.c       # Linux mprotect, /proc/self/maps
│   │   └── darwin.c      # macOS vm_protect, mach_vm_*
│   └── pattern/
│       ├── pattern.h     # Pattern plugin interface
│       ├── registry.c    # Pattern registration/matching
│       ├── x86_64_common.c  # x86-64 prologue patterns
│       └── arm64_common.c   # ARM64 prologue patterns
└── test/
    ├── test_basic.c      # Basic hook/unhook tests
    ├── test_hooks.c      # Low-level API integration tests
    └── test_realworld.c  # Real libc function hooking
```

## Hook Installation Flow

When `patch_install()` is called:

```
1. Pattern Matching (pattern/registry.c)
   ├── Try each registered pattern in priority order
   ├── Pattern examines bytes at target address
   ├── Returns: matched, prologue_size, min_patch_size, has_pc_relative
   └── Fail if no pattern matches

2. Trampoline Creation (trampoline.c)
   ├── Allocate executable memory NEAR target (platform_alloc_near)
   │   └── Critical: must be within branch range (±128MB ARM64, ±2GB x86-64)
   ├── Copy prologue bytes to trampoline
   ├── Relocate PC-relative instructions (arch_relocate)
   │   ├── x86-64: RIP-relative addressing
   │   └── ARM64: ADR, ADRP, B, BL, etc.
   └── Append jump back to (target + prologue_size)

3. Dispatcher Creation (dispatcher.c)
   ├── Allocate executable memory NEAR target
   ├── Generate architecture-specific stub:
   │   ├── Save argument registers
   │   ├── Call patch__dispatch_full(handle, args, trampoline)
   │   └── Return result to caller
   └── Embed pointers: handle, trampoline, dispatch function

4. Detour Installation (trampoline.c:patch__write_detour)
   ├── Build jump instruction to dispatcher
   │   ├── x86-64: JMP rel32 (5 bytes) or MOVABS+JMP (13 bytes)
   │   └── ARM64: B rel26 (4 bytes) or LDR+BR+.quad (16 bytes)
   ├── Make target page writable (platform_write_code)
   ├── Overwrite prologue with jump
   └── Restore page to RX, flush icache
```

## Dispatcher Mechanics

The dispatcher is dynamically generated machine code that bridges between the hooked function and the C callback system.

### ARM64 Dispatcher (src/dispatcher.c)

```asm
; Stack layout: 288 bytes
;   [sp, #0-15]:   x29, x30 (frame/link)
;   [sp, #16-79]:  x0-x7 (integer arguments)
;   [sp, #80-207]: v0-v7 (FP arguments, 128-bit each)
;   [sp, #208-223]: fp_return storage

stp x29, x30, [sp, #-288]!    ; Save frame/link, allocate stack
stp x0, x1, [sp, #16]         ; Save integer arguments
stp x2, x3, [sp, #32]
stp x4, x5, [sp, #48]
stp x6, x7, [sp, #64]
stp q0, q1, [sp, #80]         ; Save FP arguments
stp q2, q3, [sp, #112]
stp q4, q5, [sp, #144]
stp q6, q7, [sp, #176]
mov x29, sp                    ; Set up frame

ldr x0, [pc, #offset_handle]   ; x0 = handle
add x1, sp, #16                ; x1 = pointer to saved int args
add x2, sp, #80                ; x2 = pointer to saved FP args
add x3, sp, #288               ; x3 = caller's stack (for stack args)
ldr x4, [pc, #offset_tramp]    ; x4 = trampoline
add x5, sp, #208               ; x5 = pointer to fp_return
ldr x16, [pc, #offset_func]    ; x16 = patch__dispatch_full
blr x16                        ; Call dispatch helper

ldr q0, [sp, #208]             ; Load FP return value into v0
ldp x29, x30, [sp], #288       ; Restore and deallocate
ret                            ; Return (int in x0, FP in v0)

; Embedded data (8-byte aligned at end):
.quad patch__dispatch_full
.quad handle
.quad trampoline
```

### x86-64 Dispatcher

```asm
push rbp
mov rbp, rsp
sub rsp, 256                   ; Allocate stack

; Save integer arguments at [rbp-48] through [rbp-8]
mov [rbp-48], rdi              ; arg0
mov [rbp-40], rsi              ; arg1
mov [rbp-32], rdx              ; arg2
mov [rbp-24], rcx              ; arg3
mov [rbp-16], r8               ; arg4
mov [rbp-8], r9                ; arg5

; Save FP arguments at [rbp-176] through [rbp-64]
movups [rbp-176], xmm0
movups [rbp-160], xmm1
movups [rbp-144], xmm2
movups [rbp-128], xmm3
movups [rbp-112], xmm4
movups [rbp-96], xmm5
movups [rbp-80], xmm6
movups [rbp-64], xmm7

movabs rdi, handle             ; arg0: handle
lea rsi, [rbp-48]              ; arg1: pointer to saved int args
lea rdx, [rbp-176]             ; arg2: pointer to saved FP args
lea rcx, [rbp+16]              ; arg3: caller's stack
movabs r8, trampoline          ; arg4: trampoline
lea r9, [rbp-192]              ; arg5: pointer to fp_return
movabs rax, patch__dispatch_full
call rax

movups xmm0, [rbp-192]         ; Load FP return value into xmm0
mov rsp, rbp
pop rbp
ret                            ; int result in rax, FP in xmm0
```

### C Dispatch Helper (patch__dispatch_full)

```c
uint64_t patch__dispatch_full(patch_handle_t  *handle,
                              uint64_t        *args,
                              patch__fp_reg_t *fp_args,
                              void            *caller_stack,
                              void            *trampoline,
                              patch__fp_reg_t *fp_return)
{
    // Re-entrancy check: if this hook is already active on this thread,
    // bypass callbacks and call the next in chain directly
    if (is_hook_active(handle)) {
        return call_next_directly(handle, args);
    }

    push_active_hook(handle);

    patch_context_t ctx = {0};
    ctx.handle = handle;
    ctx.caller_stack = caller_stack;
    memcpy(ctx.args, args, sizeof(ctx.args));
    memcpy(ctx.fp_args, fp_args, sizeof(ctx.fp_args));

    // Get next callable in chain (next hook's dispatcher or trampoline)
    void *next_callable = patch__get_chain_next(handle);

    // Prologue callback
    bool call_original = true;
    if (handle->prologue) {
        call_original = handle->prologue(&ctx, handle->prologue_user_data);
        // Copy potentially modified args back
    }

    uint64_t result;
    if (call_original) {
#ifdef PATCH_HAVE_LIBFFI
        if (handle->ffi_cif) {
            // Use FFI for full argument forwarding (int, FP, and stack args)
            ffi_call(handle->ffi_cif, next_callable, &result_or_fp_return, arg_values);
        } else
#endif
        {
            // Direct call with register args only
            result = ((fn_t)next_callable)(args[0], args[1], ...);
        }
    }

    // Epilogue callback
    if (handle->epilogue) {
        handle->epilogue(&ctx, handle->epilogue_user_data);
    }

    pop_active_hook();
    return result;
}
```

## Trampoline Layout

### ARM64

```
+---------------------------+
| Relocated prologue        |  (4-16+ bytes, PC-relative fixed)
+---------------------------+
| B resume_addr             |  (4 bytes, if within ±128MB)
+---------------------------+
   OR
+---------------------------+
| LDR x16, [pc, #8]         |  (4 bytes)
| BR x16                    |  (4 bytes)
| .quad resume_addr         |  (8 bytes)
+---------------------------+
```

### x86-64

```
+---------------------------+
| Relocated prologue        |  (5-15+ bytes, RIP-relative fixed)
+---------------------------+
| JMP rel32                 |  (5 bytes, if within ±2GB)
+---------------------------+
   OR
+---------------------------+
| MOVABS r11, resume_addr   |  (10 bytes)
| JMP r11                   |  (3 bytes)
+---------------------------+
```

## Pattern Recognition

Patterns are registered in priority order (higher = tried first):

### x86-64 Patterns (src/pattern/x86_64_common.c)

| Priority | Name | Description |
|----------|------|-------------|
| 150 | patchable_entry | NOP sled from `patchable_function_entry` attribute |
| 110 | endbr64 | CET-enabled: `endbr64` + prologue |
| 100 | frame_setup | Standard: `push rbp; mov rbp, rsp` |
| 80 | no_frame | Optimized: callee-saved pushes without frame |
| 70 | sub_rsp | Leaf-ish: `sub rsp, imm` only |

**NOP Detection**: Recognizes 1-9 byte x86 NOP encodings:
- `90` (1-byte NOP)
- `66 90` (2-byte)
- `0F 1F 00` (3-byte)
- `0F 1F 40 00` (4-byte)
- `0F 1F 44 00 00` (5-byte)
- `66 0F 1F 44 00 00` (6-byte)
- `0F 1F 80 00 00 00 00` (7-byte)
- `0F 1F 84 00 xx xx xx xx` (8-byte, common clang output)
- `66 0F 1F 84 00 xx xx xx xx` (9-byte)

### ARM64 Patterns (src/pattern/arm64_common.c)

| Priority | Name | Description |
|----------|------|-------------|
| 150 | patchable_entry | NOP sled (≥2 NOPs = 8 bytes) |
| 120 | bti | BTI instruction + prologue |
| 110 | pac | PAC instruction (paciasp/pacibsp) + prologue |
| 100 | frame_setup | Standard: `stp x29, x30, [sp, #-N]!; mov x29, sp` |
| 80 | leaf | Leaf function: `sub sp, sp, #imm` |

**NOP Detection**: ARM64 NOP is exactly `0xD503201F` (4 bytes).

## Instruction Relocation

### x86-64 (src/arch/x86_64.c)

PC-relative instructions that need relocation:
- RIP-relative addressing (ModRM with mod=00, rm=101)
- Relative jumps (JMP rel8/rel32, Jcc)
- Relative calls (CALL rel32)
- LEA with RIP-relative operand

Relocation strategy:
1. Decode instruction to find displacement offset and size
2. Calculate new displacement: `new_disp = old_target - new_location`
3. If displacement doesn't fit, convert to absolute (may expand instruction)

### ARM64 (src/arch/arm64.c)

PC-relative instructions that need relocation:
- `B`, `BL` (±128MB range, 26-bit offset)
- `B.cond`, `CBZ`, `CBNZ` (±1MB range, 19-bit offset)
- `TBZ`, `TBNZ` (±32KB range, 14-bit offset)
- `ADR` (±1MB range, 21-bit offset)
- `ADRP` (±4GB range, 21-bit page offset)
- `LDR` literal (±1MB range, 19-bit offset)

Relocation strategy:
1. Decode instruction to extract target address
2. Calculate offset from new location
3. If offset fits, re-encode with new displacement
4. If offset doesn't fit, convert to absolute sequence:
   - `MOVZ x16, #imm16` + `MOVK x16, #imm16, lsl #16` + ... + `BR x16`

## Platform Memory Management

### Nearby Allocation (platform_alloc_near)

Critical for efficient jumps:
- **x86-64**: Must be within ±2GB for `JMP rel32`
- **ARM64**: Must be within ±128MB for `B` instruction

Strategy:
1. Try strategic hints: just before/after target, then 64KB, 1MB, 16MB, 256MB
2. Use `mmap` with `MAP_FIXED_NOREPLACE` (Linux 4.17+)
3. If hints fail, sparse search with 1MB steps
4. Fallback to anywhere (will require absolute jumps)

### Code Writing (platform_write_code)

**Linux**:
1. `mprotect(page, size, PROT_READ | PROT_WRITE | PROT_EXEC)`
2. `memcpy(target, data, size)`
3. `mprotect(page, size, PROT_READ | PROT_EXEC)` — critical for security
4. `__builtin___clear_cache()` on ARM64

**macOS**:
- Hardware W^X on Apple Silicon prevents runtime code modification
- Unified macro layer uses pointer indirection instead
- `patchable_function_entry` attribute is the only option for code patching

## Unified Macro Interface

The `patch_hook.h` header provides a portable API that abstracts platform differences:

### macOS Implementation

Uses pure function pointer indirection (no code modification):

```c
PATCH_DEFINE_HOOKABLE(int, add, int a, int b)  // Expands to:
int add_impl(int a, int b);                     // Forward declaration
int (*add_ptr)(int a, int b) = add_impl;        // Pointer (initially to impl)
static int (*add__saved_ptr)(int a, int b);     // Saved original pointer
int add_impl(int a, int b) { ... }              // Actual implementation

PATCH_CALL(add, 2, 3)        →  add_ptr(2, 3)
PATCH_HOOK_INSTALL(add, fn)  →  add__saved_ptr = add_ptr; add_ptr = fn;
PATCH_HOOK_REMOVE(add)       →  add_ptr = add__saved_ptr;
PATCH_CALL_ORIGINAL(add, ..) →  add_impl(...)
```

### Linux Implementation

Supports both pointer indirection and code patching:

```c
PATCH_DEFINE_HOOKABLE(int, add, int a, int b)  // Expands to:
__attribute__((patchable_function_entry(N,M)))
__attribute__((noinline))
int add(int a, int b);                          // With NOP sled
int (*add_ptr)(int a, int b) = add;             // Pointer
static patch_handle_t *add__patch_handle;       // For code patching
int add(int a, int b) { ... }                   // Implementation with NOPs

PATCH_CALL(add, 2, 3)  →  add_ptr(2, 3)
```

### patchable_function_entry Attribute

Architecture-specific NOP sled sizes:
- **x86-64**: `patchable_function_entry(16, 8)` = 8 NOPs at entry (enough for JMP rel32)
- **ARM64**: `patchable_function_entry(4, 2)` = 2 NOPs at entry (8 bytes)

## Build

### Native (macOS)

```bash
CC=/usr/local/bin/clang meson setup build
meson compile -C build
meson test -C build
```

### Docker (Linux, multi-arch)

```bash
./scripts/test-docker.sh          # Both architectures
./scripts/test-docker.sh arm64    # ARM64 only
./scripts/test-docker.sh amd64    # x86-64 only
```

## Error Handling

Error codes (`patch_error_t`):
- `PATCH_SUCCESS` (0) — Operation succeeded
- `PATCH_ERR_INVALID_ARGUMENT` — Null pointer or invalid config
- `PATCH_ERR_PATTERN_UNRECOGNIZED` — No pattern matched (graceful, not fatal)
- `PATCH_ERR_INSUFFICIENT_SPACE` — Prologue too small for detour
- `PATCH_ERR_MEMORY_PROTECTION` — mprotect/vm_protect failed
- `PATCH_ERR_ALLOCATION_FAILED` — Could not allocate executable memory
- `PATCH_ERR_INTERNAL` — Unexpected internal error

Thread-local error details: `patch_get_error_details()` returns detailed message.

## Hook Chaining

Multiple hooks can be installed on the same target function. Hooks are executed in reverse installation order (most recent first).

```c
// Install first hook
patch_install(&config_A, &handle_A);  // Will be called second

// Install second hook on same target
patch_install(&config_B, &handle_B);  // Will be called first

// Call flow: target → B's dispatcher → A's dispatcher → trampoline → original
```

The chain is maintained via `chain_next` and `chain_prev` pointers in each handle. When a hook is removed from the middle of a chain, the detour is updated to point to the next hook.

## Re-entrancy Guard

A thread-local linked list tracks active hooks to prevent infinite recursion:

```c
bool my_prologue(patch_context_t *ctx, void *user_data) {
    // If this hook calls the hooked function, the dispatcher detects
    // re-entrancy and bypasses callbacks, calling the next in chain directly
    some_function_that_might_call_target();
    return true;
}
```

## FFI Support (Optional)

When built with libffi (`-Duse_libffi=true`), full argument forwarding is available:

```c
// Function with 9 arguments (some on stack)
int func(int a, int b, int c, int d, int e, int f, int g, int h, int i);

ffi_type *arg_types[] = {
    &ffi_type_sint, &ffi_type_sint, &ffi_type_sint,
    &ffi_type_sint, &ffi_type_sint, &ffi_type_sint,
    &ffi_type_sint, &ffi_type_sint, &ffi_type_sint,
};

patch_config_t config = {
    .target = (void *)func,
    .prologue = my_prologue,
    .arg_types = arg_types,
    .arg_count = 9,
    .return_type = &ffi_type_sint,
};
```

Without FFI, only register arguments are forwarded:
- **x86-64**: 6 integer (rdi, rsi, rdx, rcx, r8, r9) + 8 FP (xmm0-7)
- **ARM64**: 8 integer (x0-x7) + 8 FP (v0-v7)

With FFI, all arguments including stack-passed and floating-point are correctly forwarded.

## Symbol-Based Hooking

Functions can be hooked by symbol name without needing to know their address:

```c
// Resolve a symbol to an address
void *addr;
patch_resolve_symbol("malloc", NULL, &addr);  // From current process
patch_resolve_symbol("SSL_read", "libssl.so", &addr);  // From specific library

// Install hook by symbol name (combines resolve + install)
patch_config_t config = { .prologue = my_prologue };
patch_handle_t *handle;
patch_install_symbol("atoi", NULL, &config, &handle);
```

The library parameter can be:
- `NULL` — Search all loaded libraries (uses RTLD_DEFAULT)
- Library path — Load and search that specific library

## GOT/PLT Hooking

For imported functions, GOT (Global Offset Table) hooking is available as an alternative to code patching:

```c
// Force GOT hooking
patch_config_t config = {
    .replacement = my_malloc,
    .method = PATCH_METHOD_GOT,
};
patch_install_symbol("malloc", NULL, &config, &handle);

// AUTO mode (default): tries GOT first, falls back to code patching
patch_config_t config = {
    .replacement = my_func,
    .method = PATCH_METHOD_AUTO,
};
```

**Method selection:**
- `PATCH_METHOD_AUTO` — Try GOT first, fall back to code patching (default)
- `PATCH_METHOD_GOT` — Force GOT hooking, fail if no GOT entry
- `PATCH_METHOD_CODE` — Force code patching

**GOT hooking advantages:**
- No instruction decoding or relocation needed
- Works on any imported function (no prologue pattern matching)
- Simpler and more reliable for external functions

**GOT hooking limitations:**
- Only works for imported functions (calls through PLT)
- Does not support prologue/epilogue callbacks (replacement only)
- Per-module (each shared object has its own GOT)

## Hot-Swap Hooks

Callbacks can be changed while a hook is active without removing and reinstalling:

```c
// Install hook with initial callbacks
patch_config_t config = {
    .target = (void *)func,
    .prologue = prologue_v1,
    .epilogue = epilogue_v1,
};
patch_install(&config, &handle);

// Later, swap to new callbacks without reinstalling
patch_set_prologue(handle, prologue_v2, user_data);
patch_set_epilogue(handle, epilogue_v2, user_data);

// Or swap both atomically
patch_set_callbacks(handle, prologue_v2, p_data, epilogue_v2, e_data);

// For GOT hooks, swap the replacement function
patch_set_replacement(handle, new_replacement);
```

**Hot-swap API:**
- `patch_set_prologue(handle, prologue, user_data)` — Replace prologue callback
- `patch_set_epilogue(handle, epilogue, user_data)` — Replace epilogue callback
- `patch_set_callbacks(handle, prologue, p_data, epilogue, e_data)` — Replace both
- `patch_set_replacement(handle, replacement)` — Replace GOT hook target (GOT hooks only)

Setting a callback to `NULL` disables that callback without removing the hook.

**Thread safety:** Updates are performed using atomic stores, so no calls will see partially updated state. However, there is no synchronization guarantee about which callback a concurrent call will use.

## Code Style

- Public symbols: `patch_` prefix
- Internal symbols: `patch__` prefix (double underscore)
- Pattern handlers: `pattern_<arch>_<variant>`
- Platform functions: `platform_<action>()`
- Architecture functions: `arch_<action>()`
