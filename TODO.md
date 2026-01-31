# Patch Library TODO

## Improvements to Existing Functionality

- [ ] **Struct return values** - Support functions that return structs by value (currently only scalar/pointer returns work)

- [ ] **Variadic function support** - Handle `printf`-style functions properly

- [ ] **More prologue patterns** - Add recognition for:
  - Functions with stack canaries (`__stack_chk_guard`)
  - Position-independent code patterns
  - Compiler-specific prologues (MSVC, ICC)

- [ ] **Instruction relocation coverage** - Handle more PC-relative instructions (currently some edge cases may fail)

## New Features

- [x] **PLT/GOT hooking** - Hook imported functions via the PLT/GOT tables (simpler than code patching, works on more targets)

- [ ] **Batch hook API** - `patch_install_batch()` to atomically install multiple hooks

- [ ] **Hook statistics** - Optional call counting, timing, argument logging

- [ ] **Conditional hooks** - Only trigger callback when arguments match a predicate

- [x] **Hot-swap hooks** - Replace a hook's callbacks without remove/reinstall cycle

- [x] **Watchpoint-guarded pointer hooks** - Hook function pointers (vtables, callbacks, GOT entries) with hardware watchpoint protection. When the program updates the pointer, automatically reinstall the detour and cache the new original. Uses debug registers (DR0-DR3 on x86-64, DBGWVR on ARM64). Returns error when watchpoints exhausted (no slow fallback).

- [x] **vtable hooking** - Subsumed by watchpoint-guarded pointer hooks

- [x] **GitHub Actions CI** - Add workflow for automated testing on Linux (x86-64 and ARM64) with hardware watchpoint support via `sysctl kernel.perf_event_paranoid=-1`

- [ ] **Hook discovery** - Detect if a function is already hooked by another library

- [ ] **Serializable configurations** - Save/load hook configs to JSON/binary
