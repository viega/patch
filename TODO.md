# Patch Library TODO

## Improvements to Existing Functionality

- [ ] **Struct return values** - Support functions that return structs by value (currently only scalar/pointer returns work)

- [ ] **Variadic function support** - Handle `printf`-style functions properly

- [x] **More prologue patterns** - Added recognition for:
  - [x] ARM64: frame_setup_alt, preindex_callee, null_check, no_frame_pointer
  - [x] Functions with stack canaries work (canary setup is AFTER standard prologue)
  - [ ] Position-independent code patterns (if needed)
  - [ ] Compiler-specific prologues (MSVC, ICC)

- [ ] **Shadow call stack compatibility** (`-fsanitize=shadow-call-stack` on ARM64) - Investigate interaction with hooking:
  - Uses x18 register for shadow stack pointer
  - May interfere with hook trampolines
  - Currently only supported on Linux ARM64

- [ ] **Instruction relocation coverage** - Handle more PC-relative instructions (currently some edge cases may fail)

## New Features

- [x] **PLT/GOT hooking** - Hook imported functions via the PLT/GOT tables (simpler than code patching, works on more targets)

- [ ] **Batch hook API** - `patch_install_batch()` to atomically install multiple hooks

- [ ] **Hook statistics** - Optional call counting, timing, argument logging

- [ ] **Conditional hooks** - Only trigger callback when arguments match a predicate

- [x] **Hot-swap hooks** - Replace a hook's callbacks without remove/reinstall cycle

- [x] **Watchpoint-guarded pointer hooks** - Hook function pointers (vtables, callbacks, GOT entries) with hardware watchpoint protection. When the program updates the pointer, automatically reinstall the detour and cache the new original. Uses debug registers (DR0-DR3 on x86-64, DBGWVR on ARM64). Returns error when watchpoints exhausted (no slow fallback).

- [x] **vtable hooking** - Subsumed by watchpoint-guarded pointer hooks

- [x] **GitHub Actions CI** - Automated testing on Linux x86-64, Linux ARM64, macOS ARM64, and Docker
  - **Note:** Hardware watchpoints may not work on GitHub-hosted runners due to Azure kernel restrictions on `perf_event_open`. See [issue #4974](https://github.com/actions/runner-images/issues/4974).
  - For full hardware watchpoint testing, use a self-hosted runner with label `perf` and `kernel.perf_event_paranoid=-1`
  - Core functionality (code patching, GOT hooking, breakpoint hooks) works on all runners

- [ ] **Hook discovery** - Detect if a function is already hooked by another library

- [ ] **Serializable configurations** - Save/load hook configs to JSON/binary
