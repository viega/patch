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

- [ ] **PLT/GOT hooking** - Hook imported functions via the PLT/GOT tables (simpler than code patching, works on more targets)

- [ ] **Batch hook API** - `patch_install_batch()` to atomically install multiple hooks

- [ ] **Hook statistics** - Optional call counting, timing, argument logging

- [ ] **Conditional hooks** - Only trigger callback when arguments match a predicate

- [ ] **Hot-swap hooks** - Replace a hook's callbacks without remove/reinstall cycle

- [ ] **vtable hooking** - Hook C++ virtual methods by patching vtables

- [ ] **Hook discovery** - Detect if a function is already hooked by another library

- [ ] **Serializable configurations** - Save/load hook configs to JSON/binary
