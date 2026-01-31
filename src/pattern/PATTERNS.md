# Prologue Pattern Recognition

This document describes the function prologue patterns recognized by the patch library,
including the source/rationale for each pattern and why it won't cause false positives.

## Overview

Function prologue recognition is critical for safe code patching. We must:
1. Identify a safe "clobber zone" at the function start that can be overwritten
2. Ensure the clobbered instructions can be relocated to a trampoline
3. Avoid false positives that would corrupt non-prologue code

False positives are dangerous because they could:
- Corrupt data that happens to look like instructions
- Overwrite branch targets within a function
- Break functions that don't follow standard calling conventions

## ARM64 Patterns

### arm64_patchable_entry (Priority: 150)
**Source:** GCC/Clang `__attribute__((patchable_function_entry(N)))` or `-fpatchable-function-entry=N`

**Pattern:** Two or more consecutive NOP instructions (0xD503201F)

**Why safe:** This attribute explicitly marks functions as patchable by inserting NOPs.
The NOPs have no semantic meaning and exist solely for patching. Requiring ≥2 NOPs (8 bytes)
distinguishes intentional patchable entries from incidental alignment NOPs.

**Reference:**
- GCC: https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html
- LLVM: https://clang.llvm.org/docs/AttributeReference.html#patchable-function-entry

---

### arm64_bti_prologue (Priority: 120)
**Source:** ARM Branch Target Identification (BTI) for Control Flow Integrity

**Pattern:** BTI instruction followed by standard prologue
```
bti c/j/jc    ; 0xD503241F, 0xD503245F, 0xD503249F, 0xD50324DF
<prologue>    ; pac/frame_setup patterns
```

**Why safe:** BTI instructions are landing pads required by -mbranch-protection=standard.
They MUST appear at valid branch targets, making them reliable function entry markers.
We require a valid prologue to follow, preventing false matches on BTI within functions.

**Reference:** ARM Architecture Reference Manual, FEAT_BTI

---

### arm64_pac_frame (Priority: 110)
**Source:** ARM Pointer Authentication Code for return address protection

**Pattern:** PACIASP/PACIBSP followed by frame setup
```
paciasp/pacibsp  ; 0xD503233F or 0xD503237F
stp x29, x30, [sp, #-N]!
mov x29, sp      ; optional
```

**Why safe:** PAC instructions sign the return address and appear at function entry.
Combined with the frame setup requirement, this is highly specific to function prologues.

**Reference:** ARM Architecture Reference Manual, FEAT_PAuth

---

### arm64_frame_setup (Priority: 100)
**Source:** ARM64 Procedure Call Standard (AAPCS64)

**Pattern:** Standard frame pointer setup
```
stp x29, x30, [sp, #-N]!  ; Save frame pointer and link register, pre-decrement
mov x29, sp               ; Optional: set up frame pointer
stp x19, x20, [sp, #off]  ; Optional: save callee-saved registers
sub sp, sp, #M            ; Optional: allocate local variables
```

**Why safe:** This is the canonical ARM64 prologue. The pre-indexed STP with x29+x30
to sp is extremely specific - it's the standard way to save the frame pointer and
return address. Non-prologue code wouldn't use this exact pattern.

**False positive risk:** Very low. The combination of:
- Pre-indexed store (specific addressing mode)
- Both x29 AND x30 (specific registers)
- Base register sp (specific register)
makes accidental matches nearly impossible.

**Reference:**
- ARM AAPCS64: https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst
- Apple ARM64 ABI: https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms

---

### arm64_frame_setup_alt (Priority: 95) [NEW]
**Source:** Observed in glibc, macOS libSystem for functions with large stack frames

**Pattern:** Alternative frame setup with explicit SUB then STP at offset
```
sub sp, sp, #N            ; Allocate stack space first
[stp xA, xB, [sp, #off1]] ; Optional: callee-saved registers before fp
...
stp x29, x30, [sp, #off]  ; Save frame pointer and link register at offset
add x29, sp, #off         ; Set up frame pointer
```

**Why safe:** This is a valid alternative to pre-indexed STP used when the stack
frame is larger than the immediate range of pre-indexed addressing (±512 bytes).
The sequence SUB sp → (optional callee-saved saves) → STP x29,x30 → ADD x29 is
specific to prologue code. Some functions save callee-saved registers before the
frame pointer pair.

**False positive risk:** Low. Requires exact sequence with:
- SUB targeting sp
- STP with x29 AND x30
- ADD setting x29 from sp

**Reference:** Observed in glibc printf, macOS libSystem printf/sprintf/puts/fopen/fwrite

---

### arm64_frame_setup_preindex_callee (Priority: 93) [NEW]
**Source:** Observed in macOS libSystem fclose, fread, and similar functions

**Pattern:** Pre-indexed callee-saved STP followed by frame pointer setup
```
stp xA, xB, [sp, #-N]!    ; Pre-indexed STP allocates stack AND saves callee-saved
stp xC, xD, [sp, #off1]   ; Optional: more callee-saved at signed offset
...
stp x29, x30, [sp, #off2] ; Frame pointer and link register
add x29, sp, #off2        ; Set up frame pointer
```

**Why safe:** This variant folds the stack allocation into the first pre-indexed STP
instruction instead of using a separate SUB sp. The pre-indexed STP with callee-saved
registers (x19-x28) combined with the x29,x30 save and frame pointer setup is specific
to function prologues.

**False positive risk:** Low. Requires exact sequence with:
- Pre-indexed STP of callee-saved registers to sp
- Later STP of x29 AND x30
- ADD setting x29 from sp

**Reference:** Observed in macOS libSystem fclose, fread, and similar file I/O functions

---

### arm64_null_check_prologue (Priority: 90) [NEW]
**Source:** Observed in glibc free(), many functions that check arguments early

**Pattern:** Null/condition check followed by standard prologue
```
cbz/cbnz xN, label   ; Early return for null/special case
<standard_prologue>  ; pac/frame_setup patterns
```

**Why safe:** Many functions check for null pointers or special cases before
setting up the frame (optimization to avoid frame setup on fast paths).
We only match if a valid prologue follows the conditional branch.

**Important:** We include the CBZ/CBNZ in the clobber zone, which means:
- The early-exit path is removed (callers hitting this path will now execute the full function)
- This is acceptable because the hook controls all behavior anyway

**False positive risk:** Low. Requires:
- CBZ/CBNZ as first instruction
- Valid standard prologue immediately following

**Reference:** Observed in glibc free(), realloc()

---

### arm64_no_frame_pointer (Priority: 85) [NEW]
**Source:** GCC/Clang with -fomit-frame-pointer on ARM64

**Pattern:** LR saved with callee-saved, no frame pointer setup
```
stp x30, xN, [sp, #-M]!  ; Pre-indexed STP saves LR with callee-saved
[stp xA, xB, [sp, #off]] ; Optional: more callee-saved saves
; NOTE: No ADD x29, sp instruction (no frame pointer)
```

**Why safe:** Functions compiled with `-fomit-frame-pointer` still save the link
register (x30) for proper return, but don't set up x29 as a frame pointer.
The pre-indexed STP with x30 and callee-saved to sp is specific to function entry.

**False positive risk:** Low. Requires:
- Pre-indexed STP to sp
- x30 (LR) in one position, callee-saved (x19-x28) in the other

**Reference:** Observed in GCC/Clang -O2 -fomit-frame-pointer compiled code on Linux ARM64

---

### arm64_leaf (Priority: 80)
**Source:** Leaf functions that don't call other functions

**Pattern:** Stack allocation without frame pointer
```
sub sp, sp, #N        ; Allocate stack space
stp xA, xB, [sp, #O]  ; Optional: save callee-saved registers
```

**Why safe:** Leaf functions often skip frame pointer setup since they don't need it.
The SUB sp as first instruction is characteristic of function entry.

**False positive risk:** Moderate. SUB sp alone is less specific than frame setup.
We mitigate by requiring the instruction to be the function entry point.

---

## x86-64 Patterns

### x86_64_patchable_entry (Priority: 150)
**Source:** GCC/Clang `__attribute__((patchable_function_entry(N)))`

**Pattern:** NOP sled of ≥5 bytes (various NOP encodings)

**Why safe:** Same rationale as ARM64 - explicit opt-in for patching.
We require ≥5 bytes to fit a JMP rel32 instruction.

---

### x86_64_endbr64 (Priority: 110)
**Source:** Intel Control-flow Enforcement Technology (CET)

**Pattern:** ENDBR64 followed by prologue
```
endbr64          ; f3 0f 1e fa
push rbp
mov rbp, rsp
...
```

**Why safe:** ENDBR64 is a landing pad for indirect branches under CET.
Like BTI on ARM64, it marks valid branch targets.

**Reference:** Intel SDM, Volume 1, Chapter 18 (CET)

---

### x86_64_frame_setup (Priority: 100)
**Source:** System V AMD64 ABI

**Pattern:** Standard frame setup
```
push rbp         ; 55
mov rbp, rsp     ; 48 89 e5
sub rsp, N       ; Optional: allocate locals
push rbx/r12-15  ; Optional: save callee-saved
```

**Why safe:** The push rbp + mov rbp,rsp sequence is the canonical x86-64 prologue.
This exact 4-byte sequence (55 48 89 e5) is extremely specific.

**Reference:** System V AMD64 ABI: https://gitlab.com/x86-psABIs/x86-64-ABI

---

### x86_64_no_frame (Priority: 80)
**Source:** -fomit-frame-pointer optimization

**Pattern:** Callee-saved register pushes without frame pointer
```
push rbx         ; 53
push r12         ; 41 54
push r13         ; 41 55
...
```

**Why safe:** Requires ≥5 bytes of consecutive pushes of callee-saved registers.
This pattern is specific to function prologues in optimized code.

---

### x86_64_sub_rsp (Priority: 70)
**Source:** Functions that allocate stack space without frame pointer

**Pattern:** Stack allocation as first instruction
```
sub rsp, N       ; 48 83 ec XX (imm8) or 48 81 ec XX XX XX XX (imm32)
```

**Why safe:** Only matches if ≥5 bytes, ensuring patchability.
The SUB rsp immediate pattern is characteristic of function entry.

**False positive risk:** Moderate for small functions. The 5-byte minimum helps.

---

## Pattern Priority Guidelines

Higher priority patterns are checked first:
- 150: Explicit patchable entry markers (NOP sleds)
- 110-120: Security features (BTI, CET, PAC) - very reliable markers
- 100: Standard ABI-compliant prologues
- 90-95: Alternative prologue variants (frame_setup_alt, preindex_callee, null_check)
- 80: Leaf functions and edge cases
- 70: Sub-optimal patterns (sub rsp only)

## Adding New Patterns

When adding a new pattern:
1. Document the **source** - where does this pattern come from?
2. Show the **exact byte sequence** expected
3. Explain **why it won't false positive** on non-prologue code
4. Assign appropriate **priority** based on specificity
5. Add **test cases** that verify both matching and non-matching

## Compiler Flag Compatibility

The following compiler flags have been tested and do NOT require special pattern handling:

| Flag | Platform | Notes |
|------|----------|-------|
| `-fstack-protector-strong` | All | Canary setup is AFTER standard prologue |
| `-fomit-frame-pointer` | All | Handled by `arm64_no_frame_pointer` and `x86_64_no_frame` |
| `-mgeneral-regs-only` | ARM64 | No effect on prologue patterns |
| `-mno-red-zone` | x86-64 | No effect on prologue patterns |
| `-fcf-protection=full` | x86-64 | Handled by `x86_64_endbr64` |
| `-mbranch-protection=standard` | ARM64 | Handled by `arm64_bti_prologue` and `arm64_pac_frame` |

**Note:** `-fsanitize=shadow-call-stack` (ARM64 only) may interfere with hooking
as it uses the x18 register for the shadow stack pointer.

## Known Limitations

Some functions cannot be hooked via code patching:
- Hand-optimized assembly (strlen, memcpy, memset in libc)
- Functions smaller than the minimum patch size
- Functions that start with PC-relative instructions that can't be relocated
- IFUNC resolvers (use GOT hooking instead)

For these cases, use `PATCH_METHOD_AUTO` which falls back to GOT hooking.
