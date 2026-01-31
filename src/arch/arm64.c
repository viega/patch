#include "arch.h"

#include "../pattern/pattern.h"
#include "patch/patch_arch.h"

#ifdef PATCH_ARCH_ARM64

#include <string.h>

// =============================================================================
// ARM64 Instruction Encoding/Decoding
// =============================================================================

static inline uint32_t
read_insn(const uint8_t *code)
{
    return (uint32_t)code[0] | ((uint32_t)code[1] << 8) | ((uint32_t)code[2] << 16) | ((uint32_t)code[3] << 24);
}

static inline void
write_insn(uint8_t *code, uint32_t insn)
{
    code[0] = insn & 0xFF;
    code[1] = (insn >> 8) & 0xFF;
    code[2] = (insn >> 16) & 0xFF;
    code[3] = (insn >> 24) & 0xFF;
}

// Extract signed immediate from instruction
static inline int64_t
sign_extend(uint64_t val, int bits)
{
    int64_t sign_bit = 1LL << (bits - 1);
    return (int64_t)((val ^ sign_bit) - sign_bit);
}

size_t
arch_decode_insn(const uint8_t *code, size_t avail, arch_insn_t *out)
{
    if (avail < 4) {
        return 0;
    }

    *out = (arch_insn_t){.length = 4}; // All ARM64 instructions are 4 bytes

    uint32_t insn = read_insn(code);

    // B (unconditional branch)
    // 000101 imm26
    if ((insn & 0xFC000000) == 0x14000000) {
        out->is_branch      = true;
        out->is_pc_relative = true;
        return 4;
    }

    // BL (branch with link)
    // 100101 imm26
    if ((insn & 0xFC000000) == 0x94000000) {
        out->is_call        = true;
        out->is_pc_relative = true;
        return 4;
    }

    // B.cond (conditional branch)
    // 01010100 imm19 0 cond
    if ((insn & 0xFF000010) == 0x54000000) {
        out->is_branch      = true;
        out->is_pc_relative = true;
        return 4;
    }

    // CBZ/CBNZ (compare and branch)
    // x011010 0 imm19 Rt (CBZ)
    // x011010 1 imm19 Rt (CBNZ)
    if ((insn & 0x7E000000) == 0x34000000) {
        out->is_branch      = true;
        out->is_pc_relative = true;
        return 4;
    }

    // TBZ/TBNZ (test and branch)
    // b5 011011 0 b40 imm14 Rt (TBZ)
    // b5 011011 1 b40 imm14 Rt (TBNZ)
    if ((insn & 0x7E000000) == 0x36000000) {
        out->is_branch      = true;
        out->is_pc_relative = true;
        return 4;
    }

    // RET
    // 1101011 0010 11111 0000 00 Rn 00000
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        out->is_return = true;
        return 4;
    }

    // ADR/ADRP (PC-relative address)
    // 0 immlo 10000 immhi Rd (ADR)
    // 1 immlo 10000 immhi Rd (ADRP)
    if ((insn & 0x1F000000) == 0x10000000) {
        out->is_pc_relative = true;
        return 4;
    }

    // LDR (literal) - PC-relative load
    // xx 011 x 00 imm19 Rt
    if ((insn & 0x3B000000) == 0x18000000) {
        out->is_pc_relative = true;
        return 4;
    }

    return 4;
}

size_t
arch_relocate(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_avail, uintptr_t src_addr, uintptr_t dst_addr)
{
    size_t src_pos = 0;
    size_t dst_pos = 0;

    while (src_pos < src_len) {
        if (src_pos + 4 > src_len) {
            return 0;
        }
        if (dst_pos + 16 > dst_avail) {
            return 0; // Reserve space for expansion
        }

        uint32_t  insn = read_insn(src + src_pos);
        uintptr_t pc   = src_addr + src_pos;

        // B (unconditional branch)
        if ((insn & 0xFC000000) == 0x14000000) {
            int32_t   imm26  = insn & 0x03FFFFFF;
            int64_t   offset = sign_extend(imm26, 26) << 2;
            uintptr_t target = pc + offset;

            int64_t new_offset = (int64_t)target - (int64_t)(dst_addr + dst_pos);
            if (new_offset >= (int64_t)-128 * 1024 * 1024 && new_offset < (int64_t)128 * 1024 * 1024 && (new_offset & 3) == 0) {
                // Can use B instruction
                uint32_t new_insn = 0x14000000 | ((new_offset >> 2) & 0x03FFFFFF);
                write_insn(dst + dst_pos, new_insn);
                dst_pos += 4;
            }
            else {
                // Need indirect branch: ldr x16, [pc, #8]; br x16; .quad target
                write_insn(dst + dst_pos, 0x58000050); // LDR x16, [pc, #8]
                dst_pos += 4;
                write_insn(dst + dst_pos, 0xD61F0200); // BR x16
                dst_pos += 4;
                memcpy(dst + dst_pos, &target, 8);
                dst_pos += 8;
            }
            src_pos += 4;
            continue;
        }

        // BL (branch with link)
        if ((insn & 0xFC000000) == 0x94000000) {
            int32_t   imm26  = insn & 0x03FFFFFF;
            int64_t   offset = sign_extend(imm26, 26) << 2;
            uintptr_t target = pc + offset;

            int64_t new_offset = (int64_t)target - (int64_t)(dst_addr + dst_pos);
            if (new_offset >= (int64_t)-128 * 1024 * 1024 && new_offset < (int64_t)128 * 1024 * 1024 && (new_offset & 3) == 0) {
                uint32_t new_insn = 0x94000000 | ((new_offset >> 2) & 0x03FFFFFF);
                write_insn(dst + dst_pos, new_insn);
                dst_pos += 4;
            }
            else {
                // ldr x16, [pc, #8]; blr x16; b +12; .quad target
                write_insn(dst + dst_pos, 0x58000070); // LDR x16, [pc, #12]
                dst_pos += 4;
                write_insn(dst + dst_pos, 0xD63F0200); // BLR x16
                dst_pos += 4;
                write_insn(dst + dst_pos, 0x14000003); // B +12 (skip .quad)
                dst_pos += 4;
                memcpy(dst + dst_pos, &target, 8);
                dst_pos += 8;
            }
            src_pos += 4;
            continue;
        }

        // B.cond (conditional branch)
        if ((insn & 0xFF000010) == 0x54000000) {
            int32_t   imm19  = (insn >> 5) & 0x7FFFF;
            int64_t   offset = sign_extend(imm19, 19) << 2;
            uintptr_t target = pc + offset;

            int64_t new_offset = (int64_t)target - (int64_t)(dst_addr + dst_pos);
            if (new_offset >= (int64_t)-1024 * 1024 && new_offset < (int64_t)1024 * 1024 && (new_offset & 3) == 0) {
                uint32_t new_insn = (insn & 0xFF00001F) | (((new_offset >> 2) & 0x7FFFF) << 5);
                write_insn(dst + dst_pos, new_insn);
                dst_pos += 4;
            }
            else {
                // Invert condition and skip over indirect branch
                uint32_t cond     = insn & 0xF;
                uint32_t inv_cond = cond ^ 1; // Invert least significant bit
                // B.!cond +20 (skip indirect branch)
                write_insn(dst + dst_pos, 0x54000000 | (5 << 5) | inv_cond);
                dst_pos += 4;
                // ldr x16, [pc, #8]; br x16; .quad target
                write_insn(dst + dst_pos, 0x58000050);
                dst_pos += 4;
                write_insn(dst + dst_pos, 0xD61F0200);
                dst_pos += 4;
                memcpy(dst + dst_pos, &target, 8);
                dst_pos += 8;
            }
            src_pos += 4;
            continue;
        }

        // ADR
        if ((insn & 0x9F000000) == 0x10000000) {
            uint32_t  immlo  = (insn >> 29) & 0x3;
            uint32_t  immhi  = (insn >> 5) & 0x7FFFF;
            int64_t   imm    = sign_extend((immhi << 2) | immlo, 21);
            uintptr_t target = pc + imm;
            uint32_t  rd     = insn & 0x1F;

            int64_t new_imm = (int64_t)target - (int64_t)(dst_addr + dst_pos);
            if (new_imm >= (int64_t)-1024 * 1024 && new_imm < (int64_t)1024 * 1024) {
                uint32_t new_immlo = new_imm & 0x3;
                uint32_t new_immhi = (new_imm >> 2) & 0x7FFFF;
                uint32_t new_insn  = (insn & 0x9F00001F) | (new_immlo << 29) | (new_immhi << 5);
                write_insn(dst + dst_pos, new_insn);
                dst_pos += 4;
            }
            else {
                // MOVZ/MOVK sequence to load full address
                // MOVZ rd, #(target & 0xFFFF)
                // MOVK rd, #((target >> 16) & 0xFFFF), LSL #16
                // MOVK rd, #((target >> 32) & 0xFFFF), LSL #32
                // MOVK rd, #((target >> 48) & 0xFFFF), LSL #48
                write_insn(dst + dst_pos, 0xD2800000 | rd | ((target & 0xFFFF) << 5));
                dst_pos += 4;
                write_insn(dst + dst_pos, 0xF2A00000 | rd | (((target >> 16) & 0xFFFF) << 5));
                dst_pos += 4;
                if (target >> 32) {
                    write_insn(dst + dst_pos, 0xF2C00000 | rd | (((target >> 32) & 0xFFFF) << 5));
                    dst_pos += 4;
                }
                if (target >> 48) {
                    write_insn(dst + dst_pos, 0xF2E00000 | rd | (((target >> 48) & 0xFFFF) << 5));
                    dst_pos += 4;
                }
            }
            src_pos += 4;
            continue;
        }

        // ADRP
        if ((insn & 0x9F000000) == 0x90000000) {
            uint32_t  immlo  = (insn >> 29) & 0x3;
            uint32_t  immhi  = (insn >> 5) & 0x7FFFF;
            int64_t   imm    = sign_extend((immhi << 2) | immlo, 21) << 12;
            uintptr_t target = (pc & ~0xFFFULL) + imm;
            uint32_t  rd     = insn & 0x1F;

            // ADRP is page-relative and hard to adjust directly.
            // Use MOVZ/MOVK sequence, emitting only necessary instructions.
            write_insn(dst + dst_pos, 0xD2800000 | rd | ((target & 0xFFFF) << 5));
            dst_pos += 4;
            if (target >> 16) {
                write_insn(dst + dst_pos, 0xF2A00000 | rd | (((target >> 16) & 0xFFFF) << 5));
                dst_pos += 4;
            }
            if (target >> 32) {
                write_insn(dst + dst_pos, 0xF2C00000 | rd | (((target >> 32) & 0xFFFF) << 5));
                dst_pos += 4;
            }
            if (target >> 48) {
                write_insn(dst + dst_pos, 0xF2E00000 | rd | (((target >> 48) & 0xFFFF) << 5));
                dst_pos += 4;
            }

            src_pos += 4;
            continue;
        }

        // LDR (literal)
        if ((insn & 0x3B000000) == 0x18000000) {
            int32_t   imm19  = (insn >> 5) & 0x7FFFF;
            int64_t   offset = sign_extend(imm19, 19) << 2;
            uintptr_t target = pc + offset;

            int64_t new_offset = (int64_t)target - (int64_t)(dst_addr + dst_pos);
            if (new_offset >= (int64_t)-1024 * 1024 && new_offset < (int64_t)1024 * 1024 && (new_offset & 3) == 0) {
                uint32_t new_insn = (insn & 0xFF00001F) | (((new_offset >> 2) & 0x7FFFF) << 5);
                write_insn(dst + dst_pos, new_insn);
                dst_pos += 4;
            }
            else {
                // Complex: need to load address then do regular LDR
                // This changes the instruction semantics, might not work for all cases
                return 0;
            }
            src_pos += 4;
            continue;
        }

        // Non-PC-relative instruction, just copy
        memcpy(dst + dst_pos, src + src_pos, 4);
        dst_pos += 4;
        src_pos += 4;
    }

    return dst_pos;
}

size_t
arch_write_jump(uint8_t *dst, size_t dst_avail, uintptr_t src_addr, uintptr_t dst_addr)
{
    int64_t offset = (int64_t)dst_addr - (int64_t)src_addr;

    // Try B instruction (128MB range)
    if (offset >= (int64_t)-128 * 1024 * 1024 && offset < (int64_t)128 * 1024 * 1024 && (offset & 3) == 0) {
        if (dst_avail < 4) {
            return 0;
        }
        uint32_t insn = 0x14000000 | ((offset >> 2) & 0x03FFFFFF);
        write_insn(dst, insn);
        return 4;
    }

    // Need indirect branch
    // LDR x16, [pc, #8]
    // BR x16
    // .quad target
    if (dst_avail < 16) {
        return 0;
    }

    write_insn(dst, 0x58000050);     // LDR x16, [pc, #8]
    write_insn(dst + 4, 0xD61F0200); // BR x16
    memcpy(dst + 8, &dst_addr, 8);

    return 16;
}

size_t
arch_min_prologue_size(void)
{
    return 4; // Single B instruction
}

// =============================================================================
// ARM64 Prologue Pattern Recognition
// =============================================================================

// Check if instruction is STP with pre-decrement (frame setup)
static inline bool
is_stp_pre(uint32_t insn)
{
    // STP Xt1, Xt2, [Xn, #imm]! (pre-index)
    // 1x10 1001 11ii iiii itttt tnnn nntt ttt1
    return (insn & 0xFFC00000) == 0xA9800000;
}

// Check if instruction is STP x29, x30 (frame pointer + link register)
static inline bool
is_stp_fp_lr(uint32_t insn)
{
    // STP x29, x30, [sp, #imm]! or STP x29, x30, [sp, #imm]
    // Rt = x29 (11101), Rt2 = x30 (11110), Rn = sp (11111)
    uint32_t rt  = insn & 0x1F;
    uint32_t rt2 = (insn >> 10) & 0x1F;
    uint32_t rn  = (insn >> 5) & 0x1F;

    return rt == 29 && rt2 == 30 && rn == 31;
}

// Check if instruction is MOV x29, sp
static inline bool
is_mov_fp_sp(uint32_t insn)
{
    // MOV x29, sp is encoded as ADD x29, sp, #0
    // 1001 0001 00ii iiii iiii ii11 1111 1101 (0x910003FD)
    return insn == 0x910003FD;
}

// Check if instruction is SUB sp, sp, #imm
static inline bool
is_sub_sp(uint32_t insn)
{
    // SUB Xd, Xn, #imm (64-bit)
    // 1101 0001 00ii iiii iiii iinn nnnd dddd
    // We want Xn = sp (11111) and Xd = sp (11111)
    uint32_t rn = (insn >> 5) & 0x1F;
    uint32_t rd = insn & 0x1F;
    // Check it's a 64-bit SUB immediate with Rn=sp and Rd=sp
    return (insn & 0xFF000000) == 0xD1000000 && rn == 31 && rd == 31;
}

// Check if instruction is STP for callee-saved registers
static inline bool
is_stp_callee_saved(uint32_t insn)
{
    // STP with x19-x28 or d8-d15
    if ((insn & 0x7FC00000) != 0x29000000 && // STP signed offset
        (insn & 0x7FC00000) != 0x29800000) { // STP pre-index
        return false;
    }
    uint32_t rt = insn & 0x1F;
    // x19-x28 are callee-saved
    return (rt >= 19 && rt <= 28);
}

// Forward declarations for patterns that reference each other
static bool match_frame_setup(const uint8_t *code, size_t avail, pattern_match_t *out);
static bool match_frame_setup_alt(const uint8_t *code, size_t avail, pattern_match_t *out);
static bool match_frame_setup_preindex_callee(const uint8_t *code, size_t avail, pattern_match_t *out);
static bool match_no_frame_pointer(const uint8_t *code, size_t avail, pattern_match_t *out);

// Pattern: Standard frame setup
// stp x29, x30, [sp, #-N]!
// mov x29, sp
static bool
match_frame_setup(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 8) {
        return false;
    }

    uint32_t insn0 = read_insn(code);
    uint32_t insn1 = read_insn(code + 4);

    // Check for STP x29, x30, [sp, #-N]!
    if (!is_stp_pre(insn0) || !is_stp_fp_lr(insn0)) {
        return false;
    }

    size_t offset = 4;

    // Check for MOV x29, sp
    if (is_mov_fp_sp(insn1)) {
        offset = 8;
    }

    // Look for additional callee-saved register saves
    while (avail >= offset + 4) {
        uint32_t insn = read_insn(code + offset);
        if (is_stp_callee_saved(insn) || is_sub_sp(insn)) {
            offset += 4;
        }
        else {
            break;
        }
    }

    out->matched         = true;
    out->pattern_name    = "arm64_frame_setup";
    out->prologue_size   = offset;
    out->min_patch_size  = 4; // Single branch
    out->has_pc_relative = false;

    return true;
}

// Pattern: Pac-enabled prologue (pointer authentication)
// paciasp / pacibsp followed by normal prologue
static bool
match_pac(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 8) {
        return false;
    }

    uint32_t insn0 = read_insn(code);

    // paciasp = 0xD503233F, pacibsp = 0xD503237F
    if (insn0 != 0xD503233F && insn0 != 0xD503237F) {
        return false;
    }

    // Try to match rest as frame_setup variants
    pattern_match_t sub = {0};
    if (match_frame_setup(code + 4, avail - 4, &sub) ||
        match_frame_setup_alt(code + 4, avail - 4, &sub) ||
        match_frame_setup_preindex_callee(code + 4, avail - 4, &sub)) {
        out->matched         = true;
        out->pattern_name    = "arm64_pac_frame";
        out->prologue_size   = 4 + sub.prologue_size;
        out->min_patch_size  = 4;
        out->has_pc_relative = sub.has_pc_relative;
        return true;
    }

    return false;
}

// Pattern: BTI (Branch Target Identification) followed by prologue
static bool
match_bti(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 8) {
        return false;
    }

    uint32_t insn0 = read_insn(code);

    // BTI instructions: 0xD503241F (bti), 0xD503245F (bti c),
    //                   0xD503249F (bti j), 0xD50324DF (bti jc)
    if ((insn0 & 0xFFFFFF1F) != 0xD503241F) {
        return false;
    }

    // Try to match rest as PAC, frame_setup, or frame_setup_alt
    pattern_match_t sub = {0};
    if (match_pac(code + 4, avail - 4, &sub) ||
        match_frame_setup(code + 4, avail - 4, &sub) ||
        match_frame_setup_alt(code + 4, avail - 4, &sub)) {
        out->matched         = true;
        out->pattern_name    = "arm64_bti_prologue";
        out->prologue_size   = 4 + sub.prologue_size;
        out->min_patch_size  = 4;
        out->has_pc_relative = sub.has_pc_relative;
        return true;
    }

    return false;
}

// Pattern: Leaf function (no frame setup, maybe just sub sp)
static bool
match_leaf(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 4) {
        return false;
    }

    uint32_t insn0 = read_insn(code);

    // Check for SUB sp, sp, #imm as first instruction
    if (!is_sub_sp(insn0)) {
        return false;
    }

    size_t offset = 4;

    // Look for more stack operations
    while (avail >= offset + 4) {
        uint32_t insn = read_insn(code + offset);
        if (is_sub_sp(insn) || is_stp_callee_saved(insn)) {
            offset += 4;
        }
        else {
            break;
        }
    }

    out->matched         = true;
    out->pattern_name    = "arm64_leaf";
    out->prologue_size   = offset;
    out->min_patch_size  = 4;
    out->has_pc_relative = false;

    return true;
}

// Check if instruction is STP with signed offset (not pre-index)
// Used for: stp x29, x30, [sp, #offset]
static inline bool
is_stp_signed_offset(uint32_t insn)
{
    // STP Xt1, Xt2, [Xn, #imm] (signed offset, no writeback)
    // 1x10 1001 00ii iiii itttt tnnn nntt ttt1
    return (insn & 0xFFC00000) == 0xA9000000;
}

// Check if instruction is ADD Xd, sp, #imm
static inline bool
is_add_from_sp(uint32_t insn, uint32_t *rd)
{
    // ADD Xd, Xn, #imm (64-bit)
    // 1001 0001 00ii iiii iiii iinn nnnd dddd
    // We want Xn = sp (11111)
    if ((insn & 0xFF000000) != 0x91000000) {
        return false;
    }
    uint32_t rn = (insn >> 5) & 0x1F;
    if (rn != 31) {
        return false;
    }
    *rd = insn & 0x1F;
    return true;
}

// Check if instruction is STP for callee-saved registers (with signed offset variant)
static inline bool
is_stp_callee_saved_signed(uint32_t insn)
{
    // STP with signed offset (not pre-index): 1x10 1001 00ii iiii itttt tnnn nntt ttt1
    if ((insn & 0xFFC00000) != 0xA9000000) {
        return false;
    }
    uint32_t rt = insn & 0x1F;
    // x19-x28 are callee-saved
    return (rt >= 19 && rt <= 28);
}

// Check if instruction is STP callee-saved with pre-index (allocates stack AND saves)
static inline bool
is_stp_callee_saved_pre(uint32_t insn)
{
    // STP with pre-index: 1x10 1001 11ii iiii itttt tnnn nntt ttt1
    if ((insn & 0xFFC00000) != 0xA9800000) {
        return false;
    }
    uint32_t rt = insn & 0x1F;
    uint32_t rn = (insn >> 5) & 0x1F;
    // x19-x28 are callee-saved, base must be sp
    return (rt >= 19 && rt <= 28) && (rn == 31);
}

// Check if instruction is STP with LR (x30) saved (common with -fomit-frame-pointer)
// This includes patterns like: STP x30, x19, [sp, #-N]! where LR is rt and callee-saved is rt2
static inline bool
is_stp_lr_pre(uint32_t insn)
{
    // STP with pre-index: 1x10 1001 11ii iiii itttt tnnn nntt ttt1
    if ((insn & 0xFFC00000) != 0xA9800000) {
        return false;
    }
    uint32_t rt  = insn & 0x1F;
    uint32_t rt2 = (insn >> 10) & 0x1F;
    uint32_t rn  = (insn >> 5) & 0x1F;
    // x30 (LR) in either position with callee-saved register, base must be sp
    bool has_lr = (rt == 30 || rt2 == 30);
    bool has_callee_saved = (rt >= 19 && rt <= 28) || (rt2 >= 19 && rt2 <= 28);
    return has_lr && has_callee_saved && (rn == 31);
}

// Pattern: Alternative frame setup with explicit SUB then STP at offset
// Source: Observed in glibc printf, macOS libSystem printf/sprintf/puts/fopen/etc.
// Pattern variants:
//   1. sub sp, sp, #N; stp x29, x30, [sp, #off]; add x29, sp, #off
//   2. sub sp, sp, #N; stp xA, xB, [sp, #off1]; ... ; stp x29, x30, [sp, #off2]; add x29, sp, #off2
// The second variant saves callee-saved registers BEFORE x29,x30.
// See PATTERNS.md for full documentation.
static bool
match_frame_setup_alt(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 12) {  // Need at least 3 instructions
        return false;
    }

    uint32_t insn0 = read_insn(code);

    // First instruction: SUB sp, sp, #imm
    if (!is_sub_sp(insn0)) {
        return false;
    }

    size_t offset = 4;

    // Skip any callee-saved register saves that come before x29,x30
    while (avail >= offset + 4) {
        uint32_t insn = read_insn(code + offset);
        if (is_stp_callee_saved_signed(insn)) {
            offset += 4;
        }
        else {
            break;
        }
    }

    // Now we need: STP x29, x30, [sp, #offset] (signed offset, not pre-index)
    if (avail < offset + 8) {
        return false;
    }

    uint32_t stp_insn = read_insn(code + offset);
    if (!is_stp_signed_offset(stp_insn) || !is_stp_fp_lr(stp_insn)) {
        return false;
    }
    offset += 4;

    // Next instruction: ADD x29, sp, #offset (set up frame pointer)
    uint32_t add_insn = read_insn(code + offset);
    uint32_t rd;
    if (!is_add_from_sp(add_insn, &rd) || rd != 29) {
        return false;
    }
    offset += 4;

    // Look for additional callee-saved register saves or stack adjustments
    while (avail >= offset + 4) {
        uint32_t insn = read_insn(code + offset);
        if (is_stp_callee_saved(insn) || is_stp_callee_saved_signed(insn) || is_sub_sp(insn)) {
            offset += 4;
        }
        else {
            break;
        }
    }

    out->matched         = true;
    out->pattern_name    = "arm64_frame_setup_alt";
    out->prologue_size   = offset;
    out->min_patch_size  = 4;
    out->has_pc_relative = false;

    return true;
}

// Pattern: Frame setup starting with pre-indexed callee-saved STP
// Source: Observed in macOS libSystem fclose, fread, etc.
// Pattern: stp xA, xB, [sp, #-N]!; stp ...; stp x29, x30, [sp, #off]; add x29, sp, #off
// The stack allocation is implicit in the first pre-indexed STP.
// See PATTERNS.md for full documentation.
static bool
match_frame_setup_preindex_callee(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 16) {  // Need at least 4 instructions
        return false;
    }

    uint32_t insn0 = read_insn(code);

    // First instruction: STP callee-saved, [sp, #-N]! (pre-indexed)
    if (!is_stp_callee_saved_pre(insn0)) {
        return false;
    }

    size_t offset = 4;

    // Skip any additional callee-saved register saves (signed offset)
    while (avail >= offset + 4) {
        uint32_t insn = read_insn(code + offset);
        if (is_stp_callee_saved_signed(insn)) {
            offset += 4;
        }
        else {
            break;
        }
    }

    // Now we need: STP x29, x30, [sp, #offset] (signed offset)
    if (avail < offset + 8) {
        return false;
    }

    uint32_t stp_insn = read_insn(code + offset);
    if (!is_stp_signed_offset(stp_insn) || !is_stp_fp_lr(stp_insn)) {
        return false;
    }
    offset += 4;

    // Next instruction: ADD x29, sp, #offset (set up frame pointer)
    uint32_t add_insn = read_insn(code + offset);
    uint32_t rd;
    if (!is_add_from_sp(add_insn, &rd) || rd != 29) {
        return false;
    }
    offset += 4;

    // Look for additional callee-saved register saves or stack adjustments
    while (avail >= offset + 4) {
        uint32_t insn = read_insn(code + offset);
        if (is_stp_callee_saved(insn) || is_stp_callee_saved_signed(insn) || is_sub_sp(insn)) {
            offset += 4;
        }
        else {
            break;
        }
    }

    out->matched         = true;
    out->pattern_name    = "arm64_frame_setup_preindex_callee";
    out->prologue_size   = offset;
    out->min_patch_size  = 4;
    out->has_pc_relative = false;

    return true;
}

// Check if instruction is CBZ or CBNZ
static inline bool
is_cbz_cbnz(uint32_t insn)
{
    // CBZ:  x011 0100 imm19 Rt
    // CBNZ: x011 0101 imm19 Rt
    return (insn & 0x7E000000) == 0x34000000;
}

// Pattern: -fomit-frame-pointer prologue
// Source: GCC/Clang with -fomit-frame-pointer on ARM64
// Pattern: stp x30, xN, [sp, #-M]! or stp xN, x30, [sp, #-M]!
// The function saves LR and callee-saved registers but doesn't set up x29 as frame pointer.
// See PATTERNS.md for full documentation.
static bool
match_no_frame_pointer(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 4) {
        return false;
    }

    uint32_t insn0 = read_insn(code);

    // First instruction: STP with LR (x30) pre-indexed
    if (!is_stp_lr_pre(insn0)) {
        return false;
    }

    size_t offset = 4;

    // Look for additional callee-saved register saves or stack adjustments
    while (avail >= offset + 4) {
        uint32_t insn = read_insn(code + offset);
        if (is_stp_callee_saved(insn) || is_stp_callee_saved_signed(insn) || is_sub_sp(insn)) {
            offset += 4;
        }
        else {
            break;
        }
    }

    out->matched         = true;
    out->pattern_name    = "arm64_no_frame_pointer";
    out->prologue_size   = offset;
    out->min_patch_size  = 4;
    out->has_pc_relative = false;

    return true;
}

// Pattern: Null/condition check followed by standard prologue
// Source: Observed in glibc free(), realloc() - check for null before frame setup
// Pattern: cbz/cbnz xN, label; <standard_prologue>
// See PATTERNS.md for full documentation.
static bool
match_null_check_prologue(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 8) {
        return false;
    }

    uint32_t insn0 = read_insn(code);

    // First instruction must be CBZ or CBNZ
    if (!is_cbz_cbnz(insn0)) {
        return false;
    }

    // Try to match the rest as a standard prologue
    pattern_match_t sub = {0};
    if (match_pac(code + 4, avail - 4, &sub) ||
        match_frame_setup(code + 4, avail - 4, &sub) ||
        match_frame_setup_alt(code + 4, avail - 4, &sub)) {

        out->matched         = true;
        out->pattern_name    = "arm64_null_check_prologue";
        out->prologue_size   = 4 + sub.prologue_size;
        out->min_patch_size  = 4;
        // The CBZ/CBNZ is PC-relative, so we need relocation
        out->has_pc_relative = true;

        return true;
    }

    return false;
}

// Pattern: Patchable function entry (NOP sled from __attribute__((patchable_function_entry)))
// This is the recommended way to make functions patchable on macOS ARM64
static bool
match_patchable_entry(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 4) {
        return false;
    }

    // Count leading NOPs (0xD503201F)
    size_t nop_count = 0;
    size_t offset    = 0;

    while (offset + 4 <= avail) {
        uint32_t insn = read_insn(code + offset);
        if (insn == 0xD503201F) { // NOP
            nop_count++;
            offset += 4;
        }
        else {
            break;
        }
    }

    // Need at least 2 NOPs (8 bytes) to be recognized as a patchable entry.
    // This distinguishes intentionally patchable functions (using the
    // patchable_function_entry attribute) from functions that happen to
    // start with a single NOP (common in optimized code for alignment).
    // With 8 bytes, we have room for a B instruction (4 bytes) plus margin.
    if (nop_count < 2) {
        return false;
    }

    out->matched         = true;
    out->pattern_name    = "arm64_patchable_entry";
    out->prologue_size   = offset;
    out->min_patch_size  = 4; // Minimum for B instruction
    out->has_pc_relative = false;

    return true;
}

static pattern_handler_t handler_frame_setup = {
    .name        = "arm64_frame_setup",
    .description = "Standard frame setup: stp x29, x30; mov x29, sp",
    .priority    = 100,
    .match       = match_frame_setup,
};

static pattern_handler_t handler_pac = {
    .name        = "arm64_pac",
    .description = "PAC-enabled: paciasp/pacibsp + prologue",
    .priority    = 110,
    .match       = match_pac,
};

static pattern_handler_t handler_bti = {
    .name        = "arm64_bti",
    .description = "BTI-enabled: bti + prologue",
    .priority    = 120,
    .match       = match_bti,
};

static pattern_handler_t handler_leaf = {
    .name        = "arm64_leaf",
    .description = "Leaf function: sub sp + optional saves",
    .priority    = 80,
    .match       = match_leaf,
};

static pattern_handler_t handler_patchable = {
    .name        = "arm64_patchable_entry",
    .description = "Patchable function entry: NOP sled from patchable_function_entry attribute",
    .priority    = 150, // Highest priority - explicit opt-in
    .match       = match_patchable_entry,
};

static pattern_handler_t handler_frame_setup_alt = {
    .name        = "arm64_frame_setup_alt",
    .description = "Alternative frame setup: sub sp; stp x29,x30,[sp,#off]; add x29,sp,#off",
    .priority    = 95,
    .match       = match_frame_setup_alt,
};

static pattern_handler_t handler_null_check = {
    .name        = "arm64_null_check_prologue",
    .description = "Null check prologue: cbz/cbnz followed by standard prologue",
    .priority    = 90,
    .match       = match_null_check_prologue,
};

static pattern_handler_t handler_preindex_callee = {
    .name        = "arm64_frame_setup_preindex_callee",
    .description = "Callee-saved pre-indexed: stp xA,xB,[sp,#-N]!; ... stp x29,x30; add x29",
    .priority    = 93,
    .match       = match_frame_setup_preindex_callee,
};

static pattern_handler_t handler_no_frame_pointer = {
    .name        = "arm64_no_frame_pointer",
    .description = "No frame pointer: stp x30,xN,[sp,#-M]! (-fomit-frame-pointer)",
    .priority    = 85,
    .match       = match_no_frame_pointer,
};

void
pattern_init_arm64(void)
{
    static bool initialized = false;
    if (initialized) {
        return;
    }
    initialized = true;

    pattern_register(&handler_patchable);
    pattern_register(&handler_bti);
    pattern_register(&handler_pac);
    pattern_register(&handler_frame_setup);
    pattern_register(&handler_frame_setup_alt);
    pattern_register(&handler_preindex_callee);
    pattern_register(&handler_null_check);
    pattern_register(&handler_no_frame_pointer);
    pattern_register(&handler_leaf);
}

#endif // PATCH_ARCH_ARM64
