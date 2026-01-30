#include "arch.h"

#include "patch/patch_arch.h"

#ifdef PATCH_ARCH_ARM64

#include <string.h>

// ARM64 instruction encoding/decoding helpers

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

#endif // PATCH_ARCH_ARM64
