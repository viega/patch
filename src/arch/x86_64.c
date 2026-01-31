#include "arch.h"

#include "../pattern/pattern.h"
#include "patch/patch_arch.h"

#ifdef PATCH_ARCH_X86_64

#include <string.h>

// Minimal x86-64 instruction decoder focused on prologue patterns
// This is not a complete decoder - just enough for relocation

// REX prefix bits
#define REX_W 0x08
#define REX_R 0x04
#define REX_X 0x02
#define REX_B 0x01

// ModRM byte extraction
#define MODRM_MOD(b) (((b) >> 6) & 0x03)
#define MODRM_REG(b) (((b) >> 3) & 0x07)
#define MODRM_RM(b)  ((b) & 0x07)

// SIB byte extraction
#define SIB_SCALE(b) (((b) >> 6) & 0x03)
#define SIB_INDEX(b) (((b) >> 3) & 0x07)
#define SIB_BASE(b)  ((b) & 0x07)

// Check if instruction uses RIP-relative addressing
static bool
check_rip_relative(const uint8_t *code, size_t len, size_t *disp_offset)
{
    size_t pos = 0;

    // Skip prefixes
    while (pos < len) {
        uint8_t b = code[pos];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3) {
            pos++;
        }
        else if (b >= 0x40 && b <= 0x4F) {
            pos++; // REX
            break;
        }
        else {
            break;
        }
    }

    // Skip opcode(s)
    if (pos >= len) {
        return false;
    }

    uint8_t op1 = code[pos++];

    // Two-byte opcode
    if (op1 == 0x0F && pos < len) {
        pos++; // Skip second opcode byte
    }

    // Check for ModRM byte
    if (pos >= len) {
        return false;
    }

    uint8_t modrm = code[pos];
    uint8_t mod   = MODRM_MOD(modrm);
    uint8_t rm    = MODRM_RM(modrm);

    // RIP-relative: mod=00, rm=101 (without SIB)
    if (mod == 0 && rm == 5) {
        *disp_offset = pos + 1; // Displacement starts after ModRM
        return true;
    }

    return false;
}

// Decode a ModRM-based instruction starting at modrm_pos.
// Returns total instruction length, or 0 on failure.
// Sets out->is_pc_relative if RIP-relative addressing is used.
static size_t
decode_modrm_insn(const uint8_t *code, size_t avail, size_t modrm_pos, uint8_t opcode, arch_insn_t *out)
{
    if (modrm_pos >= avail) {
        return 0;
    }

    uint8_t modrm = code[modrm_pos];
    uint8_t mod   = MODRM_MOD(modrm);
    uint8_t rm    = MODRM_RM(modrm);

    size_t pos = modrm_pos + 1;

    // Check for SIB byte
    bool has_sib = (mod != 3 && rm == 4);
    if (has_sib) {
        if (pos >= avail) {
            return 0;
        }
        pos++;
    }

    // Calculate displacement size
    size_t disp_size = 0;
    if (mod == 0 && rm == 5) {
        // RIP-relative (disp32)
        disp_size           = 4;
        out->is_pc_relative = true;
    }
    else if (mod == 0 && has_sib && (code[modrm_pos + 1] & 0x07) == 5) {
        // [SIB + disp32]
        disp_size = 4;
    }
    else if (mod == 1) {
        disp_size = 1;
    }
    else if (mod == 2) {
        disp_size = 4;
    }

    pos += disp_size;

    // Add immediate size based on opcode
    if (opcode == 0x83) {
        pos += 1; // imm8
    }
    else if (opcode == 0x81) {
        pos += 4; // imm32
    }

    if (pos > avail) {
        return 0;
    }

    out->length = pos;
    return pos;
}

size_t
arch_decode_insn(const uint8_t *code, size_t avail, arch_insn_t *out)
{
    if (avail == 0) {
        return 0;
    }

    *out = (arch_insn_t){0};

    size_t pos = 0;

    // Parse prefixes
    while (pos < avail) {
        uint8_t b = code[pos];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65 || b == 0x36) {
            pos++;
        }
        else if (b >= 0x40 && b <= 0x4F) {
            pos++; // REX prefix
            break;
        }
        else {
            break;
        }
    }

    if (pos >= avail) {
        return 0;
    }

    uint8_t op1 = code[pos++];

    // Single-byte instructions
    // PUSH r64 (0x50-0x57) or POP r64 (0x58-0x5F)
    if ((op1 >= 0x50 && op1 <= 0x57) || (op1 >= 0x58 && op1 <= 0x5F)) {
        out->length = pos;
        return pos;
    }

    // Jcc rel8 (0x70-0x7F)
    if (op1 >= 0x70 && op1 <= 0x7F) {
        if (pos + 1 > avail) {
            return 0;
        }
        out->length         = pos + 1;
        out->is_branch      = true;
        out->is_pc_relative = true;
        return pos + 1;
    }

    switch (op1) {
    case 0x90: // NOP
        out->length = pos;
        return pos;

    case 0xC3: // RET
        out->length    = pos;
        out->is_return = true;
        return pos;

    case 0xC2: // RET imm16
        if (pos + 2 > avail) {
            return 0;
        }
        out->length    = pos + 2;
        out->is_return = true;
        return pos + 2;

    case 0xE8: // CALL rel32
        if (pos + 4 > avail) {
            return 0;
        }
        out->length         = pos + 4;
        out->is_call        = true;
        out->is_pc_relative = true;
        return pos + 4;

    case 0xE9: // JMP rel32
        if (pos + 4 > avail) {
            return 0;
        }
        out->length         = pos + 4;
        out->is_branch      = true;
        out->is_pc_relative = true;
        return pos + 4;

    case 0xEB: // JMP rel8
        if (pos + 1 > avail) {
            return 0;
        }
        out->length         = pos + 1;
        out->is_branch      = true;
        out->is_pc_relative = true;
        return pos + 1;
    }

    // Two-byte opcode (0F xx)
    if (op1 == 0x0F) {
        if (pos >= avail) {
            return 0;
        }
        uint8_t op2 = code[pos++];

        // Jcc rel32
        if (op2 >= 0x80 && op2 <= 0x8F) {
            if (pos + 4 > avail) {
                return 0;
            }
            out->length         = pos + 4;
            out->is_branch      = true;
            out->is_pc_relative = true;
            return pos + 4;
        }

        // Other 0F instructions need ModRM
        return decode_modrm_insn(code, avail, pos, op1, out);
    }

    // Instructions with ModRM byte (common prologue instructions)
    return decode_modrm_insn(code, avail, pos, op1, out);
}

size_t
arch_relocate(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_avail, uintptr_t src_addr, uintptr_t dst_addr)
{
    size_t src_pos = 0;
    size_t dst_pos = 0;

    while (src_pos < src_len) {
        arch_insn_t insn;
        size_t      len = arch_decode_insn(src + src_pos, src_len - src_pos, &insn);

        if (len == 0) {
            return 0; // Decode failure
        }

        if (insn.is_pc_relative) {
            // Need to relocate PC-relative instruction
            // For simplicity, convert short jumps to near jumps if needed
            uint8_t op = src[src_pos];

            // CALL rel32 or JMP rel32
            if ((op == 0xE8 || op == 0xE9) && len == 5) {
                if (dst_pos + 5 > dst_avail) {
                    return 0;
                }

                int32_t orig_rel;
                memcpy(&orig_rel, src + src_pos + 1, 4);

                uintptr_t target  = src_addr + src_pos + 5 + orig_rel;
                int64_t   new_rel = (int64_t)target - (int64_t)(dst_addr + dst_pos + 5);

                if (new_rel > INT32_MAX || new_rel < INT32_MIN) {
                    // Target too far, need absolute jump
                    // Use: movabs r11, target; call/jmp r11
                    if (dst_pos + 13 > dst_avail) {
                        return 0;
                    }

                    dst[dst_pos++] = 0x49; // REX.WB
                    dst[dst_pos++] = 0xBB; // MOV r11, imm64
                    memcpy(dst + dst_pos, &target, 8);
                    dst_pos += 8;

                    if (op == 0xE8) {
                        dst[dst_pos++] = 0x41; // REX.B
                        dst[dst_pos++] = 0xFF; // CALL r/m
                        dst[dst_pos++] = 0xD3; // ModRM: r11
                    }
                    else {
                        dst[dst_pos++] = 0x41; // REX.B
                        dst[dst_pos++] = 0xFF; // JMP r/m
                        dst[dst_pos++] = 0xE3; // ModRM: r11
                    }
                }
                else {
                    dst[dst_pos++]    = op;
                    int32_t new_rel32 = (int32_t)new_rel;
                    memcpy(dst + dst_pos, &new_rel32, 4);
                    dst_pos += 4;
                }

                src_pos += len;
                continue;
            }

            // Short conditional jump - expand to near
            if (op >= 0x70 && op <= 0x7F && len == 2) {
                if (dst_pos + 6 > dst_avail) {
                    return 0;
                }

                int8_t    orig_rel = (int8_t)src[src_pos + 1];
                uintptr_t target   = src_addr + src_pos + 2 + orig_rel;
                int64_t   new_rel  = (int64_t)target - (int64_t)(dst_addr + dst_pos + 6);

                if (new_rel > INT32_MAX || new_rel < INT32_MIN) {
                    return 0; // Can't handle this case easily
                }

                dst[dst_pos++]    = 0x0F;      // Two-byte opcode prefix
                dst[dst_pos++]    = op + 0x10; // Jcc rel32
                int32_t new_rel32 = (int32_t)new_rel;
                memcpy(dst + dst_pos, &new_rel32, 4);
                dst_pos += 4;

                src_pos += len;
                continue;
            }

            // Short JMP - expand to near
            if (op == 0xEB && len == 2) {
                if (dst_pos + 5 > dst_avail) {
                    return 0;
                }

                int8_t    orig_rel = (int8_t)src[src_pos + 1];
                uintptr_t target   = src_addr + src_pos + 2 + orig_rel;
                int64_t   new_rel  = (int64_t)target - (int64_t)(dst_addr + dst_pos + 5);

                if (new_rel > INT32_MAX || new_rel < INT32_MIN) {
                    return 0;
                }

                dst[dst_pos++]    = 0xE9;
                int32_t new_rel32 = (int32_t)new_rel;
                memcpy(dst + dst_pos, &new_rel32, 4);
                dst_pos += 4;

                src_pos += len;
                continue;
            }

            // RIP-relative memory operand
            size_t disp_offset;
            if (check_rip_relative(src + src_pos, len, &disp_offset)) {
                if (dst_pos + len > dst_avail) {
                    return 0;
                }

                // Copy instruction
                memcpy(dst + dst_pos, src + src_pos, len);

                // Adjust the RIP-relative displacement
                int32_t orig_disp;
                memcpy(&orig_disp, src + src_pos + disp_offset, 4);

                uintptr_t target   = src_addr + src_pos + len + orig_disp;
                int64_t   new_disp = (int64_t)target - (int64_t)(dst_addr + dst_pos + len);

                if (new_disp > INT32_MAX || new_disp < INT32_MIN) {
                    return 0; // Need absolute addressing, complex
                }

                int32_t new_disp32 = (int32_t)new_disp;
                memcpy(dst + dst_pos + disp_offset, &new_disp32, 4);

                dst_pos += len;
                src_pos += len;
                continue;
            }
        }

        // Non-PC-relative instruction, just copy
        if (dst_pos + len > dst_avail) {
            return 0;
        }
        memcpy(dst + dst_pos, src + src_pos, len);
        dst_pos += len;
        src_pos += len;
    }

    return dst_pos;
}

size_t
arch_write_jump(uint8_t *dst, size_t dst_avail, uintptr_t src_addr, uintptr_t dst_addr)
{
    int64_t rel = (int64_t)dst_addr - (int64_t)(src_addr + 5);

    // Try rel32 jump first
    if (rel >= INT32_MIN && rel <= INT32_MAX) {
        if (dst_avail < 5) {
            return 0;
        }
        dst[0]        = 0xE9; // JMP rel32
        int32_t rel32 = (int32_t)rel;
        memcpy(dst + 1, &rel32, 4);
        return 5;
    }

    // Need absolute jump via register
    // movabs r11, target; jmp r11 = 13 bytes
    if (dst_avail < 13) {
        return 0;
    }

    dst[0] = 0x49;  // REX.WB
    dst[1] = 0xBB;  // MOV r11, imm64
    memcpy(dst + 2, &dst_addr, 8);
    dst[10] = 0x41; // REX.B
    dst[11] = 0xFF; // JMP r/m64
    dst[12] = 0xE3; // ModRM: r11

    return 13;
}

size_t
arch_min_prologue_size(void)
{
    return 5; // JMP rel32
}

// =============================================================================
// x86-64 Prologue Pattern Recognition
// =============================================================================

// Pattern: push rbp; mov rbp, rsp
// This is the standard frame setup, found in -O0 and sometimes -O1
static bool
match_frame_setup(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 4) {
        return false;
    }

    // push rbp = 0x55
    if (code[0] != 0x55) {
        return false;
    }

    // mov rbp, rsp = 48 89 e5
    if (code[1] != 0x48 || code[2] != 0x89 || code[3] != 0xe5) {
        return false;
    }

    size_t offset = 4;

    // Look for optional sub rsp, imm (stack allocation)
    if (avail >= offset + 4) {
        // sub rsp, imm8: 48 83 ec XX
        if (code[offset] == 0x48 && code[offset + 1] == 0x83 && code[offset + 2] == 0xec) {
            offset += 4;
        }
        // sub rsp, imm32: 48 81 ec XX XX XX XX
        else if (avail >= offset + 7 && code[offset] == 0x48 && code[offset + 1] == 0x81 && code[offset + 2] == 0xec) {
            offset += 7;
        }
    }

    // Look for push of callee-saved registers
    while (avail > offset) {
        // push rbx = 53
        // push r12 = 41 54
        // push r13 = 41 55
        // push r14 = 41 56
        // push r15 = 41 57
        if (code[offset] == 0x53) {
            offset++;
        }
        else if (avail >= offset + 2 && code[offset] == 0x41) {
            uint8_t reg = code[offset + 1];
            if (reg >= 0x54 && reg <= 0x57) {
                offset += 2;
            }
            else {
                break;
            }
        }
        else {
            break;
        }
    }

    out->matched         = true;
    out->pattern_name    = "x86_64_frame_setup";
    out->prologue_size   = offset;
    out->min_patch_size  = 5; // JMP rel32
    out->has_pc_relative = false;

    return true;
}

// Pattern: No frame pointer (optimized code)
// Often starts with push of callee-saved registers directly
static bool
match_no_frame(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 5) {
        return false;
    }

    size_t offset = 0;

    // Must start with at least one push
    bool found_push = false;

    while (avail > offset) {
        // push rbx = 53
        if (code[offset] == 0x53) {
            offset++;
            found_push = true;
        }
        // push rbp = 55 (but without frame setup)
        else if (code[offset] == 0x55) {
            // Check that next is NOT mov rbp, rsp
            if (avail >= offset + 4 && code[offset + 1] == 0x48 && code[offset + 2] == 0x89 && code[offset + 3] == 0xe5) {
                // This is actually a frame setup pattern
                return false;
            }
            offset++;
            found_push = true;
        }
        // push r12-r15 = 41 54-57
        else if (avail >= offset + 2 && code[offset] == 0x41) {
            uint8_t reg = code[offset + 1];
            if (reg >= 0x54 && reg <= 0x57) {
                offset += 2;
                found_push = true;
            }
            else {
                break;
            }
        }
        else {
            break;
        }
    }

    if (!found_push || offset < 5) {
        return false;
    }

    out->matched         = true;
    out->pattern_name    = "x86_64_no_frame";
    out->prologue_size   = offset;
    out->min_patch_size  = 5;
    out->has_pc_relative = false;

    return true;
}

// Pattern: endbr64 followed by normal prologue (CET-enabled code)
static bool
match_endbr64(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 8) {
        return false;
    }

    // endbr64 = f3 0f 1e fa
    if (code[0] != 0xf3 || code[1] != 0x0f || code[2] != 0x1e || code[3] != 0xfa) {
        return false;
    }

    // Try to match rest as frame_setup
    pattern_match_t sub = {0};
    if (match_frame_setup(code + 4, avail - 4, &sub)) {
        out->matched         = true;
        out->pattern_name    = "x86_64_endbr64_frame";
        out->prologue_size   = 4 + sub.prologue_size;
        out->min_patch_size  = 5;
        out->has_pc_relative = sub.has_pc_relative;
        return true;
    }

    // Or just endbr64 + push rbp minimum
    if (code[4] == 0x55) {
        out->matched         = true;
        out->pattern_name    = "x86_64_endbr64_min";
        out->prologue_size   = 5;
        out->min_patch_size  = 5;
        out->has_pc_relative = false;
        return true;
    }

    return false;
}

// Pattern: SUB RSP only (leaf-ish functions or special calling convention)
static bool
match_sub_rsp(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 4) {
        return false;
    }

    size_t offset = 0;

    // sub rsp, imm8: 48 83 ec XX
    if (code[0] == 0x48 && code[1] == 0x83 && code[2] == 0xec) {
        offset = 4;
    }
    // sub rsp, imm32: 48 81 ec XX XX XX XX
    else if (avail >= 7 && code[0] == 0x48 && code[1] == 0x81 && code[2] == 0xec) {
        offset = 7;
    }

    if (offset == 0) {
        return false;
    }

    // Need at least 5 bytes for patch. If the sub rsp instruction is shorter,
    // we can't safely extend - we don't know what follows and it might be a
    // branch target or essential instruction. Reject instead of guessing.
    if (offset < 5) {
        return false;
    }

    out->matched         = true;
    out->pattern_name    = "x86_64_sub_rsp";
    out->prologue_size   = offset;
    out->min_patch_size  = 5;
    out->has_pc_relative = false;

    return true;
}

// Helper: Check if code at offset is a multi-byte NOP and return its length.
// Returns 0 if not a NOP.
static size_t
detect_nop(const uint8_t *code, size_t avail)
{
    if (avail < 1) {
        return 0;
    }

    // Single-byte NOP: 90
    if (code[0] == 0x90) {
        return 1;
    }

    // 2-byte NOP: 66 90
    if (avail >= 2 && code[0] == 0x66 && code[1] == 0x90) {
        return 2;
    }

    // Multi-byte NOPs use 0F 1F prefix
    if (avail >= 3 && code[0] == 0x0F && code[1] == 0x1F) {
        uint8_t modrm = code[2];

        // 3-byte NOP: 0F 1F 00 (mod=00, rm=000, no SIB, no disp)
        if (modrm == 0x00) {
            return 3;
        }

        // 4-byte NOP: 0F 1F 40 00 (mod=01, rm=000, disp8)
        if (avail >= 4 && modrm == 0x40) {
            return 4;
        }

        // 5-byte NOP: 0F 1F 44 00 00 (mod=01, rm=100/SIB, SIB=00, disp8)
        if (avail >= 5 && modrm == 0x44 && code[3] == 0x00) {
            return 5;
        }

        // 6-byte NOP: 66 0F 1F 44 00 00 - handled by 66 prefix check below

        // 7-byte NOP: 0F 1F 80 00 00 00 00 (mod=10, rm=000, disp32)
        if (avail >= 7 && modrm == 0x80) {
            return 7;
        }

        // 8-byte NOP: 0F 1F 84 00 xx xx xx xx (mod=10, rm=100/SIB, SIB, disp32)
        // This is the common clang NOP: nopl disp32(%rax,%rax,1)
        if (avail >= 8 && modrm == 0x84 && code[3] == 0x00) {
            return 8;
        }
    }

    // 6-byte NOP with 66 prefix: 66 0F 1F 44 00 00
    if (avail >= 6 && code[0] == 0x66 && code[1] == 0x0F && code[2] == 0x1F && code[3] == 0x44 && code[4] == 0x00) {
        return 6;
    }

    // 9-byte NOP: 66 0F 1F 84 00 xx xx xx xx
    if (avail >= 9 && code[0] == 0x66 && code[1] == 0x0F && code[2] == 0x1F && code[3] == 0x84 && code[4] == 0x00) {
        return 9;
    }

    return 0;
}

// Pattern: Patchable function entry (NOP sled from __attribute__((patchable_function_entry)))
static bool
match_patchable_entry(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 5) {
        return false;
    }

    // Count leading NOP bytes
    size_t offset = 0;

    while (offset < avail) {
        size_t nop_len = detect_nop(code + offset, avail - offset);
        if (nop_len == 0) {
            break;
        }
        offset += nop_len;
    }

    // Need at least 5 bytes for a rel32 jump
    if (offset < 5) {
        return false;
    }

    out->matched         = true;
    out->pattern_name    = "x86_64_patchable_entry";
    out->prologue_size   = offset;
    out->min_patch_size  = 5;
    out->has_pc_relative = false;

    return true;
}

static pattern_handler_t handler_frame_setup = {
    .name        = "x86_64_frame_setup",
    .description = "Standard frame setup: push rbp; mov rbp, rsp",
    .priority    = 100,
    .match       = match_frame_setup,
};

static pattern_handler_t handler_endbr64 = {
    .name        = "x86_64_endbr64",
    .description = "CET-enabled: endbr64 + prologue",
    .priority    = 110, // Try before standard frame
    .match       = match_endbr64,
};

static pattern_handler_t handler_no_frame = {
    .name        = "x86_64_no_frame",
    .description = "Optimized: callee-saved pushes without frame pointer",
    .priority    = 80,
    .match       = match_no_frame,
};

static pattern_handler_t handler_sub_rsp = {
    .name        = "x86_64_sub_rsp",
    .description = "Stack allocation: sub rsp, imm",
    .priority    = 70,
    .match       = match_sub_rsp,
};

static pattern_handler_t handler_patchable = {
    .name        = "x86_64_patchable_entry",
    .description = "Patchable function entry: NOP sled from patchable_function_entry attribute",
    .priority    = 150,
    .match       = match_patchable_entry,
};

void
pattern_init_x86_64(void)
{
    static bool initialized = false;
    if (initialized) {
        return;
    }
    initialized = true;

    pattern_register(&handler_patchable);
    pattern_register(&handler_frame_setup);
    pattern_register(&handler_endbr64);
    pattern_register(&handler_no_frame);
    pattern_register(&handler_sub_rsp);
}

#endif // PATCH_ARCH_X86_64
