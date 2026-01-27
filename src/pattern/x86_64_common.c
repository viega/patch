#include "pattern.h"

#include "patch/patch_arch.h"

#ifdef PATCH_ARCH_X86_64

// Common x86-64 prologue patterns for both GCC and Clang

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
        if (code[offset] == 0x48 && code[offset + 1] == 0x83 &&
            code[offset + 2] == 0xec) {
            offset += 4;
        }
        // sub rsp, imm32: 48 81 ec XX XX XX XX
        else if (avail >= offset + 7 && code[offset] == 0x48 &&
                 code[offset + 1] == 0x81 && code[offset + 2] == 0xec) {
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

    out->matched        = true;
    out->pattern_name   = "x86_64_frame_setup";
    out->prologue_size  = offset;
    out->min_patch_size = 5;  // JMP rel32
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
            if (avail >= offset + 4 && code[offset + 1] == 0x48 &&
                code[offset + 2] == 0x89 && code[offset + 3] == 0xe5) {
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
    if (code[0] != 0xf3 || code[1] != 0x0f || code[2] != 0x1e ||
        code[3] != 0xfa) {
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
    else if (avail >= 7 && code[0] == 0x48 && code[1] == 0x81 &&
             code[2] == 0xec) {
        offset = 7;
    }

    if (offset == 0) {
        return false;
    }

    // Need at least 5 bytes for patch
    if (offset < 5) {
        // Look for more instructions to reach 5 bytes
        while (offset < 5 && offset < avail) {
            // Just include the next bytes if they look safe
            // This is conservative - we might miss some patterns
            offset++;
        }
    }

    out->matched         = true;
    out->pattern_name    = "x86_64_sub_rsp";
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
    .priority    = 110,  // Try before standard frame
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

// Pattern: Patchable function entry (NOP sled from __attribute__((patchable_function_entry)))
static bool
match_patchable_entry(const uint8_t *code, size_t avail, pattern_match_t *out)
{
    if (avail < 5) {
        return false;
    }

    // Count leading NOPs (0x90) or multi-byte NOPs
    size_t offset = 0;

    while (offset < avail) {
        if (code[offset] == 0x90) {
            // Single-byte NOP
            offset++;
        }
        else if (offset + 2 <= avail && code[offset] == 0x66 &&
                 code[offset + 1] == 0x90) {
            // 2-byte NOP (66 90)
            offset += 2;
        }
        else if (offset + 3 <= avail && code[offset] == 0x0F &&
                 code[offset + 1] == 0x1F && code[offset + 2] == 0x00) {
            // 3-byte NOP (0F 1F 00)
            offset += 3;
        }
        else if (offset + 4 <= avail && code[offset] == 0x0F &&
                 code[offset + 1] == 0x1F &&
                 code[offset + 2] == 0x40 && code[offset + 3] == 0x00) {
            // 4-byte NOP (0F 1F 40 00)
            offset += 4;
        }
        else if (offset + 5 <= avail && code[offset] == 0x0F &&
                 code[offset + 1] == 0x1F &&
                 code[offset + 2] == 0x44 && code[offset + 3] == 0x00 &&
                 code[offset + 4] == 0x00) {
            // 5-byte NOP (0F 1F 44 00 00)
            offset += 5;
        }
        else {
            break;
        }
    }

    // Need at least 5 bytes for a rel32 jump, or 13 for absolute
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
    if (initialized) return;
    initialized = true;

    pattern_register(&handler_patchable);
    pattern_register(&handler_frame_setup);
    pattern_register(&handler_endbr64);
    pattern_register(&handler_no_frame);
    pattern_register(&handler_sub_rsp);
}

#endif  // PATCH_ARCH_X86_64
