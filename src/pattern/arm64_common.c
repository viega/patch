#include "pattern.h"

#include "patch/patch_arch.h"

#ifdef PATCH_ARCH_ARM64

// ARM64 instruction encoding helpers
static inline uint32_t
read_insn(const uint8_t *code)
{
    return (uint32_t)code[0] | ((uint32_t)code[1] << 8) |
           ((uint32_t)code[2] << 16) | ((uint32_t)code[3] << 24);
}

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
    // Mask: 0xFF C0 03 FF -> check opc and Rd, Rn fields
    // But we need to allow any imm12 value
    // Format: sf=1, op=1, S=0, 100010, shift, imm12, Rn, Rd
    // For SUB sp, sp, #imm: opcode bits are 1101 0001 00xx xxxx xxxx xx11 1111 1111
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
    if ((insn & 0x7FC00000) != 0x29000000 &&  // STP signed offset
        (insn & 0x7FC00000) != 0x29800000) {  // STP pre-index
        return false;
    }
    uint32_t rt = insn & 0x1F;
    // x19-x28 are callee-saved
    return (rt >= 19 && rt <= 28);
}

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
    out->min_patch_size  = 4;  // Single branch
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

    // Try to match rest as frame_setup
    pattern_match_t sub = {0};
    if (match_frame_setup(code + 4, avail - 4, &sub)) {
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

    // Try to match rest as frame_setup or PAC
    pattern_match_t sub = {0};
    if (match_pac(code + 4, avail - 4, &sub) ||
        match_frame_setup(code + 4, avail - 4, &sub)) {
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
        if (insn == 0xD503201F) {  // NOP
            nop_count++;
            offset += 4;
        }
        else {
            break;
        }
    }

    // Need at least 4 NOPs (16 bytes) to be useful for patching
    // This gives us room for: ldr x16, [pc, #8]; br x16; .quad addr
    if (nop_count < 4) {
        return false;
    }

    out->matched         = true;
    out->pattern_name    = "arm64_patchable_entry";
    out->prologue_size   = offset;
    out->min_patch_size  = 4;
    out->has_pc_relative = false;

    return true;
}

static pattern_handler_t handler_patchable = {
    .name        = "arm64_patchable_entry",
    .description = "Patchable function entry: NOP sled from patchable_function_entry attribute",
    .priority    = 150,  // Highest priority - explicit opt-in
    .match       = match_patchable_entry,
};

void
pattern_init_arm64(void)
{
    static bool initialized = false;
    if (initialized) return;
    initialized = true;

    pattern_register(&handler_patchable);
    pattern_register(&handler_frame_setup);
    pattern_register(&handler_pac);
    pattern_register(&handler_bti);
    pattern_register(&handler_leaf);
}

#endif  // PATCH_ARCH_ARM64
