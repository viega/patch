#pragma once

#include "patch/patch.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Decoded instruction info
typedef struct {
    size_t length;
    bool   is_pc_relative;
    bool   is_branch;
    bool   is_call;
    bool   is_return;
} arch_insn_t;

// Decode a single instruction at the given address
// Returns instruction length, or 0 on failure
size_t arch_decode_insn(const uint8_t *code, size_t avail, arch_insn_t *out);

// Relocate instructions from src to dst, adjusting PC-relative references
// Returns number of bytes written to dst, or 0 on failure
size_t arch_relocate(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_avail, uintptr_t src_addr, uintptr_t dst_addr);

// Write a detour jump from src to dst
// Returns number of bytes written, or 0 on failure
size_t arch_write_jump(uint8_t *dst, size_t dst_avail, uintptr_t src_addr, uintptr_t dst_addr);

// Get minimum prologue size needed for a detour
size_t arch_min_prologue_size(void);
