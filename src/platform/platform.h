#pragma once

#include "patch/patch.h"

#include <stddef.h>

typedef enum {
    MEM_PROT_NONE,
    MEM_PROT_R,
    MEM_PROT_RW,
    MEM_PROT_RX,
    MEM_PROT_RWX,
} mem_prot_t;

// Change memory protection for a region.
patch_error_t platform_protect(void *addr, size_t size, mem_prot_t prot);

// Get current protection for an address.
patch_error_t platform_get_protection(void *addr, mem_prot_t *out_prot);

// Allocate executable memory near target (for trampolines).
// On x86-64, tries to allocate within 2GB of target for rel32 jumps.
patch_error_t platform_alloc_near(void *target, size_t size, void **out);

// Free executable memory.
void platform_free_exec(void *addr, size_t size);

// Flush instruction cache (required on ARM64, no-op on x86-64).
void platform_flush_icache(void *addr, size_t size);

// Get page size.
size_t platform_page_size(void);

// Align address down to page boundary.
void *platform_page_align(void *addr);
