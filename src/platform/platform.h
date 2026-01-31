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

// Write to code memory (handles platform-specific protections).
// This is the preferred method for patching code on platforms with
// strict memory protection (e.g., macOS with hardened runtime).
patch_error_t platform_write_code(void *addr, const void *data, size_t size);

// Find the GOT entry for a symbol.
// Returns PATCH_SUCCESS and sets *got_entry to the GOT slot address if found.
// Returns PATCH_ERR_NO_GOT_ENTRY if the symbol has no GOT entry.
// The symbol must be an imported function (called through PLT/GOT).
patch_error_t platform_find_got_entry(const char *symbol, void ***got_entry);

// =============================================================================
// Hardware Watchpoint Support
// =============================================================================

// Maximum number of hardware watchpoints available
// x86-64: 4 (DR0-DR3)
// ARM64: typically 4 (implementation-defined, 2-16)
#define PLATFORM_MAX_WATCHPOINTS 4

// Watchpoint type
typedef enum {
    WATCHPOINT_WRITE = 1,      // Trigger on write only
    WATCHPOINT_READWRITE = 3,  // Trigger on read or write
} watchpoint_type_t;

// Set a hardware watchpoint on an address.
// Returns watchpoint ID (0-3) on success, or -1 on error.
// Sets PATCH_ERR_NO_WATCHPOINT if all watchpoints are in use.
// The size must be 1, 2, 4, or 8 bytes and addr must be naturally aligned.
int platform_set_watchpoint(void *addr, size_t size, watchpoint_type_t type);

// Clear a hardware watchpoint by ID.
// Returns PATCH_SUCCESS on success.
patch_error_t platform_clear_watchpoint(int watchpoint_id);

// Check if a watchpoint was hit and return its ID.
// Called from signal handler context (Linux) or not used (macOS with Mach exceptions).
// Returns watchpoint ID (0-3) if a watchpoint triggered, or -1 if not.
int platform_check_watchpoint_hit(void *ucontext);

// Get the address that triggered the watchpoint.
// Called from signal handler context after platform_check_watchpoint_hit returns >= 0.
void *platform_get_watchpoint_addr(void *ucontext, int watchpoint_id);

#ifdef __APPLE__
// macOS-specific: Register callback for watchpoint hits.
// The callback is invoked from a dedicated exception handler thread (not signal context).
// Note: On macOS, watchpoint exceptions are delivered via Mach exceptions, not signals.
// The callback runs in a separate thread, NOT the faulting thread.
//
// Callback parameters:
//   wp_id        - which watchpoint was hit (0-3)
//   thread       - the faulting thread (suspended during callback)
//   watched_addr - the address being watched
//   old_value    - the current value at that address (before the write)
//   new_value    - the value being written (decoded from registers)
//
// Callback returns:
//   0 = KEEP:   Skip the write, keep the hook. Caller should update original_value.
//   1 = REMOVE: Let the write proceed, remove the watchpoint.
//   2 = REJECT: Skip the write, keep the old value. Hook stays with same original.
//
// Note: For KEEP and REJECT, the write instruction is skipped (PC advanced).
//       For REMOVE, the write instruction proceeds normally.
#include <mach/mach.h>
typedef int (*platform_watchpoint_callback_t)(int wp_id, thread_t thread, void *watched_addr,
                                              void *old_value, void *new_value);
void platform_set_watchpoint_callback(platform_watchpoint_callback_t callback);
#endif
