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

// =============================================================================
// Unified Watchpoint Callback API (Cross-Platform)
// =============================================================================
//
// Both macOS (Mach exceptions) and Linux (SIGTRAP) use this unified callback API.
// The platform layer handles the low-level details and calls the registered callback.
//
// Key semantic difference handled by platform layer:
// - macOS: Write has NOT completed when callback is called (intercepted)
// - Linux: Write HAS completed when callback is called (post-facto)
//
// The callback sees the same interface regardless of platform.

// Watchpoint callback action
typedef enum {
    PLATFORM_WP_KEEP = 0,    // Keep hook active, update original to new_value
    PLATFORM_WP_REMOVE = 1,  // Remove hook, let new value stand
    PLATFORM_WP_REJECT = 2,  // Keep hook, reject the write (keep old original)
} platform_wp_action_t;

// Main watchpoint callback
// Called when a watched address is written to.
//
// Parameters:
//   watched_addr  - the address being watched
//   new_value     - the value being written (or already written on Linux)
//   restore_value - OUT: for KEEP/REJECT, set to value to restore (e.g., detour)
//
// Returns: action for platform to take
typedef platform_wp_action_t (*platform_watchpoint_callback_t)(
    void *watched_addr,
    void *new_value,
    void **restore_value
);

// ID update callback
// Called after platform re-establishes watchpoint (Linux KEEP/REJECT).
// On macOS, the watchpoint ID doesn't change, so this may not be called.
//
// Parameters:
//   watched_addr - the address being watched
//   new_wp_id    - the new watchpoint ID after re-establishment
typedef void (*platform_watchpoint_id_update_t)(
    void *watched_addr,
    int new_wp_id
);

// Register callbacks for watchpoint events.
// Must be called before platform_watchpoint_init().
// Pass NULL for id_update if not needed.
void platform_set_watchpoint_callback(
    platform_watchpoint_callback_t callback,
    platform_watchpoint_id_update_t id_update
);

// Initialize watchpoint subsystem.
// On macOS: starts Mach exception handler thread.
// On Linux: installs SIGTRAP signal handler.
// Returns PATCH_SUCCESS on success.
patch_error_t platform_watchpoint_init(void);

// Cleanup watchpoint subsystem.
// Restores previous signal handler (Linux) or stops exception thread (macOS).
void platform_watchpoint_cleanup(void);
