#define _GNU_SOURCE

#include "watchpoint.h"

#include "platform/platform.h"

#include <signal.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include <sys/ucontext.h>
#else
#include <ucontext.h>
#endif

// =============================================================================
// Watchpoint Registry
// =============================================================================
//
// Maps watched addresses to their hook handles for O(1) lookup in signal handler.

#define WATCHPOINT_HASH_SIZE 16

typedef struct watchpoint_entry {
    void                    *addr;   // Watched pointer address (location)
    patch_handle_t          *handle; // Associated hook handle
    int                      wp_id;  // Hardware watchpoint ID (0-3)
    struct watchpoint_entry *next;   // Hash chain
} watchpoint_entry_t;

static watchpoint_entry_t *g_watchpoint_table[WATCHPOINT_HASH_SIZE];

// Simple hash function for addresses
static inline size_t
hash_addr(void *addr)
{
    uintptr_t a = (uintptr_t)addr;
    return (a * 2654435769UL) % WATCHPOINT_HASH_SIZE;
}

static void
watchpoint_registry_add(void *addr, patch_handle_t *handle, int wp_id)
{
    size_t              idx   = hash_addr(addr);
    watchpoint_entry_t *entry = malloc(sizeof(*entry));
    if (entry != nullptr) {
        entry->addr   = addr;
        entry->handle = handle;
        entry->wp_id  = wp_id;
        entry->next   = g_watchpoint_table[idx];
        g_watchpoint_table[idx] = entry;
    }
}

static void
watchpoint_registry_remove(void *addr)
{
    size_t               idx = hash_addr(addr);
    watchpoint_entry_t **pp  = &g_watchpoint_table[idx];

    while (*pp != nullptr) {
        if ((*pp)->addr == addr) {
            watchpoint_entry_t *to_free = *pp;
            *pp = to_free->next;
            free(to_free);
            return;
        }
        pp = &(*pp)->next;
    }
}

static watchpoint_entry_t *
watchpoint_registry_find_by_addr(void *addr)
{
    size_t idx = hash_addr(addr);

    for (watchpoint_entry_t *e = g_watchpoint_table[idx]; e != nullptr; e = e->next) {
        if (e->addr == addr) {
            return e;
        }
    }
    return nullptr;
}

#ifndef __APPLE__
static watchpoint_entry_t *
watchpoint_registry_find_by_id(int wp_id)
{
    for (size_t i = 0; i < WATCHPOINT_HASH_SIZE; i++) {
        for (watchpoint_entry_t *e = g_watchpoint_table[i]; e != nullptr; e = e->next) {
            if (e->wp_id == wp_id) {
                return e;
            }
        }
    }
    return nullptr;
}
// Find by address using the platform's watchpoint address lookup
// (Linux only - macOS uses watchpoint_registry_find_by_addr directly)
static watchpoint_entry_t *
watchpoint_registry_find(void *ucontext, int wp_id)
{
    // First try to find by watchpoint ID
    watchpoint_entry_t *entry = watchpoint_registry_find_by_id(wp_id);
    if (entry != nullptr) {
        return entry;
    }

    // Fall back to finding by address (from ucontext)
    void *addr = platform_get_watchpoint_addr(ucontext, wp_id);
    if (addr != nullptr) {
        return watchpoint_registry_find_by_addr(addr);
    }

    return nullptr;
}
#endif

// =============================================================================
// Watchpoint Handler (Platform-Specific)
// =============================================================================

static atomic_bool g_handler_installed = false;

#ifdef __APPLE__
// =============================================================================
// macOS: Mach Exception-based Handler
// =============================================================================
// On macOS, watchpoint exceptions are delivered via Mach exceptions.
// The platform layer handles the exception server thread and calls our callback.
// The callback runs in a DIFFERENT THREAD than the faulting code.
// The write instruction has NOT completed when we're called (we intercept it).

static int
mach_watchpoint_callback(int wp_id, thread_t thread, void *watched_addr,
                         void *old_value_from_platform, void *new_value)
{
    (void)wp_id;   // Platform layer handles watchpoint clearing
    (void)thread;
    (void)old_value_from_platform; // Platform passes current memory value (detour), we use handle's original

    // Find the watchpoint entry
    watchpoint_entry_t *entry = watchpoint_registry_find_by_addr(watched_addr);
    if (entry == nullptr || entry->handle == nullptr) {
        return 1; // REMOVE - unknown watchpoint, let the write proceed
    }

    patch_handle_t *handle = entry->handle;

    // The "old value" for the user callback is the original function pointer,
    // not the current memory value (which is our detour).
    void *old_value = handle->original_got_value;

    // Determine action
    patch_watch_action_t action = PATCH_WATCH_KEEP;

    if (handle->watch_callback != nullptr) {
        action = handle->watch_callback(handle,
                                        old_value,
                                        new_value,
                                        handle->watch_user_data);
    }

    // Return value tells platform layer what to do:
    // 0 = KEEP:   Skip the write, keep the hook
    // 1 = REMOVE: Let the write proceed, we'll clean up
    // 2 = REJECT: Skip the write, keep old value

    switch (action) {
    case PATCH_WATCH_KEEP:
        // Update cached original (the new value the caller wanted to write)
        // The detour stays in place (we skipped their write)
        handle->original_got_value = new_value;
        return 0; // Skip instruction

    case PATCH_WATCH_REMOVE:
        // Let the write proceed - platform layer clears watchpoint on faulting thread
        // We just clean up our tracking state
        watchpoint_registry_remove(watched_addr);
        handle->is_watchpoint_hook = false;
        handle->watchpoint_id = -1;
        return 1; // Let write proceed

    case PATCH_WATCH_REJECT:
        // Skip the write, keep detour and old original value
        return 2; // Skip instruction
    }

    return 0;
}

#else
// =============================================================================
// Linux: SIGTRAP-based Handler
// =============================================================================
// On Linux, watchpoint exceptions are delivered via SIGTRAP signal.
// The write instruction has COMPLETED when we're called.

static struct sigaction g_old_sigtrap_action;

static void
sigtrap_handler(int sig, siginfo_t *info, void *ucontext_raw)
{
    (void)sig;
    (void)info;

    // Check if this is a watchpoint hit
    int wp_id = platform_check_watchpoint_hit(ucontext_raw);

    if (wp_id >= 0) {
        // Find the watchpoint entry
        watchpoint_entry_t *entry = watchpoint_registry_find(ucontext_raw, wp_id);

        if (entry != nullptr && entry->handle != nullptr) {
            patch_handle_t *handle = entry->handle;

            // Read the new value that was written (write already completed on Linux)
            void *new_value = *(void **)handle->watched_location;

            // Get the old original value
            void *old_value = handle->original_got_value;

            // Determine action
            patch_watch_action_t action = PATCH_WATCH_KEEP;

            if (handle->watch_callback != nullptr) {
                action = handle->watch_callback(handle,
                                                old_value,
                                                new_value,
                                                handle->watch_user_data);
            }

            // Temporarily clear the watchpoint before writing to the watched location,
            // otherwise our write will trigger another watchpoint hit
            platform_clear_watchpoint(wp_id);

            switch (action) {
            case PATCH_WATCH_KEEP:
                // Update cached original and reinstall detour
                handle->original_got_value = new_value;
                *(void **)handle->watched_location = handle->detour_dest;
                // Re-enable watchpoint
                {
                    int new_wp_id =
                        platform_set_watchpoint(handle->watched_location,
                                                sizeof(void *),
                                                WATCHPOINT_WRITE);
                    handle->watchpoint_id = new_wp_id;
                    if (entry != nullptr && new_wp_id >= 0) {
                        entry->wp_id = new_wp_id;
                    }
                }
                break;

            case PATCH_WATCH_REMOVE:
                // Let the new value stand, watchpoint already cleared
                watchpoint_registry_remove(handle->watched_location);
                handle->is_watchpoint_hook = false;
                handle->watchpoint_id = -1;
                break;

            case PATCH_WATCH_REJECT:
                // Reinstall detour with old original (ignore the update)
                *(void **)handle->watched_location = handle->detour_dest;
                // Re-enable watchpoint
                {
                    int new_wp_id =
                        platform_set_watchpoint(handle->watched_location,
                                                sizeof(void *),
                                                WATCHPOINT_WRITE);
                    handle->watchpoint_id = new_wp_id;
                    if (entry != nullptr && new_wp_id >= 0) {
                        entry->wp_id = new_wp_id;
                    }
                }
                break;
            }

            return;
        }
    }

    // Not our watchpoint - chain to previous handler
    if (g_old_sigtrap_action.sa_flags & SA_SIGINFO) {
        if (g_old_sigtrap_action.sa_sigaction != nullptr) {
            g_old_sigtrap_action.sa_sigaction(sig, info, ucontext_raw);
        }
    }
    else if (g_old_sigtrap_action.sa_handler != SIG_IGN &&
             g_old_sigtrap_action.sa_handler != SIG_DFL) {
        g_old_sigtrap_action.sa_handler(sig);
    }
}
#endif // __APPLE__

// =============================================================================
// Public API
// =============================================================================

patch_error_t
patch__watchpoint_init(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_handler_installed, &expected, true)) {
        // Already initialized
        return PATCH_SUCCESS;
    }

#ifdef __APPLE__
    // On macOS, register our callback with the platform layer.
    // The Mach exception handler is started automatically when the first
    // watchpoint is set via platform_set_watchpoint().
    platform_set_watchpoint_callback(mach_watchpoint_callback);
    return PATCH_SUCCESS;
#else
    // On Linux, use SIGTRAP signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigtrap_handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTRAP, &sa, &g_old_sigtrap_action) != 0) {
        atomic_store(&g_handler_installed, false);
        patch__set_error("failed to install SIGTRAP handler for watchpoints");
        return PATCH_ERR_SIGNAL_HANDLER;
    }

    return PATCH_SUCCESS;
#endif
}

void
patch__watchpoint_cleanup(void)
{
    bool expected = true;
    if (!atomic_compare_exchange_strong(&g_handler_installed, &expected, false)) {
        return;
    }

#ifdef __APPLE__
    // On macOS, just clear the callback
    platform_set_watchpoint_callback(NULL);
#else
    // On Linux, restore the old signal handler
    sigaction(SIGTRAP, &g_old_sigtrap_action, nullptr);
#endif
}

patch_error_t
patch__watchpoint_install(patch_handle_t *handle)
{
    if (handle == nullptr || handle->watched_location == nullptr ||
        handle->detour_dest == nullptr) {
        patch__set_error("invalid handle for watchpoint install");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Initialize watchpoint subsystem
    patch_error_t err = patch__watchpoint_init();
    if (err != PATCH_SUCCESS) {
        return err;
    }

    void **location    = handle->watched_location;
    void  *replacement = handle->detour_dest;

    // Save the original value
    handle->original_got_value = *location;

    // Write our replacement
    *location = replacement;

    // Set up hardware watchpoint on the location
    int wp_id = platform_set_watchpoint(location, sizeof(void *), WATCHPOINT_WRITE);
    if (wp_id < 0) {
        // Restore original value
        *location = handle->original_got_value;
        patch__set_error("failed to set hardware watchpoint");
        return PATCH_ERR_NO_WATCHPOINT;
    }

    // Add to registry
    watchpoint_registry_add(location, handle, wp_id);
    handle->is_watchpoint_hook = true;
    handle->watchpoint_id      = wp_id;

    return PATCH_SUCCESS;
}

patch_error_t
patch__watchpoint_remove(patch_handle_t *handle)
{
    if (handle == nullptr || !handle->is_watchpoint_hook) {
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Clear hardware watchpoint
    platform_clear_watchpoint(handle->watchpoint_id);

    // Remove from registry
    watchpoint_registry_remove(handle->watched_location);

    // Restore original value
    *(void **)handle->watched_location = handle->original_got_value;

    handle->is_watchpoint_hook = false;
    handle->watchpoint_id      = -1;

    return PATCH_SUCCESS;
}

patch_error_t
patch__watchpoint_enable(patch_handle_t *handle)
{
    if (handle == nullptr || !handle->is_watchpoint_hook) {
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Write our replacement (may have been disabled)
    *(void **)handle->watched_location = handle->detour_dest;

    // Re-enable watchpoint (in case it was disabled)
    int wp_id = platform_set_watchpoint(handle->watched_location,
                                        sizeof(void *),
                                        WATCHPOINT_WRITE);
    if (wp_id < 0) {
        return PATCH_ERR_NO_WATCHPOINT;
    }

    handle->watchpoint_id = wp_id;

    return PATCH_SUCCESS;
}

patch_error_t
patch__watchpoint_disable(patch_handle_t *handle)
{
    if (handle == nullptr || !handle->is_watchpoint_hook) {
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Clear watchpoint temporarily
    platform_clear_watchpoint(handle->watchpoint_id);

    // Restore original value so calls bypass the hook
    *(void **)handle->watched_location = handle->original_got_value;

    return PATCH_SUCCESS;
}
