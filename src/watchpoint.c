#define _GNU_SOURCE

#include "watchpoint.h"

#include "platform/platform.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

// =============================================================================
// Watchpoint Registry
// =============================================================================
//
// Maps watched addresses to their hook handles for O(1) lookup in callbacks.

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

// =============================================================================
// Unified Watchpoint Callback (Platform-Agnostic)
// =============================================================================

static atomic_bool g_handler_installed = false;

// Unified callback for watchpoint hits - called by platform layer
static platform_wp_action_t
watchpoint_callback(void *watched_addr, void *new_value, void **restore_value)
{
    watchpoint_entry_t *entry = watchpoint_registry_find_by_addr(watched_addr);
    if (entry == nullptr || entry->handle == nullptr) {
        // Unknown watchpoint - let it proceed (REMOVE)
        return PLATFORM_WP_REMOVE;
    }

    patch_handle_t *handle = entry->handle;

    // The "old value" for the user callback is the original function pointer,
    // not the current memory value (which is our detour).
    void *old_value = handle->original_got_value;

    // Determine action via user callback
    patch_watch_action_t action = PATCH_WATCH_KEEP;

    if (handle->watch_callback != nullptr) {
        action = handle->watch_callback(handle,
                                        old_value,
                                        new_value,
                                        handle->watch_user_data);
    }

    switch (action) {
    case PATCH_WATCH_KEEP:
        // Update cached original (the new value the caller wanted to write)
        // The detour stays in place
        handle->original_got_value = new_value;
        *restore_value = handle->detour_dest;
        return PLATFORM_WP_KEEP;

    case PATCH_WATCH_REMOVE:
        // Clean up our tracking state
        watchpoint_registry_remove(watched_addr);
        handle->is_watchpoint_hook = false;
        handle->watchpoint_id = -1;
        return PLATFORM_WP_REMOVE;

    case PATCH_WATCH_REJECT:
        // Keep detour and old original value
        *restore_value = handle->detour_dest;
        return PLATFORM_WP_REJECT;
    }

    // Default: keep
    *restore_value = handle->detour_dest;
    return PLATFORM_WP_KEEP;
}

// ID update callback - called by platform after watchpoint re-establishment (Linux)
static void
watchpoint_id_update(void *watched_addr, int new_wp_id)
{
    watchpoint_entry_t *entry = watchpoint_registry_find_by_addr(watched_addr);
    if (entry != nullptr) {
        entry->wp_id = new_wp_id;
        if (entry->handle != nullptr) {
            entry->handle->watchpoint_id = new_wp_id;
        }
    }
}

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

    // Register callbacks with platform layer
    platform_set_watchpoint_callback(watchpoint_callback, watchpoint_id_update);

    // Initialize platform watchpoint subsystem
    patch_error_t err = platform_watchpoint_init();
    if (err != PATCH_SUCCESS) {
        platform_set_watchpoint_callback(NULL, NULL);
        atomic_store(&g_handler_installed, false);
        return err;
    }

    return PATCH_SUCCESS;
}

void
patch__watchpoint_cleanup(void)
{
    bool expected = true;
    if (!atomic_compare_exchange_strong(&g_handler_installed, &expected, false)) {
        return;
    }

    platform_watchpoint_cleanup();
    platform_set_watchpoint_callback(NULL, NULL);
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

    // Update registry with new ID
    watchpoint_entry_t *entry = watchpoint_registry_find_by_addr(handle->watched_location);
    if (entry != nullptr) {
        entry->wp_id = wp_id;
    }

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
