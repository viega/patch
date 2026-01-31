#include "patch_internal.h"

#include "arch/arch.h"
#include "futex.h"
#include "pattern/pattern.h"
#include "platform/platform.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Thread-local error message storage
static _Thread_local char g_error_buffer[PATCH_ERROR_BUFFER_SIZE];

// Global mutex for thread-safe install/remove/enable/disable operations.
// This protects against concurrent modifications but does NOT protect against
// a thread executing in a hook while another thread removes it. For that level
// of safety, users should ensure no threads are calling the hooked function
// during removal, or use appropriate synchronization in their code.
static futex_mutex_t g_patch_mutex = FUTEX_MUTEX_INIT;

// One-time initialization
static futex_once_t g_init_once = FUTEX_ONCE_INIT;

void
patch__set_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vsnprintf(g_error_buffer, sizeof(g_error_buffer), fmt, args);
    va_end(args);
}

const char *
patch_get_error_details(void)
{
    return g_error_buffer;
}

// Dispatcher stub that gets called when hooked function is entered
// This is architecture-specific assembly that:
// 1. Saves all argument registers
// 2. Creates a patch_context_t
// 3. Calls the prologue callback
// 4. Based on result, either jumps to trampoline or returns early
// 5. After trampoline returns, calls epilogue callback
// 6. Returns to caller

static void
do_initialize(void)
{
    if (!pattern_init_defaults()) {
        // This should never happen - patterns are compiled in.
        // Log for debugging but continue - patch_can_install will fail gracefully.
        patch__set_error("pattern initialization failed (no handlers registered)");
    }
}

static void
ensure_initialized(void)
{
    futex_once(&g_init_once, do_initialize);
}

// ============================================================================
// Hook Chain Registry
// ============================================================================
//
// Tracks all installed hooks by target address. When multiple hooks are
// installed on the same target, they form a chain. The most recently
// installed hook runs first.
//
// This is a simple linked list since the number of distinct targets is
// typically small. The mutex must be held when accessing the registry.

typedef struct registry_entry {
    void                  *target;       // Target function address
    patch_handle_t        *first_hook;   // First (most recent) hook in chain
    struct registry_entry *next;         // Next registry entry
} registry_entry_t;

static registry_entry_t *g_registry = nullptr;

// Find the registry entry for a target (caller must hold mutex)
static registry_entry_t *
find_registry_entry(void *target)
{
    for (registry_entry_t *e = g_registry; e != nullptr; e = e->next) {
        if (e->target == target) {
            return e;
        }
    }
    return nullptr;
}

patch_handle_t *
patch__registry_find(void *target)
{
    registry_entry_t *entry = find_registry_entry(target);
    return entry ? entry->first_hook : nullptr;
}

void
patch__registry_add(patch_handle_t *handle)
{
    registry_entry_t *entry = find_registry_entry(handle->target);

    if (entry == nullptr) {
        // First hook for this target - create new entry
        entry = calloc(1, sizeof(*entry));
        if (entry == nullptr) {
            return;  // Allocation failure - hook works but not tracked
        }
        entry->target     = handle->target;
        entry->first_hook = handle;
        entry->next       = g_registry;
        g_registry        = entry;

        handle->chain_next = nullptr;
        handle->chain_prev = nullptr;
    }
    else {
        // Add to front of existing chain
        handle->chain_next = entry->first_hook;
        handle->chain_prev = nullptr;
        if (entry->first_hook != nullptr) {
            entry->first_hook->chain_prev = handle;
        }
        entry->first_hook = handle;
    }
}

void
patch__registry_remove(patch_handle_t *handle)
{
    registry_entry_t *entry = find_registry_entry(handle->target);
    if (entry == nullptr) {
        return;
    }

    // Update chain links
    if (handle->chain_prev != nullptr) {
        handle->chain_prev->chain_next = handle->chain_next;
    }
    else {
        // Removing first hook in chain
        entry->first_hook = handle->chain_next;
    }

    if (handle->chain_next != nullptr) {
        handle->chain_next->chain_prev = handle->chain_prev;
    }

    // If chain is now empty, remove registry entry
    if (entry->first_hook == nullptr) {
        registry_entry_t **pp = &g_registry;
        while (*pp != nullptr && *pp != entry) {
            pp = &(*pp)->next;
        }
        if (*pp == entry) {
            *pp = entry->next;
            free(entry);
        }
    }

    handle->chain_next = nullptr;
    handle->chain_prev = nullptr;
}

void *
patch__get_chain_next(patch_handle_t *handle)
{
    // If there's another hook in the chain, return its dispatcher
    if (handle->chain_next != nullptr && handle->chain_next->dispatcher != nullptr) {
        return handle->chain_next->dispatcher;
    }
    // Otherwise return the trampoline (original function)
    return handle->trampoline->code;
}

patch_error_t
patch_can_install(void *target)
{
    ensure_initialized();

    if (target == nullptr) {
        patch__set_error("target is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Try to read from target to ensure it's accessible
    mem_prot_t    prot;
    patch_error_t err = platform_get_protection(target, &prot);
    if (err != PATCH_SUCCESS) {
        patch__set_error("Cannot determine protection of target address");
        return err;
    }

    if (prot == MEM_PROT_NONE) {
        patch__set_error("Target address is not readable");
        return PATCH_ERR_MEMORY_PROTECTION;
    }

    // Try to match prologue pattern
    pattern_match_t match = pattern_match_prologue((const uint8_t *)target, 64);
    if (!match.matched) {
        patch__set_error("No recognized prologue pattern at target");
        return PATCH_ERR_PATTERN_UNRECOGNIZED;
    }

    if (match.prologue_size < match.min_patch_size) {
        patch__set_error("Prologue too small: %zu bytes, need %zu",
                         match.prologue_size,
                         match.min_patch_size);
        return PATCH_ERR_INSUFFICIENT_SPACE;
    }

    return PATCH_SUCCESS;
}

patch_error_t
patch_install(const patch_config_t *config, patch_handle_t **handle)
{
    ensure_initialized();

    if (config == nullptr || handle == nullptr) {
        patch__set_error("config or handle is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    *handle = nullptr;

    if (config->target == nullptr) {
        patch__set_error("config->target is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Validate mode: either simple replacement OR callbacks, not both
    bool has_replacement = config->replacement != nullptr;
    bool has_callbacks   = config->prologue != nullptr || config->epilogue != nullptr;

    if (has_replacement && has_callbacks) {
        patch__set_error("Cannot specify both replacement and prologue/epilogue callbacks");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (!has_replacement && !has_callbacks) {
        patch__set_error("Must specify either replacement or at least one callback");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Acquire lock for thread-safe installation
    futex_mutex_lock(&g_patch_mutex);

    // Check if this target already has hooks installed (for chaining)
    patch_handle_t *existing = patch__registry_find(config->target);

    // Match prologue pattern - only needed for first hook on a target
    // When chaining, we reuse the match info from the existing hook
    pattern_match_t match;
    if (existing != nullptr) {
        // Chaining: reuse prologue info from existing hook
        match.matched        = true;
        match.prologue_size  = existing->patch_size;
        match.min_patch_size = existing->patch_size;
        match.has_pc_relative = true;  // Assume yes for safety when chaining
    }
    else {
        // First hook: match the actual prologue
        match = pattern_match_prologue((const uint8_t *)config->target, 64);
        if (!match.matched) {
            patch__set_error("No recognized prologue pattern at target");
            futex_mutex_unlock(&g_patch_mutex);
            return PATCH_ERR_PATTERN_UNRECOGNIZED;
        }
    }

    // Create handle
    patch_handle_t *h = calloc(1, sizeof(*h));
    if (h == nullptr) {
        patch__set_error("Failed to allocate handle");
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_ERR_ALLOCATION_FAILED;
    }

    h->target             = config->target;
    h->prologue           = config->prologue;
    h->epilogue           = config->epilogue;
    h->prologue_user_data = config->prologue_user_data;
    h->epilogue_user_data = config->epilogue_user_data;
    h->patch_size         = match.prologue_size;
    atomic_store(&h->enabled, true);

#ifdef PATCH_HAVE_LIBFFI
    h->ffi_cif       = nullptr;
    h->ffi_arg_types = nullptr;
    h->ffi_ret_type  = nullptr;
    h->ffi_arg_count = 0;

    if (config->arg_types != nullptr && config->arg_count > 0) {
        h->ffi_arg_count = config->arg_count;
        h->ffi_arg_types = calloc(config->arg_count, sizeof(ffi_type *));
        if (h->ffi_arg_types == nullptr) {
            patch__set_error("Failed to allocate FFI argument types");
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return PATCH_ERR_ALLOCATION_FAILED;
        }
        memcpy(h->ffi_arg_types, config->arg_types, config->arg_count * sizeof(ffi_type *));

        h->ffi_ret_type = config->return_type ? config->return_type : &ffi_type_uint64;

        h->ffi_cif = malloc(sizeof(ffi_cif));
        if (h->ffi_cif == nullptr) {
            patch__set_error("Failed to allocate FFI CIF");
            free(h->ffi_arg_types);
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return PATCH_ERR_ALLOCATION_FAILED;
        }

        if (ffi_prep_cif(h->ffi_cif, FFI_DEFAULT_ABI, (unsigned int)h->ffi_arg_count,
                         h->ffi_ret_type, h->ffi_arg_types) != FFI_OK) {
            patch__set_error("Failed to prepare FFI call interface");
            free(h->ffi_cif);
            free(h->ffi_arg_types);
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return PATCH_ERR_INTERNAL;
        }
    }
#endif

    patch_error_t err;

    if (existing != nullptr) {
        // Chaining onto existing hook - copy original bytes from existing chain
        // (the target is already patched with a detour)
        memcpy(h->original_bytes, existing->original_bytes, match.prologue_size);
        h->original_prot = existing->original_prot;

        // Each hook in chain gets its own trampoline for simplicity
        // (alternative: share trampoline but that complicates ownership)
        err = patch__trampoline_create(config->target,
                                       match.prologue_size,
                                       match.has_pc_relative,
                                       &h->trampoline);
        if (err != PATCH_SUCCESS) {
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }
    }
    else {
        // First hook on this target - save original bytes
        memcpy(h->original_bytes, config->target, match.prologue_size);

        // Get original protection
        err = platform_get_protection(config->target, &h->original_prot);
        if (err != PATCH_SUCCESS) {
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }

        // Create trampoline (holds relocated prologue + jump back to original)
        // For NOP sleds (patchable_function_entry), skip relocation since NOPs have no
        // PC-relative references. The has_pc_relative flag tells us if we need relocation.
        err = patch__trampoline_create(config->target,
                                       match.prologue_size,
                                       match.has_pc_relative,
                                       &h->trampoline);
        if (err != PATCH_SUCCESS) {
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }
    }

    // Determine detour destination based on mode
    void *detour_dest;

    if (has_replacement) {
        // Simple mode: jump directly to replacement function (no dispatcher)
        detour_dest   = config->replacement;
        h->dispatcher = nullptr;
    }
    else {
        // Callback mode: create dispatcher that invokes callbacks
        err = patch__dispatcher_create(h, &h->dispatcher);
        if (err != PATCH_SUCCESS) {
            patch__trampoline_destroy(h->trampoline);
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }
        detour_dest = h->dispatcher;
    }
    h->detour_dest = detour_dest;

    // Add to registry (sets up chain links)
    patch__registry_add(h);

    // Write the detour at the original function (always update, even when chaining)
    err = patch__write_detour(config->target, detour_dest, match.prologue_size);
    if (err != PATCH_SUCCESS) {
        patch__registry_remove(h);
        if (h->dispatcher != nullptr) {
            patch__dispatcher_destroy(h->dispatcher);
        }
        patch__trampoline_destroy(h->trampoline);
        free(h);
        futex_mutex_unlock(&g_patch_mutex);
        return err;
    }

    *handle = h;
    futex_mutex_unlock(&g_patch_mutex);
    return PATCH_SUCCESS;
}

patch_error_t
patch_remove(patch_handle_t *handle)
{
    if (handle == nullptr) {
        patch__set_error("handle is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    futex_mutex_lock(&g_patch_mutex);

    // Check if this is the first hook in the chain (the one the detour points to)
    patch_handle_t *first_in_chain = patch__registry_find(handle->target);
    bool            is_first       = (first_in_chain == handle);

    // Remove from registry (updates chain links)
    patch__registry_remove(handle);

    // Update detour or restore original bytes
    patch_error_t err = PATCH_SUCCESS;
    if (is_first) {
        // We were the first hook - need to update the detour
        patch_handle_t *new_first = patch__registry_find(handle->target);
        if (new_first != nullptr) {
            // Chain continues - point detour to next hook's dispatcher
            err = patch__write_detour(handle->target,
                                      new_first->detour_dest,
                                      handle->patch_size);
        }
        else {
            // Chain empty - restore original bytes
            err = patch__restore_bytes(handle->target,
                                       handle->original_bytes,
                                       handle->patch_size);
        }

        if (err != PATCH_SUCCESS) {
            // Re-add to registry on failure (try to maintain consistency)
            patch__registry_add(handle);
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }
    }
    // If not first, we just removed from chain - detour still valid

    // Free dispatcher (may be nullptr in simple replacement mode)
    if (handle->dispatcher != nullptr) {
        patch__dispatcher_destroy(handle->dispatcher);
    }
    patch__trampoline_destroy(handle->trampoline);

#ifdef PATCH_HAVE_LIBFFI
    if (handle->ffi_cif != nullptr) {
        free(handle->ffi_cif);
    }
    if (handle->ffi_arg_types != nullptr) {
        free(handle->ffi_arg_types);
    }
#endif

    // Free handle
    free(handle);

    futex_mutex_unlock(&g_patch_mutex);
    return PATCH_SUCCESS;
}

patch_error_t
patch_disable(patch_handle_t *handle)
{
    if (handle == nullptr) {
        patch__set_error("handle is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    futex_mutex_lock(&g_patch_mutex);

    // Idempotent: calling disable on an already-disabled patch succeeds silently.
    // This simplifies caller logic and matches common expectations.
    if (!atomic_load(&handle->enabled)) {
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Restore original bytes
    patch_error_t err = patch__restore_bytes(handle->target,
                                             handle->original_bytes,
                                             handle->patch_size);
    if (err != PATCH_SUCCESS) {
        futex_mutex_unlock(&g_patch_mutex);
        return err;
    }

    atomic_store(&handle->enabled, false);
    futex_mutex_unlock(&g_patch_mutex);
    return PATCH_SUCCESS;
}

patch_error_t
patch_enable(patch_handle_t *handle)
{
    if (handle == nullptr) {
        patch__set_error("handle is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    futex_mutex_lock(&g_patch_mutex);

    // Idempotent: calling enable on an already-enabled patch succeeds silently.
    // This simplifies caller logic and matches common expectations.
    if (atomic_load(&handle->enabled)) {
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Re-write the detour (points to dispatcher or replacement function)
    patch_error_t err = patch__write_detour(handle->target,
                                            handle->detour_dest,
                                            handle->patch_size);
    if (err != PATCH_SUCCESS) {
        futex_mutex_unlock(&g_patch_mutex);
        return err;
    }

    atomic_store(&handle->enabled, true);
    futex_mutex_unlock(&g_patch_mutex);
    return PATCH_SUCCESS;
}

// Context API implementation

void *
patch_context_get_arg(patch_context_t *ctx, size_t index)
{
    if (ctx == nullptr || index >= PATCH_REG_ARGS) {
        return nullptr;
    }
    return &ctx->args[index];
}

bool
patch_context_set_arg(patch_context_t *ctx, size_t index, const void *value, size_t size)
{
    if (ctx == nullptr || index >= PATCH_REG_ARGS || value == nullptr) {
        return false;
    }
    if (size > sizeof(ctx->args[0])) {
        size = sizeof(ctx->args[0]);
    }
    memcpy(&ctx->args[index], value, size);
    return true;
}

void *
patch_context_get_fp_arg(patch_context_t *ctx, size_t index)
{
    if (ctx == nullptr || index >= PATCH_FP_REG_ARGS) {
        return nullptr;
    }
    return &ctx->fp_args[index];
}

bool
patch_context_set_fp_arg(patch_context_t *ctx, size_t index, const void *value, size_t size)
{
    if (ctx == nullptr || index >= PATCH_FP_REG_ARGS || value == nullptr) {
        return false;
    }
    if (size > sizeof(ctx->fp_args[0])) {
        size = sizeof(ctx->fp_args[0]);
    }
    memcpy(&ctx->fp_args[index], value, size);
    return true;
}

void *
patch_context_get_stack_arg(patch_context_t *ctx, size_t index)
{
    if (ctx == nullptr || ctx->caller_stack == nullptr) {
        return nullptr;
    }
    // Stack arguments are 8-byte aligned slots
    // The caller_stack pointer points to the first stack argument
    uint64_t *stack = (uint64_t *)ctx->caller_stack;
    return &stack[index];
}

void *
patch_context_get_return(patch_context_t *ctx)
{
    if (ctx == nullptr) {
        return nullptr;
    }
    return &ctx->return_value;
}

void
patch_context_set_return(patch_context_t *ctx, const void *value, size_t size)
{
    if (ctx == nullptr || value == nullptr) {
        return;
    }
    if (size > sizeof(ctx->return_value)) {
        size = sizeof(ctx->return_value);
    }
    memcpy(&ctx->return_value, value, size);
    ctx->return_set = true;
}

void *
patch_context_get_original(patch_context_t *ctx)
{
    if (ctx == nullptr || ctx->handle == nullptr) {
        return nullptr;
    }
    // When chaining, "original" is the next hook in chain, or the trampoline
    return patch__get_chain_next(ctx->handle);
}

void *
patch_get_trampoline(patch_handle_t *handle)
{
    if (handle == nullptr || handle->trampoline == nullptr) {
        return nullptr;
    }
    return handle->trampoline->code;
}
