#include "patch_internal.h"

#include "arch/arch.h"
#include "breakpoint.h"
#include "futex.h"
#include "pattern/pattern.h"
#include "platform/platform.h"
#include "watchpoint.h"

#include <dlfcn.h>
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
    bool            use_breakpoint = false;

    if (existing != nullptr) {
        // Chaining: reuse prologue info from existing hook
        match.matched        = true;
        match.prologue_size  = existing->patch_size;
        match.min_patch_size = existing->patch_size;
        match.has_pc_relative = true;  // Assume yes for safety when chaining

        // If existing hook is breakpoint-based, we can't chain code patching onto it
        if (existing->is_breakpoint_hook) {
            patch__set_error("Cannot chain onto breakpoint-based hook");
            futex_mutex_unlock(&g_patch_mutex);
            return PATCH_ERR_INVALID_ARGUMENT;
        }
    }
    else {
        // First hook: match the actual prologue
        match = pattern_match_prologue((const uint8_t *)config->target, 64);
        if (!match.matched) {
            // Pattern not recognized - check if we should try breakpoint fallback
            if (config->method == PATCH_METHOD_CODE) {
                // Explicit CODE method requested - fail
                patch__set_error("No recognized prologue pattern at target");
                futex_mutex_unlock(&g_patch_mutex);
                return PATCH_ERR_PATTERN_UNRECOGNIZED;
            }

            if (config->method == PATCH_METHOD_AUTO ||
                config->method == PATCH_METHOD_BREAKPOINT) {
                // Try breakpoint-based hooking as fallback
                use_breakpoint = true;
            }
            else {
                patch__set_error("No recognized prologue pattern at target");
                futex_mutex_unlock(&g_patch_mutex);
                return PATCH_ERR_PATTERN_UNRECOGNIZED;
            }
        }
        else if (config->method == PATCH_METHOD_BREAKPOINT) {
            // Explicit breakpoint method requested
            use_breakpoint = true;
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
    h->patch_size         = use_breakpoint ? 0 : match.prologue_size;
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

    // =========================================================================
    // Breakpoint-based hooking path
    // =========================================================================
    if (use_breakpoint) {
        // Breakpoint hooks don't support simple replacement mode currently
        // (they use the dispatcher for signal handler integration)
        if (has_replacement) {
            patch__set_error("Breakpoint hooks require prologue/epilogue callbacks, "
                             "not simple replacement");
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return PATCH_ERR_INVALID_ARGUMENT;
        }

        err = patch__breakpoint_install(h);
        if (err != PATCH_SUCCESS) {
#ifdef PATCH_HAVE_LIBFFI
            if (h->ffi_cif != nullptr) {
                free(h->ffi_cif);
            }
            if (h->ffi_arg_types != nullptr) {
                free(h->ffi_arg_types);
            }
#endif
            free(h);
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }

        // Breakpoint hooks don't use the registry (they have their own hash table)
        // and don't support chaining
        *handle = h;
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // =========================================================================
    // Standard code patching path
    // =========================================================================

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

    // Handle GOT hooks specially
    if (handle->is_got_hook) {
        // Restore original GOT value
        if (handle->got_entry != nullptr) {
            *handle->got_entry = handle->original_got_value;
        }
        free(handle);
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Handle breakpoint hooks specially
    if (handle->is_breakpoint_hook) {
        patch_error_t err = patch__breakpoint_remove(handle);
        if (err != PATCH_SUCCESS) {
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }

#ifdef PATCH_HAVE_LIBFFI
        if (handle->ffi_cif != nullptr) {
            free(handle->ffi_cif);
        }
        if (handle->ffi_arg_types != nullptr) {
            free(handle->ffi_arg_types);
        }
#endif
        // Free dispatcher if present
        if (handle->dispatcher != nullptr) {
            patch__dispatcher_destroy(handle->dispatcher);
        }

        free(handle);
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Handle watchpoint hooks specially
    if (handle->is_watchpoint_hook) {
        patch_error_t err = patch__watchpoint_remove(handle);
        if (err != PATCH_SUCCESS) {
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }

        free(handle);
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Code patching path below

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

    // Handle GOT hooks specially
    if (handle->is_got_hook) {
        if (handle->got_entry != nullptr) {
            *handle->got_entry = handle->original_got_value;
        }
        atomic_store(&handle->enabled, false);
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Handle breakpoint hooks specially
    if (handle->is_breakpoint_hook) {
        patch_error_t err = patch__breakpoint_disable(handle);
        if (err != PATCH_SUCCESS) {
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }
        atomic_store(&handle->enabled, false);
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Handle watchpoint hooks specially
    if (handle->is_watchpoint_hook) {
        patch_error_t err = patch__watchpoint_disable(handle);
        if (err != PATCH_SUCCESS) {
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }
        atomic_store(&handle->enabled, false);
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Restore original bytes (code patching)
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

    // Handle GOT hooks specially
    if (handle->is_got_hook) {
        if (handle->got_entry != nullptr) {
            *handle->got_entry = handle->detour_dest;
        }
        atomic_store(&handle->enabled, true);
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Handle breakpoint hooks specially
    if (handle->is_breakpoint_hook) {
        patch_error_t err = patch__breakpoint_enable(handle);
        if (err != PATCH_SUCCESS) {
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }
        atomic_store(&handle->enabled, true);
        futex_mutex_unlock(&g_patch_mutex);
        return PATCH_SUCCESS;
    }

    // Handle watchpoint hooks specially
    if (handle->is_watchpoint_hook) {
        patch_error_t err = patch__watchpoint_enable(handle);
        if (err != PATCH_SUCCESS) {
            futex_mutex_unlock(&g_patch_mutex);
            return err;
        }
        atomic_store(&handle->enabled, true);
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
    if (handle == nullptr) {
        return nullptr;
    }

    // For GOT hooks and watchpoint hooks, return the original function pointer
    if (handle->is_got_hook || handle->is_watchpoint_hook) {
        return handle->original_got_value;
    }

    // For code hooks, return the trampoline
    if (handle->trampoline == nullptr) {
        return nullptr;
    }
    return handle->trampoline->code;
}

// ============================================================================
// Symbol Resolution API
// ============================================================================

patch_error_t
patch_resolve_symbol(const char *symbol, const char *library, void **address)
{
    if (symbol == nullptr || address == nullptr) {
        patch__set_error("symbol and address must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    *address = nullptr;

    void *lib_handle = nullptr;

    if (library != nullptr) {
        // Open the specific library
        lib_handle = dlopen(library, RTLD_NOW | RTLD_NOLOAD);
        if (lib_handle == nullptr) {
            // Library not already loaded, try loading it
            lib_handle = dlopen(library, RTLD_NOW);
        }
        if (lib_handle == nullptr) {
            patch__set_error("failed to open library '%s': %s", library, dlerror());
            return PATCH_ERR_SYMBOL_NOT_FOUND;
        }
    }
    else {
        // Use RTLD_DEFAULT to search all loaded libraries
        lib_handle = RTLD_DEFAULT;
    }

    // Clear any previous error
    dlerror();

    void *sym = dlsym(lib_handle, symbol);

    // Check for error (dlsym can return nullptr for valid symbols)
    const char *error = dlerror();
    if (error != nullptr) {
        patch__set_error("symbol '%s' not found%s%s: %s",
                         symbol,
                         library ? " in " : "",
                         library ? library : "",
                         error);
        if (library != nullptr && lib_handle != RTLD_DEFAULT) {
            dlclose(lib_handle);
        }
        return PATCH_ERR_SYMBOL_NOT_FOUND;
    }

    if (sym == nullptr) {
        // Symbol resolved to nullptr (unusual but possible)
        patch__set_error("symbol '%s' resolved to nullptr", symbol);
        if (library != nullptr && lib_handle != RTLD_DEFAULT) {
            dlclose(lib_handle);
        }
        return PATCH_ERR_SYMBOL_NOT_FOUND;
    }

    // If we opened a library, we keep it open. The caller is responsible
    // for the lifetime, or we could track it in the handle.
    // For now, we leave it open since closing it would invalidate the symbol.

    *address = sym;
    return PATCH_SUCCESS;
}

// Internal: Install a GOT hook (simple pointer replacement)
static patch_error_t
patch_install_got(void **got_entry, void *replacement, void *original, patch_handle_t **out)
{
    // Allocate handle
    patch_handle_t *h = calloc(1, sizeof(patch_handle_t));
    if (h == nullptr) {
        patch__set_error("failed to allocate patch handle");
        return PATCH_ERR_ALLOCATION_FAILED;
    }

    h->is_got_hook        = true;
    h->got_entry          = got_entry;
    h->original_got_value = original;
    h->target             = original;  // Target is the original function
    h->detour_dest        = replacement;
    atomic_store(&h->enabled, true);

    // GOT is typically in a writable data segment, so we can just write to it
    // But we should ensure it's writable first
    mem_prot_t prot;
    if (platform_get_protection(got_entry, &prot) == PATCH_SUCCESS) {
        if (prot != MEM_PROT_RW && prot != MEM_PROT_RWX) {
            // Need to make it writable
            if (platform_protect(got_entry, sizeof(void *), MEM_PROT_RW) != PATCH_SUCCESS) {
                free(h);
                patch__set_error("failed to make GOT entry writable");
                return PATCH_ERR_MEMORY_PROTECTION;
            }
        }
    }

    // Write the new value
    *got_entry = replacement;

    *out = h;
    return PATCH_SUCCESS;
}

patch_error_t
patch_install_symbol(const char           *symbol,
                     const char           *library,
                     const patch_config_t *config,
                     patch_handle_t      **handle)
{
    if (symbol == nullptr) {
        patch__set_error("symbol must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }
    if (config == nullptr) {
        patch__set_error("config must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }
    if (handle == nullptr) {
        patch__set_error("handle must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    *handle = nullptr;

    patch_method_t method = config->method;

    // Resolve the symbol to get the real function address
    void         *target = nullptr;
    patch_error_t err    = patch_resolve_symbol(symbol, library, &target);
    if (err != PATCH_SUCCESS) {
        return err;
    }

    // Try GOT hooking first if AUTO or GOT method
    if (method == PATCH_METHOD_AUTO || method == PATCH_METHOD_GOT) {
        void **got_entry = nullptr;
        err              = platform_find_got_entry(symbol, &got_entry);

        if (err == PATCH_SUCCESS && got_entry != nullptr) {
            // Found a GOT entry - use GOT hooking
            void *replacement = config->replacement;

            // For GOT hooking, we need a replacement function
            // Callback mode (prologue/epilogue) is not supported with GOT hooking
            if (replacement == nullptr) {
                if (config->prologue != nullptr || config->epilogue != nullptr) {
                    patch__set_error("GOT hooking does not support prologue/epilogue callbacks; "
                                     "use replacement mode or PATCH_METHOD_CODE");
                    if (method == PATCH_METHOD_GOT) {
                        return PATCH_ERR_INVALID_ARGUMENT;
                    }
                    // Fall through to code patching for AUTO mode
                    goto try_code_patching;
                }
            }

            if (replacement != nullptr) {
                futex_mutex_lock(&g_patch_mutex);
                err = patch_install_got(got_entry, replacement, target, handle);
                futex_mutex_unlock(&g_patch_mutex);
                return err;
            }
        }

        // No GOT entry found
        if (method == PATCH_METHOD_GOT) {
            patch__set_error("no GOT entry found for symbol '%s'", symbol);
            return PATCH_ERR_NO_GOT_ENTRY;
        }
        // Fall through to code patching for AUTO mode
    }

try_code_patching:
    // Use code patching
    if (method == PATCH_METHOD_GOT) {
        // Should not reach here - GOT-only mode but no GOT entry
        patch__set_error("no GOT entry found for symbol '%s'", symbol);
        return PATCH_ERR_NO_GOT_ENTRY;
    }

    // Create a copy of the config with the resolved target and force CODE method
    patch_config_t resolved_config = *config;
    resolved_config.target         = target;
    resolved_config.method         = PATCH_METHOD_CODE;

    // Install the patch using code patching
    return patch_install(&resolved_config, handle);
}

// ============================================================================
// Hot-Swap API
// ============================================================================

patch_error_t
patch_set_prologue(patch_handle_t *handle, patch_prologue_fn prologue, void *user_data)
{
    if (handle == nullptr) {
        patch__set_error("handle must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (handle->is_got_hook) {
        patch__set_error("GOT hooks do not support prologue callbacks; use patch_set_replacement");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Check if this is a dispatcher-based hook (has prologue/epilogue support)
    if (handle->dispatcher == nullptr) {
        patch__set_error("simple replacement hooks do not support prologue callbacks");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Atomic update - the dispatcher reads these at call time
    // Use atomic stores to ensure visibility across threads
    atomic_store((_Atomic(void *) *)&handle->prologue_user_data, user_data);
    atomic_store((_Atomic(patch_prologue_fn) *)&handle->prologue, prologue);

    return PATCH_SUCCESS;
}

patch_error_t
patch_set_epilogue(patch_handle_t *handle, patch_epilogue_fn epilogue, void *user_data)
{
    if (handle == nullptr) {
        patch__set_error("handle must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (handle->is_got_hook) {
        patch__set_error("GOT hooks do not support epilogue callbacks; use patch_set_replacement");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (handle->dispatcher == nullptr) {
        patch__set_error("simple replacement hooks do not support epilogue callbacks");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Atomic update
    atomic_store((_Atomic(void *) *)&handle->epilogue_user_data, user_data);
    atomic_store((_Atomic(patch_epilogue_fn) *)&handle->epilogue, epilogue);

    return PATCH_SUCCESS;
}

patch_error_t
patch_set_callbacks(patch_handle_t   *handle,
                    patch_prologue_fn prologue,
                    void             *prologue_data,
                    patch_epilogue_fn epilogue,
                    void             *epilogue_data)
{
    if (handle == nullptr) {
        patch__set_error("handle must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (handle->is_got_hook) {
        patch__set_error("GOT hooks do not support callbacks; use patch_set_replacement");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (handle->dispatcher == nullptr) {
        patch__set_error("simple replacement hooks do not support callbacks");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Update all four fields atomically (in terms of visibility)
    // Note: This is not a single atomic operation, but the dispatcher
    // will see a consistent state because it reads prologue before
    // prologue_user_data, and epilogue before epilogue_user_data.
    // We update user_data first, then the callback pointer.
    atomic_store((_Atomic(void *) *)&handle->prologue_user_data, prologue_data);
    atomic_store((_Atomic(patch_prologue_fn) *)&handle->prologue, prologue);
    atomic_store((_Atomic(void *) *)&handle->epilogue_user_data, epilogue_data);
    atomic_store((_Atomic(patch_epilogue_fn) *)&handle->epilogue, epilogue);

    return PATCH_SUCCESS;
}

patch_error_t
patch_set_replacement(patch_handle_t *handle, void *replacement)
{
    if (handle == nullptr) {
        patch__set_error("handle must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (replacement == nullptr) {
        patch__set_error("replacement must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (!handle->is_got_hook) {
        patch__set_error("patch_set_replacement only works for GOT hooks; "
                         "use patch_remove + patch_install for code-patched hooks");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // For GOT hooks, just update the GOT entry
    if (handle->got_entry != nullptr) {
        *handle->got_entry = replacement;
        handle->detour_dest = replacement;
    }

    return PATCH_SUCCESS;
}

// ============================================================================
// Watchpoint-Guarded Pointer Hooks
// ============================================================================

patch_error_t
patch_install_pointer(const patch_pointer_config_t *config, patch_handle_t **handle)
{
    if (config == nullptr || handle == nullptr) {
        patch__set_error("config and handle must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    *handle = nullptr;

    if (config->location == nullptr) {
        patch__set_error("config->location must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (config->replacement == nullptr) {
        patch__set_error("config->replacement must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Create handle
    patch_handle_t *h = calloc(1, sizeof(*h));
    if (h == nullptr) {
        patch__set_error("failed to allocate patch handle");
        return PATCH_ERR_ALLOCATION_FAILED;
    }

    h->watched_location = config->location;
    h->detour_dest      = config->replacement;
    h->watch_callback   = config->on_update;
    h->watch_user_data  = config->user_data;
    atomic_store(&h->enabled, true);

    futex_mutex_lock(&g_patch_mutex);

    // Install the watchpoint hook
    patch_error_t err = patch__watchpoint_install(h);
    if (err != PATCH_SUCCESS) {
        futex_mutex_unlock(&g_patch_mutex);
        free(h);
        return err;
    }

    futex_mutex_unlock(&g_patch_mutex);

    *handle = h;
    return PATCH_SUCCESS;
}
