#include "patch_internal.h"

#include "arch/arch.h"
#include "pattern/pattern.h"
#include "platform/platform.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Thread-local error message storage
static _Thread_local char g_error_buffer[PATCH_ERROR_BUFFER_SIZE];

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
ensure_initialized(void)
{
    static bool initialized = false;
    if (!initialized) {
        initialized = true;
        if (!pattern_init_defaults()) {
            // This should never happen - patterns are compiled in.
            // Log for debugging but continue - patch_can_install will fail gracefully.
            patch__set_error("pattern initialization failed (no handlers registered)");
        }
    }
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

    // Match prologue pattern
    pattern_match_t match = pattern_match_prologue(
        (const uint8_t *)config->target,
        64);

    if (!match.matched) {
        patch__set_error("No recognized prologue pattern at target");
        return PATCH_ERR_PATTERN_UNRECOGNIZED;
    }

    // Create handle
    patch_handle_t *h = calloc(1, sizeof(*h));
    if (h == nullptr) {
        patch__set_error("Failed to allocate handle");
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
            return PATCH_ERR_ALLOCATION_FAILED;
        }
        memcpy(h->ffi_arg_types, config->arg_types, config->arg_count * sizeof(ffi_type *));

        h->ffi_ret_type = config->return_type ? config->return_type : &ffi_type_uint64;

        h->ffi_cif = malloc(sizeof(ffi_cif));
        if (h->ffi_cif == nullptr) {
            patch__set_error("Failed to allocate FFI CIF");
            free(h->ffi_arg_types);
            free(h);
            return PATCH_ERR_ALLOCATION_FAILED;
        }

        if (ffi_prep_cif(h->ffi_cif, FFI_DEFAULT_ABI, (unsigned int)h->ffi_arg_count,
                         h->ffi_ret_type, h->ffi_arg_types) != FFI_OK) {
            patch__set_error("Failed to prepare FFI call interface");
            free(h->ffi_cif);
            free(h->ffi_arg_types);
            free(h);
            return PATCH_ERR_INTERNAL;
        }
    }
#endif

    // Save original bytes
    memcpy(h->original_bytes, config->target, match.prologue_size);

    // Get original protection
    patch_error_t err = platform_get_protection(config->target, &h->original_prot);
    if (err != PATCH_SUCCESS) {
        free(h);
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
        return err;
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
            return err;
        }
        detour_dest = h->dispatcher;
    }
    h->detour_dest = detour_dest;

    // Write the detour at the original function
    err = patch__write_detour(config->target, detour_dest, match.prologue_size);
    if (err != PATCH_SUCCESS) {
        if (h->dispatcher != nullptr) {
            patch__dispatcher_destroy(h->dispatcher);
        }
        patch__trampoline_destroy(h->trampoline);
        free(h);
        return err;
    }

    *handle = h;
    return PATCH_SUCCESS;
}

patch_error_t
patch_remove(patch_handle_t *handle)
{
    if (handle == nullptr) {
        patch__set_error("handle is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Restore original bytes
    patch_error_t err = patch__restore_bytes(handle->target,
                                             handle->original_bytes,
                                             handle->patch_size);
    if (err != PATCH_SUCCESS) {
        return err;
    }

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

    return PATCH_SUCCESS;
}

patch_error_t
patch_disable(patch_handle_t *handle)
{
    if (handle == nullptr) {
        patch__set_error("handle is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Idempotent: calling disable on an already-disabled patch succeeds silently.
    // This simplifies caller logic and matches common expectations.
    if (!atomic_load(&handle->enabled)) {
        return PATCH_SUCCESS;
    }

    // Restore original bytes
    patch_error_t err = patch__restore_bytes(handle->target,
                                             handle->original_bytes,
                                             handle->patch_size);
    if (err != PATCH_SUCCESS) {
        return err;
    }

    atomic_store(&handle->enabled, false);
    return PATCH_SUCCESS;
}

patch_error_t
patch_enable(patch_handle_t *handle)
{
    if (handle == nullptr) {
        patch__set_error("handle is null");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Idempotent: calling enable on an already-enabled patch succeeds silently.
    // This simplifies caller logic and matches common expectations.
    if (atomic_load(&handle->enabled)) {
        return PATCH_SUCCESS;
    }

    // Re-write the detour (points to dispatcher or replacement function)
    patch_error_t err = patch__write_detour(handle->target,
                                            handle->detour_dest,
                                            handle->patch_size);
    if (err != PATCH_SUCCESS) {
        return err;
    }

    atomic_store(&handle->enabled, true);
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
    return ctx->handle->trampoline->code;
}

void *
patch_get_trampoline(patch_handle_t *handle)
{
    if (handle == nullptr || handle->trampoline == nullptr) {
        return nullptr;
    }
    return handle->trampoline->code;
}
