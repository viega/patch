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

    if (config->prologue == nullptr && config->epilogue == nullptr) {
        patch__set_error("At least one callback must be provided");
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

    // Save original bytes
    memcpy(h->original_bytes, config->target, match.prologue_size);

    // Get original protection
    patch_error_t err = platform_get_protection(config->target, &h->original_prot);
    if (err != PATCH_SUCCESS) {
        free(h);
        return err;
    }

    // Create trampoline (holds relocated prologue + jump back to original)
    err = patch__trampoline_create(config->target, match.prologue_size, &h->trampoline);
    if (err != PATCH_SUCCESS) {
        free(h);
        return err;
    }

    // Create dispatcher (invokes callbacks, calls trampoline, returns result)
    err = patch__dispatcher_create(h, &h->dispatcher);
    if (err != PATCH_SUCCESS) {
        patch__trampoline_destroy(h->trampoline);
        free(h);
        return err;
    }

    // Write the detour at the original function - points to dispatcher
    err = patch__write_detour(config->target,
                              h->dispatcher,
                              match.prologue_size);
    if (err != PATCH_SUCCESS) {
        patch__dispatcher_destroy(h->dispatcher);
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

    // Free dispatcher and trampoline
    patch__dispatcher_destroy(handle->dispatcher);
    patch__trampoline_destroy(handle->trampoline);

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

    // Re-write the detour (points to dispatcher)
    patch_error_t err = patch__write_detour(handle->target,
                                            handle->dispatcher,
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
