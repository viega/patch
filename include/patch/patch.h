#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PATCH_SUCCESS = 0,
    PATCH_ERR_PATTERN_UNRECOGNIZED,
    PATCH_ERR_EPILOGUE_UNRECOGNIZED,
    PATCH_ERR_INSUFFICIENT_SPACE,
    PATCH_ERR_MEMORY_PROTECTION,
    PATCH_ERR_ALLOCATION_FAILED,
    PATCH_ERR_ALREADY_PATCHED,
    PATCH_ERR_NOT_PATCHED,
    PATCH_ERR_UNSUPPORTED_ARCH,
    PATCH_ERR_INVALID_ARGUMENT,
    PATCH_ERR_INTERNAL,
} patch_error_t;

typedef struct patch_handle  patch_handle_t;
typedef struct patch_context patch_context_t;

// Prologue callback: called before original function executes.
// Return true to proceed to original, false to skip (must set return value).
typedef bool (*patch_prologue_fn)(patch_context_t *ctx, void *user_data);

// Epilogue callback: called after original function returns.
// Can inspect arguments and modify return value.
typedef void (*patch_epilogue_fn)(patch_context_t *ctx, void *user_data);

typedef struct {
    void             *target;
    patch_prologue_fn prologue;
    patch_epilogue_fn epilogue;
    void             *prologue_user_data;
    void             *epilogue_user_data;
} patch_config_t;

// Check if target can be patched (does not modify anything).
[[nodiscard]] patch_error_t patch_can_install(void *target);

// Install hook according to configuration.
[[nodiscard]] patch_error_t patch_install(const patch_config_t *config,
                                          patch_handle_t      **handle);

// Remove hook and free resources.
patch_error_t patch_remove(patch_handle_t *handle);

// Temporarily disable hook (original runs unhooked).
patch_error_t patch_disable(patch_handle_t *handle);

// Re-enable previously disabled hook.
patch_error_t patch_enable(patch_handle_t *handle);

// Get human-readable error details for the last failure on this thread.
[[nodiscard]] const char *patch_get_error_details(void);

// Context API for use within callbacks

// Get argument by index (0-based). Returns pointer to argument storage.
[[nodiscard]] void *patch_context_get_arg(patch_context_t *ctx, size_t index);

// Set argument value. Returns true on success.
bool patch_context_set_arg(patch_context_t *ctx, size_t index,
                           const void *value, size_t size);

// Get return value pointer (valid only in epilogue).
[[nodiscard]] void *patch_context_get_return(patch_context_t *ctx);

// Set return value (for prologue skip or epilogue modification).
void patch_context_set_return(patch_context_t *ctx,
                              const void *value, size_t size);

// Get trampoline to call the original function.
[[nodiscard]] void *patch_context_get_original(patch_context_t *ctx);
