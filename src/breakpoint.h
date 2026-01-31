#pragma once

#include "patch_internal.h"

/**
 * @brief Initialize the breakpoint subsystem.
 *
 * Installs the SIGTRAP signal handler. Must be called before any breakpoint
 * hooks are installed. Safe to call multiple times (uses one-time init).
 *
 * @return PATCH_SUCCESS on success, PATCH_ERR_SIGNAL_HANDLER on failure.
 */
patch_error_t patch__breakpoint_init(void);

/**
 * @brief Cleanup the breakpoint subsystem.
 *
 * Restores the original SIGTRAP handler. Should be called when no more
 * breakpoint hooks will be used.
 */
void patch__breakpoint_cleanup(void);

/**
 * @brief Install a breakpoint hook on a function.
 *
 * Writes an INT3 (x86-64) or BRK #0 (ARM64) instruction at the target address
 * and creates a mini-trampoline containing the original instruction plus a
 * jump back to resume execution.
 *
 * @param handle The patch handle (must have target set).
 * @return PATCH_SUCCESS on success, or an error code on failure.
 */
patch_error_t patch__breakpoint_install(patch_handle_t *handle);

/**
 * @brief Remove a breakpoint hook.
 *
 * Restores the original instruction at the target address and frees the
 * mini-trampoline.
 *
 * @param handle The patch handle.
 * @return PATCH_SUCCESS on success, or an error code on failure.
 */
patch_error_t patch__breakpoint_remove(patch_handle_t *handle);

/**
 * @brief Enable a previously disabled breakpoint hook.
 *
 * Writes the breakpoint instruction back to the target address.
 *
 * @param handle The patch handle.
 * @return PATCH_SUCCESS on success, or an error code on failure.
 */
patch_error_t patch__breakpoint_enable(patch_handle_t *handle);

/**
 * @brief Disable a breakpoint hook without removing it.
 *
 * Restores the original instruction at the target address but keeps the
 * trampoline allocated.
 *
 * @param handle The patch handle.
 * @return PATCH_SUCCESS on success, or an error code on failure.
 */
patch_error_t patch__breakpoint_disable(patch_handle_t *handle);
