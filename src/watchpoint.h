#pragma once

#include "patch_internal.h"

/**
 * @brief Initialize the watchpoint subsystem.
 *
 * Installs the SIGTRAP signal handler if not already installed.
 * Safe to call multiple times.
 *
 * @return PATCH_SUCCESS on success, PATCH_ERR_SIGNAL_HANDLER on failure.
 */
patch_error_t patch__watchpoint_init(void);

/**
 * @brief Cleanup the watchpoint subsystem.
 *
 * Called when no more watchpoint hooks are active.
 */
void patch__watchpoint_cleanup(void);

/**
 * @brief Install a watchpoint-guarded pointer hook.
 *
 * @param handle The patch handle (must have location and replacement set).
 * @return PATCH_SUCCESS on success, or an error code on failure.
 */
patch_error_t patch__watchpoint_install(patch_handle_t *handle);

/**
 * @brief Remove a watchpoint hook.
 *
 * Clears the hardware watchpoint and restores the original pointer value.
 *
 * @param handle The patch handle.
 * @return PATCH_SUCCESS on success, or an error code on failure.
 */
patch_error_t patch__watchpoint_remove(patch_handle_t *handle);

/**
 * @brief Enable a previously disabled watchpoint hook.
 *
 * @param handle The patch handle.
 * @return PATCH_SUCCESS on success, or an error code on failure.
 */
patch_error_t patch__watchpoint_enable(patch_handle_t *handle);

/**
 * @brief Disable a watchpoint hook without removing it.
 *
 * @param handle The patch handle.
 * @return PATCH_SUCCESS on success, or an error code on failure.
 */
patch_error_t patch__watchpoint_disable(patch_handle_t *handle);
