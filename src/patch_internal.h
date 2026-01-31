#pragma once

#include "patch/patch.h"
#include "patch/patch_arch.h"
#include "platform/platform.h"

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

// Thread-local error details buffer.
// 256 bytes is sufficient for all error messages (longest is ~100 chars).
#define PATCH_ERROR_BUFFER_SIZE 256

// Set error details for current thread
void patch__set_error(const char *fmt, ...);

// Trampoline structure - holds relocated prologue + jump back to original
typedef struct {
    uint8_t *code;                  // Pointer to executable memory
    size_t   code_len;              // Total bytes: relocated prologue + return jump
    size_t   alloc_size;            // Size of allocated executable memory
    void    *original_target;       // Original function address
    size_t   original_prologue_len; // Bytes copied from original function
} patch__trampoline_t;

// Patch handle (opaque to users)
struct patch_handle {
    void                *target;
    patch__trampoline_t *trampoline;
    void                *dispatcher;   // Generated stub that invokes callbacks (may be NULL)
    void                *detour_dest;  // Where the detour jumps to (dispatcher or replacement)
    uint8_t              original_bytes[PATCH_MAX_PATCH_SIZE];
    size_t               patch_size;
    patch_prologue_fn    prologue;
    patch_epilogue_fn    epilogue;
    void                *prologue_user_data;
    void                *epilogue_user_data;
    atomic_bool          enabled;
    mem_prot_t           original_prot;

#ifdef PATCH_HAVE_LIBFFI
    ffi_cif   *ffi_cif;       // Prepared call interface (nullptr if not using FFI)
    ffi_type **ffi_arg_types; // Cached argument types (owned by handle)
    ffi_type  *ffi_ret_type;  // Return type
    size_t     ffi_arg_count; // Number of arguments
#endif
};

// 128-bit type for FP/SIMD registers (XMM on x86-64, V on ARM64)
typedef struct {
    uint64_t lo;
    uint64_t hi;
} patch__fp_reg_t;

// Context passed to callbacks
struct patch_context {
    patch_handle_t  *handle;
    uint64_t         args[PATCH_REG_ARGS];        // Integer arguments
    patch__fp_reg_t  fp_args[PATCH_FP_REG_ARGS];  // Floating-point arguments
    void            *caller_stack;                 // Pointer to caller's stack (for stack args)
    uint64_t         return_value;                 // Integer return value
    patch__fp_reg_t  fp_return_value;             // FP return value (xmm0/v0)
    bool             return_set;
};

// Trampoline management
// If needs_relocation is false (e.g., NOP sled), skip PC-relative fixups.
patch_error_t patch__trampoline_create(void            *target,
                                       size_t           prologue_size,
                                       bool             needs_relocation,
                                       patch__trampoline_t **out);
void          patch__trampoline_destroy(patch__trampoline_t *tramp);

// Dispatcher management - the dispatcher invokes callbacks and calls trampoline
patch_error_t patch__dispatcher_create(patch_handle_t *handle, void **out);
void          patch__dispatcher_destroy(void *dispatcher);

// Dispatch function called by generated dispatcher stub
// fp_args points to saved FP registers (8 x 128-bit)
// caller_stack points to the caller's stack frame (for accessing stack arguments)
uint64_t patch__dispatch_full(patch_handle_t  *handle,
                              uint64_t        *args,
                              patch__fp_reg_t *fp_args,
                              void            *caller_stack,
                              void            *trampoline);

// Write the detour jump at target
patch_error_t patch__write_detour(void *target, void *destination, size_t available_size);

// Restore original bytes at target
patch_error_t patch__restore_bytes(void *target, const uint8_t *original, size_t size);
