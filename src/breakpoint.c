#define _GNU_SOURCE

#include "breakpoint.h"

#include "arch/arch.h"
#include "futex.h"
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
// Breakpoint Registry
// =============================================================================
//
// Hash table for O(1) lookup of breakpoint hooks by address.
// The signal handler needs fast lookup since it runs in signal context.

#define BREAKPOINT_HASH_SIZE 64

typedef struct breakpoint_entry {
    void                    *addr;   // Address where breakpoint is installed
    patch_handle_t          *handle; // Associated hook handle
    struct breakpoint_entry *next;   // Hash chain
} breakpoint_entry_t;

static breakpoint_entry_t *g_breakpoint_table[BREAKPOINT_HASH_SIZE];
static futex_mutex_t       g_breakpoint_mutex = FUTEX_MUTEX_INIT;

static inline size_t
hash_addr(void *addr)
{
    uintptr_t a = (uintptr_t)addr;
    // Simple multiplicative hash
    return (a * 2654435769UL) % BREAKPOINT_HASH_SIZE;
}

static void
breakpoint_registry_add(void *addr, patch_handle_t *handle)
{
    futex_mutex_lock(&g_breakpoint_mutex);

    size_t              idx   = hash_addr(addr);
    breakpoint_entry_t *entry = malloc(sizeof(*entry));
    if (entry != nullptr) {
        entry->addr   = addr;
        entry->handle = handle;
        entry->next   = g_breakpoint_table[idx];
        g_breakpoint_table[idx] = entry;
    }

    futex_mutex_unlock(&g_breakpoint_mutex);
}

static void
breakpoint_registry_remove(void *addr)
{
    futex_mutex_lock(&g_breakpoint_mutex);

    size_t               idx = hash_addr(addr);
    breakpoint_entry_t **pp  = &g_breakpoint_table[idx];

    while (*pp != nullptr) {
        if ((*pp)->addr == addr) {
            breakpoint_entry_t *to_free = *pp;
            *pp = to_free->next;
            free(to_free);
            break;
        }
        pp = &(*pp)->next;
    }

    futex_mutex_unlock(&g_breakpoint_mutex);
}

static patch_handle_t *
breakpoint_registry_find(void *addr)
{
    // Note: Called from signal handler, so we don't lock
    // (mutex is not async-signal-safe). The table is stable during
    // signal handling since we only modify it outside of hooks.
    size_t idx = hash_addr(addr);

    for (breakpoint_entry_t *e = g_breakpoint_table[idx]; e != nullptr; e = e->next) {
        if (e->addr == addr) {
            return e->handle;
        }
    }
    return nullptr;
}

// =============================================================================
// Architecture-Specific Breakpoint Instructions
// =============================================================================

#ifdef PATCH_ARCH_X86_64
#define BREAKPOINT_INSN_LEN 1
#define BREAKPOINT_INSN_BYTE 0xCC // INT3
#endif

#ifdef PATCH_ARCH_ARM64
#define BREAKPOINT_INSN_LEN 4
static const uint8_t BREAKPOINT_INSN[] = {0x00, 0x00, 0x20, 0xD4}; // BRK #0
#endif

// =============================================================================
// Signal Handler
// =============================================================================

static struct sigaction g_old_sigtrap_action;
static atomic_bool      g_handler_installed = false;

// Extract faulting PC from ucontext
static inline void *
get_faulting_pc(ucontext_t *uc)
{
#ifdef PATCH_ARCH_X86_64
#ifdef __APPLE__
    return (void *)uc->uc_mcontext->__ss.__rip;
#else
    return (void *)uc->uc_mcontext.gregs[REG_RIP];
#endif
#endif

#ifdef PATCH_ARCH_ARM64
#ifdef __APPLE__
    return (void *)uc->uc_mcontext->__ss.__pc;
#else
    return (void *)uc->uc_mcontext.pc;
#endif
#endif
}

// Set PC in ucontext (for resuming execution)
static inline void
set_pc(ucontext_t *uc, void *pc)
{
#ifdef PATCH_ARCH_X86_64
#ifdef __APPLE__
    uc->uc_mcontext->__ss.__rip = (uint64_t)pc;
#else
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)pc;
#endif
#endif

#ifdef PATCH_ARCH_ARM64
#ifdef __APPLE__
    uc->uc_mcontext->__ss.__pc = (uint64_t)pc;
#else
    uc->uc_mcontext.pc = (uint64_t)pc;
#endif
#endif
}

// Get return address from context
static inline void *
get_return_addr(ucontext_t *uc)
{
#ifdef PATCH_ARCH_X86_64
    // x86-64: Return address is on stack (RSP points to it at function entry)
#ifdef __APPLE__
    uint64_t rsp = uc->uc_mcontext->__ss.__rsp;
#else
    uint64_t rsp = uc->uc_mcontext.gregs[REG_RSP];
#endif
    return *(void **)rsp;
#endif

#ifdef PATCH_ARCH_ARM64
    // ARM64: Return address is in x30 (link register)
#ifdef __APPLE__
    return (void *)uc->uc_mcontext->__ss.__lr;
#else
    return (void *)uc->uc_mcontext.regs[30];
#endif
#endif
}

// Extract integer arguments from ucontext
static void
extract_int_args(ucontext_t *uc, uint64_t *args)
{
#ifdef PATCH_ARCH_X86_64
#ifdef __APPLE__
    args[0] = uc->uc_mcontext->__ss.__rdi;
    args[1] = uc->uc_mcontext->__ss.__rsi;
    args[2] = uc->uc_mcontext->__ss.__rdx;
    args[3] = uc->uc_mcontext->__ss.__rcx;
    args[4] = uc->uc_mcontext->__ss.__r8;
    args[5] = uc->uc_mcontext->__ss.__r9;
#else
    args[0] = uc->uc_mcontext.gregs[REG_RDI];
    args[1] = uc->uc_mcontext.gregs[REG_RSI];
    args[2] = uc->uc_mcontext.gregs[REG_RDX];
    args[3] = uc->uc_mcontext.gregs[REG_RCX];
    args[4] = uc->uc_mcontext.gregs[REG_R8];
    args[5] = uc->uc_mcontext.gregs[REG_R9];
#endif
#endif

#ifdef PATCH_ARCH_ARM64
#ifdef __APPLE__
    for (int i = 0; i < 8; i++) {
        args[i] = uc->uc_mcontext->__ss.__x[i];
    }
#else
    for (int i = 0; i < 8; i++) {
        args[i] = uc->uc_mcontext.regs[i];
    }
#endif
#endif
}

// Extract floating-point arguments from ucontext
static void
extract_fp_args(ucontext_t *uc, patch__fp_reg_t *fp_args)
{
#ifdef PATCH_ARCH_X86_64
#ifdef __APPLE__
    // macOS x86-64: FP state in __fs.__fpu_xmm*
    // Access via fpu_stmm* for 128-bit XMM registers
    _STRUCT_X86_FLOAT_STATE64 *fs = &uc->uc_mcontext->__fs;
    for (int i = 0; i < 8; i++) {
        memcpy(&fp_args[i], &fs->__fpu_xmm0 + i, 16);
    }
#else
    // Linux x86-64: FP state in fpregs (if present)
    if (uc->uc_mcontext.fpregs != nullptr) {
        // _xmm array contains 16 XMM registers (128-bit each)
        for (int i = 0; i < 8; i++) {
            memcpy(&fp_args[i], &uc->uc_mcontext.fpregs->_xmm[i], 16);
        }
    }
    else {
        memset(fp_args, 0, 8 * sizeof(patch__fp_reg_t));
    }
#endif
#endif

#ifdef PATCH_ARCH_ARM64
#ifdef __APPLE__
    // macOS ARM64: FP state in __ns.__v[0-31]
    for (int i = 0; i < 8; i++) {
        memcpy(&fp_args[i], &uc->uc_mcontext->__ns.__v[i], 16);
    }
#else
    // Linux ARM64: Find FPSIMD context in __reserved area
    // This is a bit tricky - need to search for FPSIMD_MAGIC
    struct _aarch64_ctx *ctx = (struct _aarch64_ctx *)uc->uc_mcontext.__reserved;
    while (ctx->magic != 0) {
        if (ctx->magic == FPSIMD_MAGIC) {
            struct fpsimd_context *fpsimd = (struct fpsimd_context *)ctx;
            for (int i = 0; i < 8; i++) {
                memcpy(&fp_args[i], &fpsimd->vregs[i], 16);
            }
            return;
        }
        ctx = (struct _aarch64_ctx *)((char *)ctx + ctx->size);
    }
    memset(fp_args, 0, 8 * sizeof(patch__fp_reg_t));
#endif
#endif
}

// Set return value in ucontext
static void
set_return_value(ucontext_t *uc, uint64_t value)
{
#ifdef PATCH_ARCH_X86_64
#ifdef __APPLE__
    uc->uc_mcontext->__ss.__rax = value;
#else
    uc->uc_mcontext.gregs[REG_RAX] = (greg_t)value;
#endif
#endif

#ifdef PATCH_ARCH_ARM64
#ifdef __APPLE__
    uc->uc_mcontext->__ss.__x[0] = value;
#else
    uc->uc_mcontext.regs[0] = value;
#endif
#endif
}

// Get caller's stack pointer (for stack arguments)
static void *
get_caller_stack(ucontext_t *uc)
{
#ifdef PATCH_ARCH_X86_64
#ifdef __APPLE__
    // Skip return address on stack: RSP + 8
    return (void *)(uc->uc_mcontext->__ss.__rsp + 8);
#else
    return (void *)(uc->uc_mcontext.gregs[REG_RSP] + 8);
#endif
#endif

#ifdef PATCH_ARCH_ARM64
#ifdef __APPLE__
    return (void *)uc->uc_mcontext->__ss.__sp;
#else
    return (void *)uc->uc_mcontext.sp;
#endif
#endif
}

static void
sigtrap_handler(int sig, siginfo_t *info, void *ucontext_raw)
{
    (void)sig;
    (void)info;

    ucontext_t *uc = (ucontext_t *)ucontext_raw;
    void       *pc = get_faulting_pc(uc);

    // On x86-64, INT3 sets PC to *after* the instruction
    // On ARM64, BRK sets PC to *at* the instruction
#ifdef PATCH_ARCH_X86_64
    void *breakpoint_addr = (void *)((uintptr_t)pc - 1);
#else
    void *breakpoint_addr = pc;
#endif

    // Look up the breakpoint entry
    patch_handle_t *handle = breakpoint_registry_find(breakpoint_addr);

    if (handle == nullptr) {
        // Not our breakpoint - chain to previous handler
        if (g_old_sigtrap_action.sa_flags & SA_SIGINFO) {
            g_old_sigtrap_action.sa_sigaction(sig, info, ucontext_raw);
        }
        else if (g_old_sigtrap_action.sa_handler != SIG_IGN &&
                 g_old_sigtrap_action.sa_handler != SIG_DFL) {
            g_old_sigtrap_action.sa_handler(sig);
        }
        return;
    }

    // Hook is disabled? Skip to trampoline (original instruction + resume)
    if (!atomic_load(&handle->enabled)) {
        set_pc(uc, handle->breakpoint_trampoline);
        return;
    }

    // Extract arguments from context
    uint64_t        args[PATCH_REG_ARGS];
    patch__fp_reg_t fp_args[PATCH_FP_REG_ARGS];
    extract_int_args(uc, args);
    extract_fp_args(uc, fp_args);

    void           *caller_stack = get_caller_stack(uc);
    patch__fp_reg_t fp_return    = {0, 0};

    // Call the dispatch function
    uint64_t result = patch__dispatch_full(handle,
                                           args,
                                           fp_args,
                                           caller_stack,
                                           handle->breakpoint_trampoline,
                                           &fp_return);

    // Set return value in context
    set_return_value(uc, result);

    // Set PC to return to caller (skip the hooked function entirely)
    void *return_addr = get_return_addr(uc);
    set_pc(uc, return_addr);

    // On x86-64, we also need to pop the return address from stack
#ifdef PATCH_ARCH_X86_64
#ifdef __APPLE__
    uc->uc_mcontext->__ss.__rsp += 8;
#else
    uc->uc_mcontext.gregs[REG_RSP] += 8;
#endif
#endif
}

// =============================================================================
// Public API
// =============================================================================

patch_error_t
patch__breakpoint_init(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_handler_installed, &expected, true)) {
        // Already initialized
        return PATCH_SUCCESS;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigtrap_handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTRAP, &sa, &g_old_sigtrap_action) != 0) {
        atomic_store(&g_handler_installed, false);
        patch__set_error("failed to install SIGTRAP handler");
        return PATCH_ERR_SIGNAL_HANDLER;
    }

    return PATCH_SUCCESS;
}

void
patch__breakpoint_cleanup(void)
{
    bool expected = true;
    if (!atomic_compare_exchange_strong(&g_handler_installed, &expected, false)) {
        return;
    }

    sigaction(SIGTRAP, &g_old_sigtrap_action, nullptr);
}

patch_error_t
patch__breakpoint_install(patch_handle_t *handle)
{
    if (handle == nullptr || handle->target == nullptr) {
        patch__set_error("invalid handle for breakpoint install");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Initialize breakpoint subsystem if needed
    patch_error_t err = patch__breakpoint_init();
    if (err != PATCH_SUCCESS) {
        return err;
    }

    void  *target   = handle->target;
    size_t insn_len = BREAKPOINT_INSN_LEN;

    // Save original instruction
    handle->breakpoint_insn_len = insn_len;
    handle->breakpoint_addr     = target;
    memcpy(handle->original_bytes, target, insn_len);
    handle->patch_size = insn_len;

    // Create mini-trampoline: original instruction + jump back to (target + insn_len)
    void *tramp = nullptr;
    err         = platform_alloc_near(target, 64, &tramp);
    if (err != PATCH_SUCCESS) {
        patch__set_error("failed to allocate breakpoint trampoline");
        return err;
    }

    // Copy original instruction(s) to trampoline
    // For x86-64, we need to copy enough bytes for the first complete instruction
    // For ARM64, it's always 4 bytes
#ifdef PATCH_ARCH_X86_64
    // Decode and relocate the first instruction
    arch_insn_t insn;
    size_t      decoded = arch_decode_insn((const uint8_t *)target, 16, &insn);
    if (decoded == 0) {
        platform_free_exec(tramp, 64);
        patch__set_error("failed to decode instruction at breakpoint target");
        return PATCH_ERR_INTERNAL;
    }

    // Relocate instruction to trampoline
    size_t relocated = arch_relocate((const uint8_t *)target,
                                     decoded,
                                     (uint8_t *)tramp,
                                     48,
                                     (uintptr_t)target,
                                     (uintptr_t)tramp);
    if (relocated == 0) {
        platform_free_exec(tramp, 64);
        patch__set_error("failed to relocate instruction for breakpoint trampoline");
        return PATCH_ERR_INTERNAL;
    }

    // Update actual instruction length for restoring
    handle->breakpoint_insn_len = decoded;
    handle->patch_size          = decoded;
    memcpy(handle->original_bytes, target, decoded);
#else
    // ARM64: Copy 4 bytes, relocate if PC-relative
    size_t relocated = arch_relocate((const uint8_t *)target,
                                     4,
                                     (uint8_t *)tramp,
                                     48,
                                     (uintptr_t)target,
                                     (uintptr_t)tramp);
    if (relocated == 0) {
        // If relocation fails, try simple copy (for non-PC-relative instructions)
        memcpy(tramp, target, 4);
        relocated = 4;
    }
#endif

    // Write jump back to (target + instruction_length)
    uintptr_t resume_addr = (uintptr_t)target + handle->breakpoint_insn_len;
    size_t    jump_size   = arch_write_jump((uint8_t *)tramp + relocated,
                                            64 - relocated,
                                            (uintptr_t)tramp + relocated,
                                            resume_addr);
    if (jump_size == 0) {
        platform_free_exec(tramp, 64);
        patch__set_error("failed to write jump in breakpoint trampoline");
        return PATCH_ERR_INTERNAL;
    }

    platform_flush_icache(tramp, relocated + jump_size);
    handle->breakpoint_trampoline = tramp;

    // Also create the regular trampoline for patch_get_trampoline() to work
    err = patch__trampoline_create(target,
                                   handle->breakpoint_insn_len,
                                   true, // Assume PC-relative possible
                                   &handle->trampoline);
    if (err != PATCH_SUCCESS) {
        platform_free_exec(tramp, 64);
        patch__set_error("failed to create trampoline for breakpoint hook");
        return err;
    }

    // Add to registry before writing breakpoint
    breakpoint_registry_add(target, handle);
    handle->is_breakpoint_hook = true;

    // Write breakpoint instruction
#ifdef PATCH_ARCH_X86_64
    // For x86-64, we only write 1 byte (INT3) but might overwrite more bytes
    // of a longer instruction. We need to NOP-pad the rest.
    uint8_t patch_buf[16];
    patch_buf[0] = 0xCC; // INT3
    for (size_t i = 1; i < handle->breakpoint_insn_len; i++) {
        patch_buf[i] = 0x90; // NOP
    }
    err = platform_write_code(target, patch_buf, handle->breakpoint_insn_len);
#else
    err = platform_write_code(target, BREAKPOINT_INSN, BREAKPOINT_INSN_LEN);
#endif

    if (err != PATCH_SUCCESS) {
        breakpoint_registry_remove(target);
        patch__trampoline_destroy(handle->trampoline);
        handle->trampoline = nullptr;
        platform_free_exec(tramp, 64);
        handle->breakpoint_trampoline = nullptr;
        handle->is_breakpoint_hook    = false;
        patch__set_error("failed to write breakpoint instruction");
        return err;
    }

    return PATCH_SUCCESS;
}

patch_error_t
patch__breakpoint_remove(patch_handle_t *handle)
{
    if (handle == nullptr || !handle->is_breakpoint_hook) {
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Restore original instruction
    patch_error_t err = platform_write_code(handle->breakpoint_addr,
                                            handle->original_bytes,
                                            handle->breakpoint_insn_len);
    if (err != PATCH_SUCCESS) {
        return err;
    }

    // Remove from registry
    breakpoint_registry_remove(handle->breakpoint_addr);

    // Free mini-trampoline
    if (handle->breakpoint_trampoline != nullptr) {
        platform_free_exec(handle->breakpoint_trampoline, 64);
        handle->breakpoint_trampoline = nullptr;
    }

    // Free regular trampoline
    if (handle->trampoline != nullptr) {
        patch__trampoline_destroy(handle->trampoline);
        handle->trampoline = nullptr;
    }

    handle->is_breakpoint_hook = false;
    return PATCH_SUCCESS;
}

patch_error_t
patch__breakpoint_enable(patch_handle_t *handle)
{
    if (handle == nullptr || !handle->is_breakpoint_hook) {
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Write breakpoint instruction
#ifdef PATCH_ARCH_X86_64
    uint8_t patch_buf[16];
    patch_buf[0] = 0xCC; // INT3
    for (size_t i = 1; i < handle->breakpoint_insn_len; i++) {
        patch_buf[i] = 0x90; // NOP
    }
    return platform_write_code(handle->breakpoint_addr,
                               patch_buf,
                               handle->breakpoint_insn_len);
#else
    return platform_write_code(handle->breakpoint_addr,
                               BREAKPOINT_INSN,
                               BREAKPOINT_INSN_LEN);
#endif
}

patch_error_t
patch__breakpoint_disable(patch_handle_t *handle)
{
    if (handle == nullptr || !handle->is_breakpoint_hook) {
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Restore original instruction
    return platform_write_code(handle->breakpoint_addr,
                               handle->original_bytes,
                               handle->breakpoint_insn_len);
}
