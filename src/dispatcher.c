#include "patch_internal.h"

#include "platform/platform.h"

#include <string.h>

// The dispatcher is dynamically generated code that:
// 1. Saves argument registers
// 2. Calls the dispatch helper which handles prologue, original call, and epilogue
// 3. Returns the result to caller
//
// Each hook gets its own dispatcher with embedded pointers to its handle
// and trampoline.

// Full dispatch function that handles prologue, trampoline call, and epilogue
// This is called from the generated dispatcher stub
uint64_t
patch__dispatch_full(patch_handle_t *handle, uint64_t *args, void *trampoline)
{
    patch_context_t ctx = {0};
    ctx.handle          = handle;

    // Copy arguments into context
    for (size_t i = 0; i < PATCH_REG_ARGS; i++) {
        ctx.args[i] = args[i];
    }

    // Call prologue if provided
    bool call_original = true;
    if (handle->prologue != nullptr) {
        call_original = handle->prologue(&ctx, handle->prologue_user_data);
        if (call_original) {
            // Copy potentially modified args back
            for (size_t i = 0; i < PATCH_REG_ARGS; i++) {
                args[i] = ctx.args[i];
            }
        }
    }

    uint64_t result;
    if (call_original) {
        // Call the original function via trampoline
        // Use function pointer with all 6 register arguments
        typedef uint64_t (*fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        fn_t fn = (fn_t)trampoline;
        result  = fn(args[0], args[1], args[2], args[3], args[4], args[5]);

        ctx.return_value = result;
    }
    else {
        result = ctx.return_value;
    }

    // Call epilogue if provided
    if (handle->epilogue != nullptr) {
        handle->epilogue(&ctx, handle->epilogue_user_data);
        result = ctx.return_value;
    }

    return result;
}

// Dispatcher stub size - enough for code + embedded data
#define DISPATCHER_STUB_SIZE 256

#ifdef PATCH_ARCH_ARM64

// ARM64 dispatcher stub:
// - Saves x0-x7 (arguments), x29, x30 (frame, link)
// - Calls patch__dispatch_full(handle, args_ptr, trampoline)
// - Returns result to caller

static void
write_arm64_dispatcher(uint8_t *code, patch_handle_t *handle, void *trampoline)
{
    uint32_t *p   = (uint32_t *)code;
    size_t    idx = 0;

    // We need 128 bytes of stack:
    // - 16 bytes: x29, x30
    // - 64 bytes: x0-x7 saved args
    // - 48 bytes: padding (could use for context but we use stack in dispatch_full)

    // stp x29, x30, [sp, #-128]!  ; save frame/link, allocate 128 bytes
    p[idx++] = 0xA9B87BFD;

    // stp x0, x1, [sp, #16]
    p[idx++] = 0xA90107E0;
    // stp x2, x3, [sp, #32]
    p[idx++] = 0xA9020FE2;
    // stp x4, x5, [sp, #48]
    p[idx++] = 0xA90317E4;
    // stp x6, x7, [sp, #64]
    p[idx++] = 0xA9041FE6;

    // mov x29, sp  ; set up frame pointer
    p[idx++] = 0x910003FD;

    // Embedded data offsets (at end of stub, 8-byte aligned)
    // Layout: [code...] [func_ptr@232] [handle@240] [trampoline@248]
    size_t data_base  = 232;
    size_t func_off   = data_base;
    size_t handle_off = data_base + 8;
    size_t tramp_off  = data_base + 16;

    // Load handle into x0: ldr x0, [pc, #offset]
    int64_t rel_handle = (int64_t)handle_off - (int64_t)(idx * 4);
    p[idx++]           = 0x58000000 | (((rel_handle / 4) & 0x7FFFF) << 5);

    // x1 = pointer to saved args (sp + 16): add x1, sp, #16
    p[idx++] = 0x910043E1;

    // Load trampoline into x2: ldr x2, [pc, #offset]
    int64_t rel_tramp = (int64_t)tramp_off - (int64_t)(idx * 4);
    p[idx++]          = 0x58000002 | (((rel_tramp / 4) & 0x7FFFF) << 5);

    // Load dispatch function into x16: ldr x16, [pc, #offset]
    int64_t rel_func = (int64_t)func_off - (int64_t)(idx * 4);
    p[idx++]         = 0x58000010 | (((rel_func / 4) & 0x7FFFF) << 5);

    // blr x16  ; call dispatch function
    p[idx++] = 0xD63F0200;

    // Return value is in x0

    // ldp x29, x30, [sp], #128  ; restore frame/link, deallocate
    p[idx++] = 0xA8C87BFD;

    // ret
    p[idx++] = 0xD65F03C0;

    // Embed the pointers at fixed offsets
    void *func_ptr = (void *)patch__dispatch_full;
    memcpy(code + func_off, &func_ptr, 8);
    memcpy(code + handle_off, &handle, 8);
    memcpy(code + tramp_off, &trampoline, 8);
}

#endif // PATCH_ARCH_ARM64

#ifdef PATCH_ARCH_X86_64

static void
write_x86_64_dispatcher(uint8_t *code, patch_handle_t *handle, void *trampoline)
{
    size_t idx = 0;

    // push rbp
    code[idx++] = 0x55;
    // mov rbp, rsp
    code[idx++] = 0x48;
    code[idx++] = 0x89;
    code[idx++] = 0xE5;

    // Allocate 128 bytes: sub rsp, 128
    code[idx++] = 0x48;
    code[idx++] = 0x81;
    code[idx++] = 0xEC;
    code[idx++] = 0x80;
    code[idx++] = 0x00;
    code[idx++] = 0x00;
    code[idx++] = 0x00;

    // Save argument registers at [rbp-48] through [rbp-8]
    // x86-64 SysV: rdi, rsi, rdx, rcx, r8, r9
    // We save them contiguously so we can pass a pointer

    // mov [rbp-48], rdi
    code[idx++] = 0x48;
    code[idx++] = 0x89;
    code[idx++] = 0x7D;
    code[idx++] = 0xD0;
    // mov [rbp-40], rsi
    code[idx++] = 0x48;
    code[idx++] = 0x89;
    code[idx++] = 0x75;
    code[idx++] = 0xD8;
    // mov [rbp-32], rdx
    code[idx++] = 0x48;
    code[idx++] = 0x89;
    code[idx++] = 0x55;
    code[idx++] = 0xE0;
    // mov [rbp-24], rcx
    code[idx++] = 0x48;
    code[idx++] = 0x89;
    code[idx++] = 0x4D;
    code[idx++] = 0xE8;
    // mov [rbp-16], r8
    code[idx++] = 0x4C;
    code[idx++] = 0x89;
    code[idx++] = 0x45;
    code[idx++] = 0xF0;
    // mov [rbp-8], r9
    code[idx++] = 0x4C;
    code[idx++] = 0x89;
    code[idx++] = 0x4D;
    code[idx++] = 0xF8;

    // Call patch__dispatch_full(handle, args, trampoline)
    // rdi = handle: movabs rdi, imm64
    code[idx++] = 0x48;
    code[idx++] = 0xBF;
    memcpy(code + idx, &handle, 8);
    idx += 8;

    // rsi = &args: lea rsi, [rbp-48]
    code[idx++] = 0x48;
    code[idx++] = 0x8D;
    code[idx++] = 0x75;
    code[idx++] = 0xD0;

    // rdx = trampoline: movabs rdx, imm64
    code[idx++] = 0x48;
    code[idx++] = 0xBA;
    memcpy(code + idx, &trampoline, 8);
    idx += 8;

    // movabs rax, patch__dispatch_full
    code[idx++]  = 0x48;
    code[idx++]  = 0xB8;
    void *fn_ptr = (void *)patch__dispatch_full;
    memcpy(code + idx, &fn_ptr, 8);
    idx += 8;

    // call rax
    code[idx++] = 0xFF;
    code[idx++] = 0xD0;

    // Return value is in rax

    // mov rsp, rbp
    code[idx++] = 0x48;
    code[idx++] = 0x89;
    code[idx++] = 0xEC;
    // pop rbp
    code[idx++] = 0x5D;
    // ret
    code[idx++] = 0xC3;
}

#endif // PATCH_ARCH_X86_64

patch_error_t
patch__dispatcher_create(patch_handle_t *handle, void **out)
{
    // Allocate executable memory for the dispatcher
    void         *code = nullptr;
    patch_error_t err  = platform_alloc_near(handle->target, DISPATCHER_STUB_SIZE, &code);
    if (err != PATCH_SUCCESS) {
        patch__set_error("failed to allocate dispatcher memory");
        return err;
    }

    // Zero the buffer first
    memset(code, 0, DISPATCHER_STUB_SIZE);

#ifdef PATCH_ARCH_ARM64
    write_arm64_dispatcher(code, handle, handle->trampoline->code);
#endif
#ifdef PATCH_ARCH_X86_64
    write_x86_64_dispatcher(code, handle, handle->trampoline->code);
#endif

    platform_flush_icache(code, DISPATCHER_STUB_SIZE);

    *out = code;
    return PATCH_SUCCESS;
}

void
patch__dispatcher_destroy(void *dispatcher)
{
    if (dispatcher != nullptr) {
        platform_free_exec(dispatcher, DISPATCHER_STUB_SIZE);
    }
}
