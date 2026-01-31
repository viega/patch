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
// fp_args points to saved FP registers (8 x 128-bit = 128 bytes)
// caller_stack points to the caller's stack frame (for accessing stack arguments)
uint64_t
patch__dispatch_full(patch_handle_t  *handle,
                     uint64_t        *args,
                     patch__fp_reg_t *fp_args,
                     void            *caller_stack,
                     void            *trampoline)
{
    patch_context_t ctx = {0};
    ctx.handle          = handle;
    ctx.caller_stack    = caller_stack;

    // Copy integer arguments into context
    for (size_t i = 0; i < PATCH_REG_ARGS; i++) {
        ctx.args[i] = args[i];
    }

    // Copy FP arguments into context
    for (size_t i = 0; i < PATCH_FP_REG_ARGS; i++) {
        ctx.fp_args[i] = fp_args[i];
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
            for (size_t i = 0; i < PATCH_FP_REG_ARGS; i++) {
                fp_args[i] = ctx.fp_args[i];
            }
        }
    }

    uint64_t result;
    if (call_original) {
        // Call the original function via trampoline
        // Use function pointer with all register arguments
        // Note: FP args are restored by the dispatcher stub before returning
#ifdef PATCH_ARCH_X86_64
        typedef uint64_t (*fn_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
        fn_t fn = (fn_t)trampoline;
        result  = fn(args[0], args[1], args[2], args[3], args[4], args[5]);
#else
        typedef uint64_t (*fn_t)(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, uint64_t, uint64_t);
        fn_t fn = (fn_t)trampoline;
        result  = fn(args[0], args[1], args[2], args[3],
                     args[4], args[5], args[6], args[7]);
#endif
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
// Increased for FP register save/restore
#define DISPATCHER_STUB_SIZE 384

#ifdef PATCH_ARCH_ARM64

// ARM64 dispatcher stub:
// - Saves x0-x7 (integer args), x29, x30 (frame, link)
// - Calls patch__dispatch_full(handle, args_ptr, fp_args_ptr, trampoline)
// - Returns result to caller
//
// Note: FP registers are saved to stack for fp_args pointer but not explicitly
// restored since the C calling convention preserves them across calls.

static void
write_arm64_dispatcher(uint8_t *code, patch_handle_t *handle, void *trampoline)
{
    uint32_t *p   = (uint32_t *)code;
    size_t    idx = 0;

    // Stack layout (256 bytes total):
    // [sp+0]:    x29, x30 (frame, link) - 16 bytes
    // [sp+16]:   x0-x7 (integer args) - 64 bytes
    // [sp+80]:   space for FP args (passed as pointer) - 128 bytes
    // [sp+208]:  padding - 48 bytes

    // stp x29, x30, [sp, #-256]!  ; save frame/link, allocate stack
    // Encoding: 10 1 01 100 1 imm7 Rt2 Rn Rt
    // imm7 = -256/8 = -32 = 0b1100000
    p[idx++] = 0xA9B07BFD;

    // Save integer registers x0-x7 at [sp+16]
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
    size_t data_base  = 232;
    size_t func_off   = data_base;
    size_t handle_off = data_base + 8;
    size_t tramp_off  = data_base + 16;

    // Load handle into x0: ldr x0, [pc, #offset]
    int64_t rel_handle = (int64_t)handle_off - (int64_t)(idx * 4);
    p[idx++]           = 0x58000000 | (((rel_handle / 4) & 0x7FFFF) << 5);

    // x1 = pointer to saved integer args (sp + 16): add x1, sp, #16
    p[idx++] = 0x910043E1;

    // x2 = pointer for FP args (sp + 80): add x2, sp, #80
    // Note: FP args not actually saved, but we need to pass a valid pointer
    p[idx++] = 0x91014002;

    // x3 = caller's stack pointer (sp + 256): add x3, sp, #256
    // After stp [sp, #-256]!, original sp is at sp+256, which is where
    // the caller's stack arguments begin
    // Encoding: sf=1 opc=00 10001 shift=00 imm12=0x100 Rn=11111(sp) Rd=00011(x3)
    p[idx++] = 0x910403E3;

    // Load trampoline into x4: ldr x4, [pc, #offset]
    int64_t rel_tramp = (int64_t)tramp_off - (int64_t)(idx * 4);
    p[idx++]          = 0x58000004 | (((rel_tramp / 4) & 0x7FFFF) << 5);

    // Load dispatch function into x16: ldr x16, [pc, #offset]
    int64_t rel_func = (int64_t)func_off - (int64_t)(idx * 4);
    p[idx++]         = 0x58000010 | (((rel_func / 4) & 0x7FFFF) << 5);

    // blr x16  ; call dispatch function
    p[idx++] = 0xD63F0200;

    // Return value is in x0

    // ldp x29, x30, [sp], #256  ; restore frame/link, deallocate
    p[idx++] = 0xA8D07BFD;

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

    // Stack layout (256 bytes):
    // [rbp-48]:   rdi, rsi, rdx, rcx, r8, r9 (integer args) - 48 bytes
    // [rbp-176]:  xmm0-xmm7 (FP args) - 128 bytes (8 x 16 bytes)
    // [rbp-256]:  padding/red zone

    // push rbp
    code[idx++] = 0x55;
    // mov rbp, rsp
    code[idx++] = 0x48;
    code[idx++] = 0x89;
    code[idx++] = 0xE5;

    // Allocate 256 bytes: sub rsp, 256
    code[idx++] = 0x48;
    code[idx++] = 0x81;
    code[idx++] = 0xEC;
    code[idx++] = 0x00;
    code[idx++] = 0x01;
    code[idx++] = 0x00;
    code[idx++] = 0x00;

    // Save integer argument registers at [rbp-48] through [rbp-8]
    // x86-64 SysV: rdi, rsi, rdx, rcx, r8, r9

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

    // Save XMM registers at [rbp-176] through [rbp-64]
    // Each movdqu is 16 bytes of data

    // movdqu [rbp-176], xmm0  (0F 11 45 50 in 32-bit offset form won't work, need disp32)
    // movups [rbp-176], xmm0  ; 0F 11 85 50 FF FF FF
    code[idx++] = 0x0F;
    code[idx++] = 0x11;
    code[idx++] = 0x85;
    code[idx++] = 0x50;  // -176 = 0xFFFFFF50
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups [rbp-160], xmm1
    code[idx++] = 0x0F;
    code[idx++] = 0x11;
    code[idx++] = 0x8D;
    code[idx++] = 0x60;  // -160 = 0xFFFFFF60
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups [rbp-144], xmm2
    code[idx++] = 0x0F;
    code[idx++] = 0x11;
    code[idx++] = 0x95;
    code[idx++] = 0x70;  // -144 = 0xFFFFFF70
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups [rbp-128], xmm3
    code[idx++] = 0x0F;
    code[idx++] = 0x11;
    code[idx++] = 0x9D;
    code[idx++] = 0x80;  // -128 = 0xFFFFFF80
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups [rbp-112], xmm4
    code[idx++] = 0x0F;
    code[idx++] = 0x11;
    code[idx++] = 0xA5;
    code[idx++] = 0x90;  // -112 = 0xFFFFFF90
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups [rbp-96], xmm5
    code[idx++] = 0x0F;
    code[idx++] = 0x11;
    code[idx++] = 0xAD;
    code[idx++] = 0xA0;  // -96 = 0xFFFFFFA0
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups [rbp-80], xmm6
    code[idx++] = 0x0F;
    code[idx++] = 0x11;
    code[idx++] = 0xB5;
    code[idx++] = 0xB0;  // -80 = 0xFFFFFFB0
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups [rbp-64], xmm7
    code[idx++] = 0x0F;
    code[idx++] = 0x11;
    code[idx++] = 0xBD;
    code[idx++] = 0xC0;  // -64 = 0xFFFFFFC0
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // Call patch__dispatch_full(handle, args, fp_args, caller_stack, trampoline)

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

    // rdx = &fp_args: lea rdx, [rbp-176]
    code[idx++] = 0x48;
    code[idx++] = 0x8D;
    code[idx++] = 0x95;
    code[idx++] = 0x50;  // -176
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // rcx = caller_stack: lea rcx, [rbp+16]
    // After push rbp; mov rbp, rsp:
    //   [rbp+0] = saved rbp
    //   [rbp+8] = return address
    //   [rbp+16] = first stack argument from caller
    code[idx++] = 0x48;
    code[idx++] = 0x8D;
    code[idx++] = 0x4D;
    code[idx++] = 0x10;  // +16

    // r8 = trampoline: movabs r8, imm64
    code[idx++] = 0x49;
    code[idx++] = 0xB8;
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

    // Restore XMM registers (in case prologue modified them)
    // movups xmm0, [rbp-176]
    code[idx++] = 0x0F;
    code[idx++] = 0x10;
    code[idx++] = 0x85;
    code[idx++] = 0x50;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups xmm1, [rbp-160]
    code[idx++] = 0x0F;
    code[idx++] = 0x10;
    code[idx++] = 0x8D;
    code[idx++] = 0x60;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups xmm2, [rbp-144]
    code[idx++] = 0x0F;
    code[idx++] = 0x10;
    code[idx++] = 0x95;
    code[idx++] = 0x70;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups xmm3, [rbp-128]
    code[idx++] = 0x0F;
    code[idx++] = 0x10;
    code[idx++] = 0x9D;
    code[idx++] = 0x80;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups xmm4, [rbp-112]
    code[idx++] = 0x0F;
    code[idx++] = 0x10;
    code[idx++] = 0xA5;
    code[idx++] = 0x90;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups xmm5, [rbp-96]
    code[idx++] = 0x0F;
    code[idx++] = 0x10;
    code[idx++] = 0xAD;
    code[idx++] = 0xA0;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups xmm6, [rbp-80]
    code[idx++] = 0x0F;
    code[idx++] = 0x10;
    code[idx++] = 0xB5;
    code[idx++] = 0xB0;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

    // movups xmm7, [rbp-64]
    code[idx++] = 0x0F;
    code[idx++] = 0x10;
    code[idx++] = 0xBD;
    code[idx++] = 0xC0;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;
    code[idx++] = 0xFF;

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
