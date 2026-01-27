#include "patch_internal.h"

#include "arch/arch.h"
#include "platform/platform.h"

#include <stdlib.h>
#include <string.h>

patch_error_t
patch__trampoline_create(void *target, size_t prologue_size,
                         patch__trampoline_t **out)
{
    patch__trampoline_t *tramp = calloc(1, sizeof(*tramp));
    if (tramp == nullptr) {
        patch__set_error("Failed to allocate trampoline structure");
        return PATCH_ERR_ALLOCATION_FAILED;
    }

    // Allocate executable memory for the trampoline code
    void         *exec_mem = nullptr;
    patch_error_t err = platform_alloc_near(target, PATCH_TRAMPOLINE_SIZE, &exec_mem);
    if (err != PATCH_SUCCESS) {
        free(tramp);
        patch__set_error("Failed to allocate executable memory for trampoline");
        return err;
    }

    tramp->code       = exec_mem;
    tramp->alloc_size = PATCH_TRAMPOLINE_SIZE;

    // Copy and relocate the prologue bytes
    size_t relocated = arch_relocate((const uint8_t *)target,
                                     prologue_size,
                                     tramp->code,
                                     PATCH_TRAMPOLINE_SIZE - 16,
                                     (uintptr_t)target,
                                     (uintptr_t)tramp->code);

    if (relocated == 0) {
        platform_free_exec(tramp->code, tramp->alloc_size);
        free(tramp);
        patch__set_error("Failed to relocate prologue instructions");
        return PATCH_ERR_INTERNAL;
    }

    // Write jump back to original function after prologue
    uintptr_t resume_addr = (uintptr_t)target + prologue_size;
    size_t    jump_size = arch_write_jump(tramp->code + relocated,
                                          PATCH_TRAMPOLINE_SIZE - relocated,
                                          (uintptr_t)tramp->code + relocated,
                                          resume_addr);

    if (jump_size == 0) {
        platform_free_exec(tramp->code, tramp->alloc_size);
        free(tramp);
        patch__set_error("Failed to write trampoline return jump");
        return PATCH_ERR_INTERNAL;
    }

    // Flush instruction cache
    platform_flush_icache(tramp->code, relocated + jump_size);

    tramp->code_len        = relocated + jump_size;
    tramp->original_target = target;
    tramp->relocated_bytes = prologue_size;

    *out = tramp;
    return PATCH_SUCCESS;
}

void
patch__trampoline_destroy(patch__trampoline_t *tramp)
{
    if (tramp == nullptr) return;

    if (tramp->code != nullptr) {
        platform_free_exec(tramp->code, tramp->alloc_size);
    }
    free(tramp);
}

patch_error_t
patch__write_detour(void *target, void *destination, size_t available_size)
{
    size_t min_size = arch_min_prologue_size();
    if (available_size < min_size) {
        patch__set_error("Insufficient space for detour: need %zu bytes, have %zu",
                        min_size, available_size);
        return PATCH_ERR_INSUFFICIENT_SPACE;
    }

    // Make target writable
    void  *page      = platform_page_align(target);
    size_t page_size = platform_page_size();
    size_t offset    = (uintptr_t)target - (uintptr_t)page;
    size_t region_size = offset + available_size;
    if (region_size > page_size) {
        region_size = ((region_size + page_size - 1) / page_size) * page_size;
    }
    else {
        region_size = page_size;
    }

    patch_error_t err = platform_protect(page, region_size, MEM_PROT_RWX);
    if (err != PATCH_SUCCESS) {
        patch__set_error("Failed to make target writable");
        return err;
    }

    // Write the jump
    size_t written = arch_write_jump((uint8_t *)target,
                                     available_size,
                                     (uintptr_t)target,
                                     (uintptr_t)destination);

    if (written == 0) {
        patch__set_error("Failed to write detour jump");
        return PATCH_ERR_INTERNAL;
    }

    // Fill remaining bytes with NOPs
#ifdef PATCH_ARCH_X86_64
    for (size_t i = written; i < available_size; i++) {
        ((uint8_t *)target)[i] = 0x90;  // NOP
    }
#endif
#ifdef PATCH_ARCH_ARM64
    for (size_t i = written; i < available_size; i += 4) {
        uint32_t nop = 0xD503201F;
        memcpy((uint8_t *)target + i, &nop, 4);
    }
#endif

    // Restore execute permission
    err = platform_protect(page, region_size, MEM_PROT_RX);
    if (err != PATCH_SUCCESS) {
        // Non-fatal, but log it
        patch__set_error("Warning: failed to restore RX permission");
    }

    platform_flush_icache(target, available_size);

    return PATCH_SUCCESS;
}

patch_error_t
patch__restore_bytes(void *target, const uint8_t *original, size_t size)
{
    void  *page      = platform_page_align(target);
    size_t page_size = platform_page_size();
    size_t offset    = (uintptr_t)target - (uintptr_t)page;
    size_t region_size = offset + size;
    if (region_size > page_size) {
        region_size = ((region_size + page_size - 1) / page_size) * page_size;
    }
    else {
        region_size = page_size;
    }

    patch_error_t err = platform_protect(page, region_size, MEM_PROT_RWX);
    if (err != PATCH_SUCCESS) {
        patch__set_error("Failed to make target writable for restore");
        return err;
    }

    memcpy(target, original, size);

    err = platform_protect(page, region_size, MEM_PROT_RX);
    if (err != PATCH_SUCCESS) {
        patch__set_error("Warning: failed to restore RX permission");
    }

    platform_flush_icache(target, size);

    return PATCH_SUCCESS;
}
