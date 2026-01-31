#include "platform.h"

#include "patch/patch_arch.h"

#include <mach/mach.h>
#include <mach/vm_map.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef PATCH_ARCH_ARM64
#include <libkern/OSCacheControl.h>
#endif

// =============================================================================
// Code Patching Stubs
// =============================================================================
//
// macOS (especially Apple Silicon) enforces hardware W^X - pages cannot be
// simultaneously writable and executable. This makes runtime code patching
// of existing functions impossible. The unified macro layer uses pointer
// indirection instead.
//
// These functions are stubbed to fail cleanly rather than maintaining complex
// code that cannot succeed on modern macOS.

patch_error_t
platform_write_code(void *addr, const void *data, size_t size)
{
    (void)addr;
    (void)data;
    (void)size;
    // Hardware W^X on Apple Silicon prevents code patching
    return PATCH_ERR_MEMORY_PROTECTION;
}

patch_error_t
platform_protect(void *addr, size_t size, mem_prot_t prot)
{
    (void)addr;
    (void)size;
    (void)prot;
    // Hardware W^X on Apple Silicon prevents changing code page protection
    return PATCH_ERR_MEMORY_PROTECTION;
}

patch_error_t
platform_get_protection(void *addr, mem_prot_t *out_prot)
{
    mach_port_t                    task    = mach_task_self();
    vm_address_t                   address = (vm_address_t)addr;
    vm_size_t                      vmsize;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t         info_count = VM_REGION_BASIC_INFO_COUNT_64;
    memory_object_name_t           object;

    kern_return_t kr = vm_region_64(task,
                                    &address,
                                    &vmsize,
                                    VM_REGION_BASIC_INFO_64,
                                    (vm_region_info_t)&info,
                                    &info_count,
                                    &object);
    if (kr != KERN_SUCCESS) {
        return PATCH_ERR_MEMORY_PROTECTION;
    }

    bool r = (info.protection & VM_PROT_READ) != 0;
    bool w = (info.protection & VM_PROT_WRITE) != 0;
    bool x = (info.protection & VM_PROT_EXECUTE) != 0;

    if (r && w && x) {
        *out_prot = MEM_PROT_RWX;
    }
    else if (r && x) {
        *out_prot = MEM_PROT_RX;
    }
    else if (r && w) {
        *out_prot = MEM_PROT_RW;
    }
    else if (r) {
        *out_prot = MEM_PROT_R;
    }
    else {
        *out_prot = MEM_PROT_NONE;
    }

    return PATCH_SUCCESS;
}

patch_error_t
platform_alloc_near(void *target, size_t size, void **out)
{
    (void)target;

    size_t ps           = platform_page_size();
    size_t aligned_size = ((size + ps - 1) / ps) * ps;

#ifdef PATCH_ARCH_ARM64
    // On ARM64 macOS, use MAP_JIT to get memory that can be switched
    // between writable and executable using pthread_jit_write_protect_np
    void *p = mmap(nullptr,
                   aligned_size,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT,
                   -1,
                   0);

    if (p == MAP_FAILED) {
        // Fallback: try without MAP_JIT (will work on non-hardened binaries)
        p = mmap(nullptr,
                 aligned_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS,
                 -1,
                 0);
    }
#else
    // On x86-64 macOS, standard mmap works
    void *p = mmap(nullptr,
                   aligned_size,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1,
                   0);
#endif

    if (p == MAP_FAILED) {
        return PATCH_ERR_ALLOCATION_FAILED;
    }

#ifdef PATCH_ARCH_ARM64
    // Enable write mode for initial code generation
    pthread_jit_write_protect_np(0); // 0 = writable
#endif

    *out = p;
    return PATCH_SUCCESS;
}

void
platform_free_exec(void *addr, size_t size)
{
    size_t ps           = platform_page_size();
    size_t aligned_size = ((size + ps - 1) / ps) * ps;
    munmap(addr, aligned_size);
}

void
platform_flush_icache(void *addr, size_t size)
{
#ifdef PATCH_ARCH_ARM64
    // Switch back to execute mode
    pthread_jit_write_protect_np(1); // 1 = executable

    sys_icache_invalidate(addr, size);
#else
    (void)addr;
    (void)size;
#endif
}

// Note: platform_page_size() and platform_page_align() are duplicated in
// linux.c intentionally. Keeping them in platform-specific files allows
// each platform to potentially use different implementations if needed,
// and keeps the platform abstraction clean.

size_t
platform_page_size(void)
{
    static size_t page_size = 0;
    if (page_size == 0) {
        page_size = (size_t)sysconf(_SC_PAGESIZE);
    }
    return page_size;
}

void *
platform_page_align(void *addr)
{
    size_t    ps = platform_page_size();
    uintptr_t a  = (uintptr_t)addr;
    return (void *)(a & ~(ps - 1));
}

patch_error_t
platform_find_got_entry(const char *symbol, void ***got_entry)
{
    (void)symbol;
    (void)got_entry;
    // GOT/PLT hooking requires ELF parsing, not supported on macOS
    // macOS uses different mechanisms (dyld interposing, etc.)
    return PATCH_ERR_NO_GOT_ENTRY;
}
