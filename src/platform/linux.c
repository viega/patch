#include "platform.h"

#include "patch/patch_arch.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int
prot_to_mman(mem_prot_t prot)
{
    switch (prot) {
    case MEM_PROT_NONE:
        return PROT_NONE;
    case MEM_PROT_R:
        return PROT_READ;
    case MEM_PROT_RW:
        return PROT_READ | PROT_WRITE;
    case MEM_PROT_RX:
        return PROT_READ | PROT_EXEC;
    case MEM_PROT_RWX:
        return PROT_READ | PROT_WRITE | PROT_EXEC;
    }
    return PROT_NONE;
}

patch_error_t
platform_protect(void *addr, size_t size, mem_prot_t prot)
{
    void  *aligned = platform_page_align(addr);
    size_t ps      = platform_page_size();
    size_t offset  = (uintptr_t)addr - (uintptr_t)aligned;
    size_t aligned_size = ((size + offset + ps - 1) / ps) * ps;

    if (mprotect(aligned, aligned_size, prot_to_mman(prot)) != 0) {
        return PATCH_ERR_MEMORY_PROTECTION;
    }
    return PATCH_SUCCESS;
}

patch_error_t
platform_get_protection(void *addr, mem_prot_t *out_prot)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        return PATCH_ERR_INTERNAL;
    }

    uintptr_t target = (uintptr_t)addr;
    char      line[512];

    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, end;
        char      perms[5] = {0};

        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3) {
            continue;
        }

        if (target >= start && target < end) {
            bool r = (perms[0] == 'r');
            bool w = (perms[1] == 'w');
            bool x = (perms[2] == 'x');

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

            fclose(fp);
            return PATCH_SUCCESS;
        }
    }

    fclose(fp);
    return PATCH_ERR_INTERNAL;
}

patch_error_t
platform_alloc_near(void *target, size_t size, void **out)
{
    size_t ps           = platform_page_size();
    size_t aligned_size = ((size + ps - 1) / ps) * ps;

#ifdef PATCH_ARCH_X86_64
    // Try to allocate within 2GB of target for rel32 jumps
    uintptr_t base  = (uintptr_t)target;
    uintptr_t start = (base > 0x7FFFFFFF) ? (base - 0x7FFFFFFF) : ps;
    uintptr_t end   = base + 0x7FFFFFFF;

    for (uintptr_t addr = start; addr < end; addr += ps) {
        void *p = mmap((void *)addr,
                       aligned_size,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                       -1,
                       0);
        if (p != MAP_FAILED) {
            *out = p;
            return PATCH_SUCCESS;
        }
    }
#else
    (void)target;  // Not used on ARM64 (uses absolute jumps)
#endif

    // Fallback: allocate anywhere
    void *p = mmap(nullptr,
                   aligned_size,
                   PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS,
                   -1,
                   0);
    if (p == MAP_FAILED) {
        return PATCH_ERR_ALLOCATION_FAILED;
    }

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
    __builtin___clear_cache((char *)addr, (char *)addr + size);
#else
    (void)addr;
    (void)size;
#endif
}

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
platform_write_code(void *addr, const void *data, size_t size)
{
    // On Linux, we can use mprotect to make code writable
    void  *page      = platform_page_align(addr);
    size_t ps        = platform_page_size();
    size_t offset    = (uintptr_t)addr - (uintptr_t)page;
    size_t region_size = ((offset + size + ps - 1) / ps) * ps;

    // Make writable
    if (mprotect(page, region_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return PATCH_ERR_MEMORY_PROTECTION;
    }

    // Write the data
    memcpy(addr, data, size);

    // Restore to RX
    mprotect(page, region_size, PROT_READ | PROT_EXEC);

    // Flush icache on ARM64
    platform_flush_icache(addr, size);

    return PATCH_SUCCESS;
}
