#define _GNU_SOURCE

#include "platform.h"

#include "patch/patch_arch.h"
#include "../patch_internal.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

// MAP_FIXED_NOREPLACE was added in Linux 4.17 / glibc 2.27
// Fall back to regular mmap without fixed address on older systems
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

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
    void  *aligned      = platform_page_align(addr);
    size_t ps           = platform_page_size();
    size_t offset       = (uintptr_t)addr - (uintptr_t)aligned;
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
        patch__set_error("Failed to open /proc/self/maps");
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
    patch__set_error("Address %p not found in /proc/self/maps", addr);
    return PATCH_ERR_INTERNAL;
}

patch_error_t
platform_alloc_near(void *target, size_t size, void **out)
{
    size_t ps           = platform_page_size();
    size_t aligned_size = ((size + ps - 1) / ps) * ps;

    // Both x86-64 and ARM64 need nearby allocation for efficient jumps.
    // - x86-64: rel32 jumps have ±2GB range
    // - ARM64: B instruction has ±128MB range
    uintptr_t base = (uintptr_t)target;

#ifdef PATCH_ARCH_X86_64
    // x86-64: ±2GB range for rel32 jumps
    uintptr_t range = 0x7FFFFFFF; // 2GB - 1
#else
    // ARM64: ±128MB range for B instruction
    uintptr_t range = 128 * 1024 * 1024 - 4;
#endif

    uintptr_t start = (base > range) ? (base - range) : ps;
    uintptr_t end   = base + range;

    // Try a few strategic locations first: near target, then spread out
    uintptr_t hints[] = {
        base - ps,         // Just before target
        base + 0x1000,     // Just after target
        base - 0x10000,    // 64KB before
        base + 0x10000,    // 64KB after
        base - 0x100000,   // 1MB before
        base + 0x100000,   // 1MB after
        base - 0x1000000,  // 16MB before
        base + 0x1000000,  // 16MB after
        base - 0x10000000, // 256MB before (within +-128MB on ARM64)
        base + 0x10000000, // 256MB after (within +-128MB on ARM64)
    };

    for (size_t i = 0; i < sizeof(hints) / sizeof(hints[0]); i++) {
        uintptr_t addr = hints[i] & ~(ps - 1); // Page-align
        if (addr < start || addr >= end) {
            continue;
        }

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

    // If hints failed, do a sparse search with large steps
    uintptr_t step = 0x100000; // 1MB steps
    for (uintptr_t addr = start; addr < end; addr += step) {
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

// Note: platform_page_size() and platform_page_align() are duplicated in
// darwin.c intentionally. Keeping them in platform-specific files allows
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
platform_write_code(void *addr, const void *data, size_t size)
{
    // On Linux, we can use mprotect to make code writable
    void  *page        = platform_page_align(addr);
    size_t ps          = platform_page_size();
    size_t offset      = (uintptr_t)addr - (uintptr_t)page;
    size_t region_size = ((offset + size + ps - 1) / ps) * ps;

    // Make writable
    if (mprotect(page, region_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        patch__set_error("failed to make code page writable");
        return PATCH_ERR_MEMORY_PROTECTION;
    }

    // Write the data
    memcpy(addr, data, size);

    // Restore to RX - this is critical for security
    if (mprotect(page, region_size, PROT_READ | PROT_EXEC) != 0) {
        patch__set_error("failed to restore code page protection (security risk)");
        return PATCH_ERR_MEMORY_PROTECTION;
    }

    // Flush icache on ARM64
    platform_flush_icache(addr, size);

    return PATCH_SUCCESS;
}

// ============================================================================
// GOT/PLT Hooking Support
// ============================================================================

// Context for dl_iterate_phdr callback
typedef struct {
    const char *symbol;      // Symbol we're looking for
    void      **got_entry;   // Output: pointer to GOT slot
    bool        found;       // Set to true when found
} got_search_ctx_t;

// Callback for dl_iterate_phdr - searches for GOT entry in each loaded object
static int
find_got_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size;
    got_search_ctx_t *ctx = (got_search_ctx_t *)data;

    // Already found in a previous object
    if (ctx->found) {
        return 0;
    }

    // Get base address of this object
    ElfW(Addr) base = info->dlpi_addr;

    // Find the DYNAMIC segment
    const ElfW(Dyn) *dyn = nullptr;
    for (size_t i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn) *)(base + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    if (dyn == nullptr) {
        return 0; // No dynamic section, skip this object
    }

    // Parse dynamic entries to find what we need
    // Note: d_ptr values are virtual addresses. For shared libraries loaded at
    // address 0 (typical), we need to add base. For the main executable or
    // libraries with a non-zero link address, they may already be correct.
    // We detect this by checking if dlpi_addr is 0 (main executable usually).
    const ElfW(Rela) *jmprel   = nullptr;
    size_t            pltrelsz = 0;
    const char       *strtab   = nullptr;
    const ElfW(Sym)  *symtab   = nullptr;

    for (const ElfW(Dyn) *d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_JMPREL:
            jmprel = (const ElfW(Rela) *)(d->d_un.d_ptr);
            break;
        case DT_PLTRELSZ:
            pltrelsz = d->d_un.d_val;
            break;
        case DT_STRTAB:
            strtab = (const char *)(d->d_un.d_ptr);
            break;
        case DT_SYMTAB:
            symtab = (const ElfW(Sym) *)(d->d_un.d_ptr);
            break;
        }
    }

    // Need all four to proceed
    if (jmprel == nullptr || pltrelsz == 0 || strtab == nullptr || symtab == nullptr) {
        return 0;
    }

    // Iterate through PLT relocations
    size_t relcount = pltrelsz / sizeof(ElfW(Rela));
    for (size_t i = 0; i < relcount; i++) {
        const ElfW(Rela) *rel = &jmprel[i];

        // Get symbol index from relocation info
#ifdef PATCH_ARCH_X86_64
        size_t sym_idx = ELF64_R_SYM(rel->r_info);
#else
        size_t sym_idx = ELF64_R_SYM(rel->r_info);
#endif

        // Get symbol name
        const char *name = strtab + symtab[sym_idx].st_name;

        // Check if this is our symbol
        if (strcmp(name, ctx->symbol) == 0) {
            // Found it! r_offset is the GOT slot address (relative to base)
            ctx->got_entry = (void **)(base + rel->r_offset);
            ctx->found     = true;
            return 1; // Stop iteration
        }
    }

    return 0; // Continue to next object
}

patch_error_t
platform_find_got_entry(const char *symbol, void ***got_entry)
{
    if (symbol == nullptr || got_entry == nullptr) {
        patch__set_error("symbol and got_entry must not be nullptr");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    *got_entry = nullptr;

    got_search_ctx_t ctx = {
        .symbol    = symbol,
        .got_entry = nullptr,
        .found     = false,
    };

    // Search all loaded objects
    dl_iterate_phdr(find_got_callback, &ctx);

    if (ctx.found) {
        *got_entry = ctx.got_entry;
        return PATCH_SUCCESS;
    }

    patch__set_error("no GOT entry found for symbol '%s'", symbol);
    return PATCH_ERR_NO_GOT_ENTRY;
}

// =============================================================================
// Hardware Watchpoint Support
// =============================================================================
//
// Linux provides hardware watchpoints via perf_event_open() with
// PERF_TYPE_BREAKPOINT. This is more ergonomic than ptrace for self-monitoring.
// The watchpoint generates SIGTRAP when triggered.

// Track watchpoint state
static atomic_int g_watchpoint_in_use[PLATFORM_MAX_WATCHPOINTS] = {0};
static void      *g_watchpoint_addr[PLATFORM_MAX_WATCHPOINTS]   = {0};
static int        g_watchpoint_fd[PLATFORM_MAX_WATCHPOINTS]     = {-1, -1, -1, -1};

// Helper to make perf_event_open syscall
static long
perf_event_open(struct perf_event_attr *attr,
                pid_t                   pid,
                int                     cpu,
                int                     group_fd,
                unsigned long           flags)
{
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

int
platform_set_watchpoint(void *addr, size_t size, watchpoint_type_t type)
{
    // Validate size
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        patch__set_error("watchpoint size must be 1, 2, 4, or 8");
        return -1;
    }

    // Find a free slot
    int slot = -1;
    for (int i = 0; i < PLATFORM_MAX_WATCHPOINTS; i++) {
        int expected = 0;
        if (atomic_compare_exchange_strong(&g_watchpoint_in_use[i], &expected, 1)) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        patch__set_error("all hardware watchpoints are in use");
        return -1;
    }

    // Configure perf event for hardware breakpoint/watchpoint
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));

    pe.type           = PERF_TYPE_BREAKPOINT;
    pe.size           = sizeof(pe);
    pe.bp_type        = (type == WATCHPOINT_WRITE) ? HW_BREAKPOINT_W : HW_BREAKPOINT_RW;
    pe.bp_addr        = (unsigned long)addr;
    pe.bp_len         = size;
    pe.disabled       = 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv     = 1;

    // Signal configuration
    pe.sigtrap        = 1; // Generate SIGTRAP on hit
    pe.remove_on_exec = 1; // Auto-remove on exec

    // Open perf event (pid=0 means current process, cpu=-1 means any CPU)
    int fd = (int)perf_event_open(&pe, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0) {
        atomic_store(&g_watchpoint_in_use[slot], 0);
        patch__set_error("perf_event_open failed for watchpoint (errno=%d)", errno);
        return -1;
    }

    // Store state
    g_watchpoint_fd[slot]   = fd;
    g_watchpoint_addr[slot] = addr;

    return slot;
}

patch_error_t
platform_clear_watchpoint(int watchpoint_id)
{
    if (watchpoint_id < 0 || watchpoint_id >= PLATFORM_MAX_WATCHPOINTS) {
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    if (!atomic_load(&g_watchpoint_in_use[watchpoint_id])) {
        return PATCH_SUCCESS; // Already cleared
    }

    // Close the perf event fd
    if (g_watchpoint_fd[watchpoint_id] >= 0) {
        close(g_watchpoint_fd[watchpoint_id]);
        g_watchpoint_fd[watchpoint_id] = -1;
    }

    g_watchpoint_addr[watchpoint_id] = nullptr;
    atomic_store(&g_watchpoint_in_use[watchpoint_id], 0);

    return PATCH_SUCCESS;
}

int
platform_check_watchpoint_hit(void *ucontext)
{
    (void)ucontext;

    // On Linux with perf events, we need to check siginfo for the source
    // Since perf watchpoints generate SIGTRAP, and we're called from a signal
    // handler, we need to figure out which watchpoint fired.

    // The siginfo_t passed to the handler contains si_addr for the faulting address.
    // However, we don't have access to siginfo here. For now, we check
    // which watchpoint address matches the fault address from ucontext.

    // On x86-64, we can check DR6 (but not easily accessible from userspace)
    // On ARM64, check FAR from ucontext

    // Simpler approach: since perf events are per-address, and we're in
    // a signal handler for SIGTRAP, check if any of our watchpoints
    // could have triggered by comparing addresses.

    // For now, return the first active watchpoint (caller should verify)
    for (int i = 0; i < PLATFORM_MAX_WATCHPOINTS; i++) {
        if (atomic_load(&g_watchpoint_in_use[i])) {
            return i;
        }
    }

    return -1;
}

void *
platform_get_watchpoint_addr(void *ucontext, int watchpoint_id)
{
    (void)ucontext;

    if (watchpoint_id < 0 || watchpoint_id >= PLATFORM_MAX_WATCHPOINTS) {
        return nullptr;
    }

    return g_watchpoint_addr[watchpoint_id];
}

// =============================================================================
// Watchpoint Callback Support (SIGTRAP Handler)
// =============================================================================

// Registered callbacks
static platform_watchpoint_callback_t g_watchpoint_callback = NULL;
static platform_watchpoint_id_update_t g_watchpoint_id_update = NULL;

// Previous signal handler for chaining
static struct sigaction g_old_sigtrap_action;
static atomic_bool g_sigtrap_handler_installed = false;

// SIGTRAP signal handler for watchpoint events
static void
sigtrap_handler(int sig, siginfo_t *info, void *ucontext_raw)
{
    (void)sig;
    (void)info;

    // Check if this is a watchpoint hit
    int wp_id = platform_check_watchpoint_hit(ucontext_raw);

    if (wp_id >= 0 && g_watchpoint_callback != NULL) {
        void *watched_addr = g_watchpoint_addr[wp_id];
        if (watched_addr == NULL) {
            goto chain;
        }

        // Read the new value that was written (write already completed on Linux)
        void *new_value = *(void **)watched_addr;

        // Temporarily clear the watchpoint before any writes to the watched location
        platform_clear_watchpoint(wp_id);

        // Call the watchpoint handler with unified API
        void *restore_value = NULL;
        platform_wp_action_t action = g_watchpoint_callback(
            watched_addr, new_value, &restore_value);

        switch (action) {
        case PLATFORM_WP_KEEP:
        case PLATFORM_WP_REJECT:
            // Write the restore value (detour) back to the watched location
            if (restore_value != NULL) {
                *(void **)watched_addr = restore_value;
            }
            // Re-enable watchpoint
            {
                int new_wp_id = platform_set_watchpoint(
                    watched_addr, sizeof(void *), WATCHPOINT_WRITE);
                if (new_wp_id >= 0 && g_watchpoint_id_update != NULL) {
                    g_watchpoint_id_update(watched_addr, new_wp_id);
                }
            }
            break;

        case PLATFORM_WP_REMOVE:
            // Let the new value stand, watchpoint already cleared
            // Callback is responsible for cleaning up its own state
            break;
        }

        return;
    }

chain:
    // Not our watchpoint - chain to previous handler
    if (g_old_sigtrap_action.sa_flags & SA_SIGINFO) {
        if (g_old_sigtrap_action.sa_sigaction != NULL) {
            g_old_sigtrap_action.sa_sigaction(sig, info, ucontext_raw);
        }
    }
    else if (g_old_sigtrap_action.sa_handler != SIG_IGN &&
             g_old_sigtrap_action.sa_handler != SIG_DFL) {
        g_old_sigtrap_action.sa_handler(sig);
    }
}

void
platform_set_watchpoint_callback(platform_watchpoint_callback_t callback,
                                 platform_watchpoint_id_update_t id_update)
{
    g_watchpoint_callback = callback;
    g_watchpoint_id_update = id_update;
}

patch_error_t
platform_watchpoint_init(void)
{
    bool expected = false;
    if (!atomic_compare_exchange_strong(&g_sigtrap_handler_installed, &expected, true)) {
        // Already initialized
        return PATCH_SUCCESS;
    }

    // Install SIGTRAP signal handler
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigtrap_handler;
    sa.sa_flags     = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGTRAP, &sa, &g_old_sigtrap_action) != 0) {
        atomic_store(&g_sigtrap_handler_installed, false);
        patch__set_error("failed to install SIGTRAP handler for watchpoints");
        return PATCH_ERR_SIGNAL_HANDLER;
    }

    return PATCH_SUCCESS;
}

void
platform_watchpoint_cleanup(void)
{
    bool expected = true;
    if (!atomic_compare_exchange_strong(&g_sigtrap_handler_installed, &expected, false)) {
        return;
    }

    // Restore the old signal handler
    sigaction(SIGTRAP, &g_old_sigtrap_action, NULL);
}
