#include "platform.h"

#include "patch/patch_arch.h"

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ucontext.h>
#include <unistd.h>

#ifdef PATCH_ARCH_ARM64
#include <mach/arm/thread_status.h>
#else
#include <mach/i386/thread_status.h>
#endif

#ifdef PATCH_ARCH_ARM64
#include <libkern/OSCacheControl.h>
#endif

// =============================================================================
// Code Patching Support
// =============================================================================
//
// macOS enforces W^X - pages cannot be simultaneously writable and executable.
// However, we CAN change protections sequentially: make writable (removing X),
// write our data, then make executable (removing W). This enables runtime code
// patching on macOS.

// Forward declaration for patch__set_error from patch_internal.h
void patch__set_error(const char *fmt, ...);

patch_error_t
platform_write_code(void *addr, const void *data, size_t size)
{
    void  *page        = platform_page_align(addr);
    size_t ps          = platform_page_size();
    size_t offset      = (uintptr_t)addr - (uintptr_t)page;
    size_t region_size = ((offset + size + ps - 1) / ps) * ps;

    // Step 1: Make writable (remove execute)
    // Use VM_PROT_COPY to request a copy-on-write copy of the page
    kern_return_t kr = vm_protect(mach_task_self(),
                                  (vm_address_t)page,
                                  region_size,
                                  FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        patch__set_error("vm_protect(RW|COPY) failed: %d", kr);
        return PATCH_ERR_MEMORY_PROTECTION;
    }

    // Step 2: Write the data
    memcpy(addr, data, size);

    // Step 3: Make executable (remove write)
    kr = vm_protect(mach_task_self(),
                    (vm_address_t)page,
                    region_size,
                    FALSE,
                    VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        patch__set_error("vm_protect(RX) failed: %d", kr);
        return PATCH_ERR_MEMORY_PROTECTION;
    }

    // Step 4: Flush icache (ARM64)
    platform_flush_icache(addr, size);

    return PATCH_SUCCESS;
}

static int
prot_to_vm(mem_prot_t prot)
{
    switch (prot) {
    case MEM_PROT_NONE:
        return VM_PROT_NONE;
    case MEM_PROT_R:
        return VM_PROT_READ;
    case MEM_PROT_RW:
        return VM_PROT_READ | VM_PROT_WRITE;
    case MEM_PROT_RX:
        return VM_PROT_READ | VM_PROT_EXECUTE;
    case MEM_PROT_RWX:
        return VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE;
    }
    return VM_PROT_NONE;
}

patch_error_t
platform_protect(void *addr, size_t size, mem_prot_t prot)
{
    void  *page        = platform_page_align(addr);
    size_t ps          = platform_page_size();
    size_t offset      = (uintptr_t)addr - (uintptr_t)page;
    size_t region_size = ((offset + size + ps - 1) / ps) * ps;

    kern_return_t kr = vm_protect(mach_task_self(),
                                  (vm_address_t)page,
                                  region_size,
                                  FALSE,
                                  prot_to_vm(prot));
    if (kr != KERN_SUCCESS) {
        return PATCH_ERR_MEMORY_PROTECTION;
    }

    return PATCH_SUCCESS;
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

// =============================================================================
// Mach-O Symbol Pointer Hooking Support
// =============================================================================
//
// macOS uses Mach-O binary format instead of ELF. The equivalent of ELF's GOT
// (Global Offset Table) is the symbol pointer sections:
//   - __DATA,__la_symbol_ptr: Lazy symbol pointers (most common)
//   - __DATA_CONST,__got: Non-lazy GOT (hardened binaries)
//   - __DATA,__nl_symbol_ptr: Non-lazy symbol pointers
//   - __DATA,__got: Another GOT variant
//
// The indirect symbol table maps entries in these sections to symbol names.

// Find a load command by type in a Mach-O header
static const struct load_command *
find_load_command(const struct mach_header_64 *header, uint32_t cmd_type)
{
    const uint8_t *ptr = (const uint8_t *)header + sizeof(struct mach_header_64);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)ptr;
        if (lc->cmd == cmd_type) {
            return lc;
        }
        ptr += lc->cmdsize;
    }

    return NULL;
}

// Find a section by segment and section name
static const struct section_64 *
find_section(const struct mach_header_64 *header,
             const char                  *segment_name,
             const char                  *section_name)
{
    const uint8_t *ptr = (const uint8_t *)header + sizeof(struct mach_header_64);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *lc = (const struct load_command *)ptr;

        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg =
                (const struct segment_command_64 *)lc;

            if (strncmp(seg->segname, segment_name, 16) == 0) {
                const struct section_64 *sections =
                    (const struct section_64 *)(seg + 1);

                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strncmp(sections[j].sectname, section_name, 16) == 0) {
                        return &sections[j];
                    }
                }
            }
        }

        ptr += lc->cmdsize;
    }

    return NULL;
}

// Search for a symbol in the indirect symbol table for a given section
static void **
find_symbol_pointer_in_section(const struct mach_header_64 *header,
                               intptr_t                     slide,
                               const struct section_64     *section,
                               const char                  *symbol_name)
{
    // Get symtab command for symbol table and string table
    const struct symtab_command *symtab =
        (const struct symtab_command *)find_load_command(header, LC_SYMTAB);
    if (!symtab) {
        return NULL;
    }

    // Get dysymtab command for indirect symbol table
    const struct dysymtab_command *dysymtab =
        (const struct dysymtab_command *)find_load_command(header, LC_DYSYMTAB);
    if (!dysymtab) {
        return NULL;
    }

    // Get pointers to tables (relative to header, not slide-adjusted)
    const struct nlist_64 *symbols =
        (const struct nlist_64 *)((uintptr_t)header + symtab->symoff);
    const char *strings = (const char *)((uintptr_t)header + symtab->stroff);
    const uint32_t *indirect_syms =
        (const uint32_t *)((uintptr_t)header + dysymtab->indirectsymoff);

    // Section's starting index in the indirect symbol table
    uint32_t indirect_start = section->reserved1;
    uint32_t entry_count    = (uint32_t)(section->size / sizeof(void *));

    // Symbol pointer array (needs slide adjustment since it's in memory)
    void **symbol_ptrs = (void **)(section->addr + slide);

    for (uint32_t i = 0; i < entry_count; i++) {
        uint32_t sym_idx = indirect_syms[indirect_start + i];

        // Skip special entries
        if (sym_idx == INDIRECT_SYMBOL_LOCAL ||
            sym_idx == INDIRECT_SYMBOL_ABS ||
            sym_idx == (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS)) {
            continue;
        }

        // Bounds check
        if (sym_idx >= symtab->nsyms) {
            continue;
        }

        const char *name = strings + symbols[sym_idx].n_un.n_strx;

        // Handle leading underscore (C symbols have it in Mach-O)
        const char *name_to_compare = name;
        if (name[0] == '_') {
            name_to_compare = name + 1;
        }

        if (strcmp(name_to_compare, symbol_name) == 0) {
            return &symbol_ptrs[i];
        }
    }

    return NULL;
}

patch_error_t
platform_find_got_entry(const char *symbol, void ***got_entry)
{
    if (symbol == NULL || got_entry == NULL) {
        patch__set_error("symbol and got_entry must not be NULL");
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    *got_entry = NULL;

    // Symbol pointer sections to search (in order of likelihood)
    static const char *sections[][2] = {
        {"__DATA", "__la_symbol_ptr"},
        {"__DATA_CONST", "__got"},
        {"__DATA", "__nl_symbol_ptr"},
        {"__DATA", "__got"},
    };

    // Iterate all loaded images
    uint32_t image_count = _dyld_image_count();
    for (uint32_t i = 0; i < image_count; i++) {
        const struct mach_header_64 *header =
            (const struct mach_header_64 *)_dyld_get_image_header(i);

        // Only handle 64-bit
        if (header->magic != MH_MAGIC_64) {
            continue;
        }

        // Skip images in the dyld shared cache - their symbol table offsets
        // are file offsets that don't work in memory. The MH_DYLIB_IN_CACHE
        // flag (0x80000000) indicates this on macOS 11+.
        if (header->flags & 0x80000000) {
            continue;
        }

        intptr_t slide = _dyld_get_image_vmaddr_slide(i);

        // Try each symbol pointer section type
        for (size_t j = 0; j < sizeof(sections) / sizeof(sections[0]); j++) {
            const struct section_64 *sect =
                find_section(header, sections[j][0], sections[j][1]);
            if (!sect) {
                continue;
            }

            void **slot =
                find_symbol_pointer_in_section(header, slide, sect, symbol);
            if (slot) {
                *got_entry = slot;
                return PATCH_SUCCESS;
            }
        }
    }

    patch__set_error("no symbol pointer entry found for '%s'", symbol);
    return PATCH_ERR_NO_GOT_ENTRY;
}

// =============================================================================
// Hardware Watchpoint Support (Mach Exception Based)
// =============================================================================
//
// macOS requires Mach exception handling for hardware watchpoints. SIGTRAP
// signals are NOT delivered for hardware debug exceptions - only Mach exceptions
// work.
//
// Architecture:
// 1. A background thread runs the Mach exception server
// 2. task_set_exception_ports() registers us for EXC_BREAKPOINT
// 3. When a watchpoint triggers, the exception is delivered to our port
// 4. The exception arrives BEFORE the write completes
// 5. We can intercept, inspect, and decide whether to allow/modify the write
//
// ARM64: Uses watchpoint registers WVR0-WVR5, WCR0-WCR5 (only 6 work on macOS)
// x86-64: Uses debug registers DR0-DR3, DR6, DR7

#include <pthread.h>

// Track which watchpoints are in use
static atomic_int g_watchpoint_in_use[PLATFORM_MAX_WATCHPOINTS] = {0};

// Track watched addresses
static void *g_watchpoint_addr[PLATFORM_MAX_WATCHPOINTS] = {0};

// Mach exception handling state
static mach_port_t g_exception_port           = MACH_PORT_NULL;
static pthread_t   g_exception_thread         = 0;
static atomic_bool g_exception_server_running = false;

// Callbacks for watchpoint hits (set by watchpoint.c via platform_set_watchpoint_callback)
static platform_watchpoint_callback_t g_watchpoint_callback = NULL;
static platform_watchpoint_id_update_t g_watchpoint_id_update = NULL;

// Forward declaration - implemented in ARM64 section below
#ifdef PATCH_ARCH_ARM64
static patch_error_t clear_watchpoint_on_thread(int watchpoint_id, thread_t target_thread);
#endif

// Exception message structures
typedef struct {
    mach_msg_header_t          Head;
    mach_msg_body_t            msgh_body;
    mach_msg_port_descriptor_t thread;
    mach_msg_port_descriptor_t task;
    NDR_record_t               NDR;
    exception_type_t           exception;
    mach_msg_type_number_t     codeCnt;
    int64_t                    code[2];
} mach_exception_raise_request_t;

typedef struct {
    mach_msg_header_t Head;
    NDR_record_t      NDR;
    kern_return_t     RetCode;
} mach_exception_raise_reply_t;

// Find which watchpoint was hit based on fault address
static int
find_watchpoint_for_addr(uint64_t fault_addr)
{
    for (int i = 0; i < PLATFORM_MAX_WATCHPOINTS; i++) {
        if (!atomic_load(&g_watchpoint_in_use[i])) {
            continue;
        }
        void    *watched = g_watchpoint_addr[i];
        uint64_t w_start = (uint64_t)watched;

        // Check if fault is in the watched range (8-byte aligned)
        uint64_t aligned_fault = fault_addr & ~7ULL;
        uint64_t aligned_watch = w_start & ~7ULL;
        if (aligned_fault == aligned_watch) {
            return i;
        }
    }
    return -1;
}

#ifdef PATCH_ARCH_ARM64
// Get the value of an ARM64 general-purpose register from thread state
static uint64_t
get_gpr(arm_thread_state64_t *ts, int reg)
{
    if (reg == 31) {
        return ts->__sp; // SP
    }
    if (reg < 0 || reg > 30) {
        return 0;
    }
    return ts->__x[reg];
}

// Decode an ARM64 store instruction and extract the value being written.
// Returns true if this is a store instruction we can handle.
// Supports: STR Xt, [Xn] and variants (most common for pointer stores)
static bool
decode_store_and_get_value(thread_t thread, uint64_t fault_addr, uint64_t *value_out)
{
    // Get thread state to read PC and registers
    arm_thread_state64_t   ts;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t          kr    = thread_get_state(thread, ARM_THREAD_STATE64,
                                            (thread_state_t)&ts, &count);
    if (kr != KERN_SUCCESS) {
        return false;
    }

    // Read the instruction at PC
    uint64_t pc   = ts.__pc;
    uint32_t insn = *(uint32_t *)pc;

    // Check for various store instructions that could write a 64-bit value:
    // STR Xt, [Xn, #imm12]     - 1111100100 imm12 Rn Rt
    // STR Xt, [Xn, #simm9]!    - 11111000000 simm9 11 Rn Rt (pre-index)
    // STR Xt, [Xn], #simm9     - 11111000000 simm9 01 Rn Rt (post-index)
    // STR Xt, [Xn, Xm]         - 11111000001 Rm opt S 10 Rn Rt

    // STR (immediate, unsigned offset): 1111 1001 00xx xxxx xxxx xxxx xxxx xxxx
    if ((insn & 0xFFC00000) == 0xF9000000) {
        // STR Xt, [Xn, #imm12]
        int rt = insn & 0x1F;           // Source register
        *value_out = get_gpr(&ts, rt);
        return true;
    }

    // STR (immediate, pre/post-index): 1111 1000 000x xxxx xxxx xx0x xxxx xxxx
    if ((insn & 0xFFE00C00) == 0xF8000000 ||  // pre-index (opc=11)
        (insn & 0xFFE00C00) == 0xF8000400) {  // post-index (opc=01)
        int rt     = insn & 0x1F;
        *value_out = get_gpr(&ts, rt);
        return true;
    }

    // STR (register): 1111 1000 001x xxxx xxxx 10xx xxxx xxxx
    if ((insn & 0xFFE00C00) == 0xF8200800) {
        int rt     = insn & 0x1F;
        *value_out = get_gpr(&ts, rt);
        return true;
    }

    // STUR (unscaled immediate): 1111 1000 000x xxxx xxxx 00xx xxxx xxxx
    if ((insn & 0xFFE00C00) == 0xF8000000) {
        int rt     = insn & 0x1F;
        *value_out = get_gpr(&ts, rt);
        return true;
    }

    (void)fault_addr; // May use in future for more complex decoding
    return false;
}

// Skip the current instruction on the faulting thread
static patch_error_t
skip_current_instruction(thread_t thread)
{
    arm_thread_state64_t   ts;
    mach_msg_type_number_t count = ARM_THREAD_STATE64_COUNT;
    kern_return_t          kr    = thread_get_state(thread, ARM_THREAD_STATE64,
                                            (thread_state_t)&ts, &count);
    if (kr != KERN_SUCCESS) {
        return PATCH_ERR_INTERNAL;
    }

    // ARM64 instructions are 4 bytes
    ts.__pc += 4;

    kr = thread_set_state(thread, ARM_THREAD_STATE64,
                          (thread_state_t)&ts, ARM_THREAD_STATE64_COUNT);
    if (kr != KERN_SUCCESS) {
        return PATCH_ERR_INTERNAL;
    }

    return PATCH_SUCCESS;
}
#endif // PATCH_ARCH_ARM64

// Exception server thread
static void *
exception_server_thread(void *arg)
{
    (void)arg;

    while (atomic_load(&g_exception_server_running)) {
        union {
            mach_exception_raise_request_t request;
            char                           buffer[1024];
        } msg;

        // Wait for exception with timeout so we can check if we should stop
        kern_return_t kr = mach_msg(&msg.request.Head,
                                    MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                    0,
                                    sizeof(msg),
                                    g_exception_port,
                                    1000, // 1 second timeout
                                    MACH_PORT_NULL);

        if (kr == MACH_RCV_TIMED_OUT) {
            continue; // Check if we should stop
        }

        if (kr != KERN_SUCCESS) {
            continue;
        }

        // Handle EXC_BREAKPOINT (includes watchpoints)
        if (msg.request.exception == EXC_BREAKPOINT) {
            thread_t faulting_thread = msg.request.thread.name;

#ifdef PATCH_ARCH_ARM64
            // Get exception state to find fault address
            arm_exception_state64_t exc_state;
            mach_msg_type_number_t  exc_count = ARM_EXCEPTION_STATE64_COUNT;
            kr = thread_get_state(faulting_thread,
                                  ARM_EXCEPTION_STATE64,
                                  (thread_state_t)&exc_state,
                                  &exc_count);
            uint64_t fault_addr = (kr == KERN_SUCCESS) ? exc_state.__far : 0;

            int wp_id = find_watchpoint_for_addr(fault_addr);

            if (wp_id >= 0 && g_watchpoint_callback != NULL) {
                void *watched_addr = g_watchpoint_addr[wp_id];

                // Decode the store instruction to get the new value being written
                uint64_t new_value_raw = 0;
                void    *new_value     = NULL;
                if (decode_store_and_get_value(faulting_thread, fault_addr, &new_value_raw)) {
                    new_value = (void *)new_value_raw;
                }

                // Call the watchpoint handler with unified API
                void *restore_value = NULL;
                platform_wp_action_t wp_action = g_watchpoint_callback(
                    watched_addr, new_value, &restore_value);

                // Handle action
                if (wp_action == PLATFORM_WP_KEEP || wp_action == PLATFORM_WP_REJECT) {
                    // KEEP or REJECT: Skip the instruction to prevent the write
                    // Memory already has the correct value (restore_value/detour)
                    skip_current_instruction(faulting_thread);
                }
                else if (wp_action == PLATFORM_WP_REMOVE) {
                    // REMOVE: Clear watchpoint on faulting thread so write can proceed
                    clear_watchpoint_on_thread(wp_id, faulting_thread);
                }
            }
#else
            // x86-64: TODO - implement similar logic for watchpoint handling
            (void)faulting_thread;
#endif
        }

        // Reply to resume execution
        mach_exception_raise_reply_t reply     = {0};
        reply.Head.msgh_bits                   = MACH_MSGH_BITS(MACH_MSG_TYPE_MOVE_SEND_ONCE, 0);
        reply.Head.msgh_size                   = sizeof(reply);
        reply.Head.msgh_remote_port            = msg.request.Head.msgh_remote_port;
        reply.Head.msgh_local_port             = MACH_PORT_NULL;
        reply.Head.msgh_id                     = msg.request.Head.msgh_id + 100;
        reply.NDR                              = NDR_record;
        reply.RetCode                          = KERN_SUCCESS;

        mach_msg(&reply.Head,
                 MACH_SEND_MSG,
                 sizeof(reply),
                 0,
                 MACH_PORT_NULL,
                 MACH_MSG_TIMEOUT_NONE,
                 MACH_PORT_NULL);
    }

    return NULL;
}

// Initialize Mach exception handling
static patch_error_t
init_mach_exception_handler(void)
{
    if (atomic_load(&g_exception_server_running)) {
        return PATCH_SUCCESS; // Already running
    }

    // Create exception port
    kern_return_t kr = mach_port_allocate(mach_task_self(),
                                          MACH_PORT_RIGHT_RECEIVE,
                                          &g_exception_port);
    if (kr != KERN_SUCCESS) {
        patch__set_error("mach_port_allocate failed: %d", kr);
        return PATCH_ERR_INTERNAL;
    }

    // Add send right
    kr = mach_port_insert_right(mach_task_self(),
                                g_exception_port,
                                g_exception_port,
                                MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), g_exception_port);
        g_exception_port = MACH_PORT_NULL;
        patch__set_error("mach_port_insert_right failed: %d", kr);
        return PATCH_ERR_INTERNAL;
    }

    // Register for EXC_BREAKPOINT exceptions
#ifdef PATCH_ARCH_ARM64
    thread_state_flavor_t flavor = ARM_THREAD_STATE64;
#else
    thread_state_flavor_t flavor = x86_THREAD_STATE64;
#endif

    kr = task_set_exception_ports(mach_task_self(),
                                  EXC_MASK_BREAKPOINT,
                                  g_exception_port,
                                  EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES,
                                  flavor);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), g_exception_port);
        g_exception_port = MACH_PORT_NULL;
        patch__set_error("task_set_exception_ports failed: %d", kr);
        return PATCH_ERR_INTERNAL;
    }

    // Start exception server thread
    atomic_store(&g_exception_server_running, true);
    if (pthread_create(&g_exception_thread, NULL, exception_server_thread, NULL) != 0) {
        atomic_store(&g_exception_server_running, false);
        mach_port_deallocate(mach_task_self(), g_exception_port);
        g_exception_port = MACH_PORT_NULL;
        patch__set_error("pthread_create for exception server failed");
        return PATCH_ERR_INTERNAL;
    }

    return PATCH_SUCCESS;
}

// Set callbacks for watchpoint hits (unified API)
void
platform_set_watchpoint_callback(platform_watchpoint_callback_t callback,
                                 platform_watchpoint_id_update_t id_update)
{
    g_watchpoint_callback = callback;
    g_watchpoint_id_update = id_update;
    (void)g_watchpoint_id_update; // Not used on macOS - watchpoint ID doesn't change
}

// Initialize watchpoint subsystem
patch_error_t
platform_watchpoint_init(void)
{
    // On macOS, the Mach exception handler is initialized lazily
    // when the first watchpoint is set (in platform_set_watchpoint).
    // Nothing to do here.
    return PATCH_SUCCESS;
}

// Cleanup watchpoint subsystem
void
platform_watchpoint_cleanup(void)
{
    // Stop exception server thread if running
    if (atomic_load(&g_exception_server_running)) {
        atomic_store(&g_exception_server_running, false);
        if (g_exception_thread != 0) {
            pthread_join(g_exception_thread, NULL);
            g_exception_thread = 0;
        }
        if (g_exception_port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), g_exception_port);
            g_exception_port = MACH_PORT_NULL;
        }
    }
}

#ifdef PATCH_ARCH_X86_64

// DR7 control register bits:
// Bits 0-1: L0/G0 - Local/Global enable for DR0 (we use local)
// Bits 2-3: L1/G1 - for DR1
// Bits 4-5: L2/G2 - for DR2
// Bits 6-7: L3/G3 - for DR3
// Bits 16-17: R/W0 - condition for DR0 (00=exec, 01=write, 11=read/write)
// Bits 18-19: LEN0 - size for DR0 (00=1, 01=2, 11=4, 10=8)
// Similar patterns repeat for DR1-DR3 at higher bit positions

static uint64_t
make_dr7_bits(int idx, watchpoint_type_t type, size_t size)
{
    uint64_t dr7 = 0;

    // Local enable bit for this watchpoint
    dr7 |= (1ULL << (idx * 2));

    // Condition bits: write=1, read/write=3
    int condition = (type == WATCHPOINT_WRITE) ? 1 : 3;
    dr7 |= ((uint64_t)condition << (16 + idx * 4));

    // Length bits: 1->00, 2->01, 4->11, 8->10
    int len_bits;
    switch (size) {
    case 1:
        len_bits = 0;
        break;
    case 2:
        len_bits = 1;
        break;
    case 4:
        len_bits = 3;
        break;
    case 8:
        len_bits = 2;
        break;
    default:
        len_bits = 0;
    }
    dr7 |= ((uint64_t)len_bits << (18 + idx * 4));

    return dr7;
}

static uint64_t
clear_dr7_bits(uint64_t dr7, int idx)
{
    // Clear local enable
    dr7 &= ~(1ULL << (idx * 2));
    // Clear condition and length bits
    dr7 &= ~(0xFULL << (16 + idx * 4));
    return dr7;
}

int
platform_set_watchpoint(void *addr, size_t size, watchpoint_type_t type)
{
    // Validate size (must be 1, 2, 4, or 8)
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        patch__set_error("watchpoint size must be 1, 2, 4, or 8");
        return -1;
    }

    // Find a free watchpoint slot
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

    // Get current debug state
    x86_debug_state64_t     debug_state;
    mach_msg_type_number_t  count = x86_DEBUG_STATE64_COUNT;
    thread_t                thread = mach_thread_self();

    kern_return_t kr = thread_get_state(thread,
                                        x86_DEBUG_STATE64,
                                        (thread_state_t)&debug_state,
                                        &count);
    if (kr != KERN_SUCCESS) {
        atomic_store(&g_watchpoint_in_use[slot], 0);
        patch__set_error("failed to get debug state: %d", kr);
        return -1;
    }

    // Set the address register
    switch (slot) {
    case 0:
        debug_state.__dr0 = (uint64_t)addr;
        break;
    case 1:
        debug_state.__dr1 = (uint64_t)addr;
        break;
    case 2:
        debug_state.__dr2 = (uint64_t)addr;
        break;
    case 3:
        debug_state.__dr3 = (uint64_t)addr;
        break;
    }

    // Update DR7 control register
    debug_state.__dr7 |= make_dr7_bits(slot, type, size);

    // Apply the debug state
    kr = thread_set_state(thread,
                          x86_DEBUG_STATE64,
                          (thread_state_t)&debug_state,
                          x86_DEBUG_STATE64_COUNT);

    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        atomic_store(&g_watchpoint_in_use[slot], 0);
        patch__set_error("failed to set debug state: %d", kr);
        return -1;
    }

    // Store address for lookup
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

    // Get current debug state
    x86_debug_state64_t     debug_state;
    mach_msg_type_number_t  count = x86_DEBUG_STATE64_COUNT;
    thread_t                thread = mach_thread_self();

    kern_return_t kr = thread_get_state(thread,
                                        x86_DEBUG_STATE64,
                                        (thread_state_t)&debug_state,
                                        &count);
    if (kr != KERN_SUCCESS) {
        mach_port_deallocate(mach_task_self(), thread);
        return PATCH_ERR_INTERNAL;
    }

    // Clear the address register
    switch (watchpoint_id) {
    case 0:
        debug_state.__dr0 = 0;
        break;
    case 1:
        debug_state.__dr1 = 0;
        break;
    case 2:
        debug_state.__dr2 = 0;
        break;
    case 3:
        debug_state.__dr3 = 0;
        break;
    }

    // Clear DR7 control bits
    debug_state.__dr7 = clear_dr7_bits(debug_state.__dr7, watchpoint_id);

    // Clear DR6 status bit for this watchpoint
    debug_state.__dr6 &= ~(1ULL << watchpoint_id);

    // Apply the debug state
    kr = thread_set_state(thread,
                          x86_DEBUG_STATE64,
                          (thread_state_t)&debug_state,
                          x86_DEBUG_STATE64_COUNT);

    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        return PATCH_ERR_INTERNAL;
    }

    g_watchpoint_addr[watchpoint_id] = nullptr;
    atomic_store(&g_watchpoint_in_use[watchpoint_id], 0);

    return PATCH_SUCCESS;
}

int
platform_check_watchpoint_hit(void *ucontext)
{
    (void)ucontext;

    // Get debug status register (DR6)
    x86_debug_state64_t    debug_state;
    mach_msg_type_number_t count  = x86_DEBUG_STATE64_COUNT;
    thread_t               thread = mach_thread_self();

    kern_return_t kr = thread_get_state(thread,
                                        x86_DEBUG_STATE64,
                                        (thread_state_t)&debug_state,
                                        &count);
    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        return -1;
    }

    // Check DR6 bits 0-3 for which watchpoint triggered
    for (int i = 0; i < PLATFORM_MAX_WATCHPOINTS; i++) {
        if ((debug_state.__dr6 & (1ULL << i)) && atomic_load(&g_watchpoint_in_use[i])) {
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

#endif // PATCH_ARCH_X86_64

#ifdef PATCH_ARCH_ARM64

// ARM64 Watchpoint Control Register (WCR) format:
// Bit 0: E (enable)
// Bits 1-2: PAC (privileged access control) - 10 = EL0 only
// Bits 3-4: LSC (load/store control) - 01=load, 10=store, 11=both
// Bits 5-12: BAS (byte address select) - which bytes within 8-byte range
// Bits 13-15: HMC, SSC, LBN (not used)
// Bits 16-19: MASK (address mask, 0=no mask)
// Bits 20-28: Reserved
// Bits 29-31: WT (watchpoint type, must be 0)

static uint32_t
make_wcr_bits(watchpoint_type_t type, size_t size)
{
    uint32_t wcr = 0;

    // Enable bit
    wcr |= 1;

    // PAC: EL0 only (user mode)
    wcr |= (2 << 1);

    // LSC: store=2, load/store=3
    int lsc = (type == WATCHPOINT_WRITE) ? 2 : 3;
    wcr |= (lsc << 3);

    // BAS: byte address select (which bytes to watch)
    // For size N, set N bits starting from appropriate position
    uint32_t bas;
    switch (size) {
    case 1:
        bas = 0x01;
        break;
    case 2:
        bas = 0x03;
        break;
    case 4:
        bas = 0x0F;
        break;
    case 8:
        bas = 0xFF;
        break;
    default:
        bas = 0xFF;
    }
    wcr |= (bas << 5);

    return wcr;
}

int
platform_set_watchpoint(void *addr, size_t size, watchpoint_type_t type)
{
    // Validate size
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        patch__set_error("watchpoint size must be 1, 2, 4, or 8");
        return -1;
    }

    // Initialize Mach exception handler on first watchpoint
    patch_error_t err = init_mach_exception_handler();
    if (err != PATCH_SUCCESS) {
        return -1;
    }

    // ARM64 watchpoints must be naturally aligned to 8 bytes
    // The BAS field selects which bytes within the 8-byte region to watch
    uintptr_t aligned_addr = (uintptr_t)addr & ~7ULL;

    // Find a free watchpoint slot
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

    // Get current debug state
    arm_debug_state64_t    debug_state;
    mach_msg_type_number_t count  = ARM_DEBUG_STATE64_COUNT;
    thread_t               thread = mach_thread_self();

    kern_return_t kr = thread_get_state(thread,
                                        ARM_DEBUG_STATE64,
                                        (thread_state_t)&debug_state,
                                        &count);
    if (kr != KERN_SUCCESS) {
        atomic_store(&g_watchpoint_in_use[slot], 0);
        mach_port_deallocate(mach_task_self(), thread);
        patch__set_error("failed to get debug state: %d", kr);
        return -1;
    }

    // Set watchpoint value register (address)
    debug_state.__wvr[slot] = aligned_addr;

    // Set watchpoint control register
    // Adjust BAS for offset within 8-byte aligned region
    size_t offset = (uintptr_t)addr - aligned_addr;
    uint32_t wcr = make_wcr_bits(type, size);
    // Shift BAS left by offset to watch the correct bytes
    uint32_t bas = ((wcr >> 5) & 0xFF) << offset;
    wcr = (wcr & ~(0xFF << 5)) | (bas << 5);

    debug_state.__wcr[slot] = wcr;

    // Enable MDSCR_EL1.MDE (Monitor Debug Events) - needed for watchpoints
    // This is typically already enabled by macOS

    // Apply the debug state
    kr = thread_set_state(thread,
                          ARM_DEBUG_STATE64,
                          (thread_state_t)&debug_state,
                          ARM_DEBUG_STATE64_COUNT);

    mach_port_deallocate(mach_task_self(), thread);

    if (kr != KERN_SUCCESS) {
        atomic_store(&g_watchpoint_in_use[slot], 0);
        patch__set_error("failed to set debug state: %d", kr);
        return -1;
    }

    // Store address for lookup
    g_watchpoint_addr[slot] = addr;

    return slot;
}

// Internal: clear watchpoint on a specific thread (used from exception handler)
static patch_error_t
clear_watchpoint_on_thread(int watchpoint_id, thread_t target_thread)
{
    if (watchpoint_id < 0 || watchpoint_id >= PLATFORM_MAX_WATCHPOINTS) {
        return PATCH_ERR_INVALID_ARGUMENT;
    }

    // Get debug state from target thread
    arm_debug_state64_t    debug_state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;

    kern_return_t kr = thread_get_state(target_thread,
                                        ARM_DEBUG_STATE64,
                                        (thread_state_t)&debug_state,
                                        &count);
    if (kr != KERN_SUCCESS) {
        return PATCH_ERR_INTERNAL;
    }

    // Clear watchpoint registers
    debug_state.__wvr[watchpoint_id] = 0;
    debug_state.__wcr[watchpoint_id] = 0;

    // Apply the debug state to target thread
    kr = thread_set_state(target_thread,
                          ARM_DEBUG_STATE64,
                          (thread_state_t)&debug_state,
                          ARM_DEBUG_STATE64_COUNT);

    if (kr != KERN_SUCCESS) {
        return PATCH_ERR_INTERNAL;
    }

    g_watchpoint_addr[watchpoint_id] = nullptr;
    atomic_store(&g_watchpoint_in_use[watchpoint_id], 0);

    return PATCH_SUCCESS;
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

    thread_t thread = mach_thread_self();
    patch_error_t result = clear_watchpoint_on_thread(watchpoint_id, thread);
    mach_port_deallocate(mach_task_self(), thread);
    return result;
}

int
platform_check_watchpoint_hit(void *ucontext)
{
    (void)ucontext;

    // On ARM64, we need to check ESR_EL1 to determine the cause
    // In signal context, we can check FAR_EL1 (fault address)
    // and compare against our registered watchpoint addresses

    // For now, check if FAR matches any of our watchpoints
    // This is called from signal handler where we have access to ucontext

    // The ucontext contains the exception state including ESR and FAR
    // On macOS, we can access this through the mcontext
    if (ucontext == nullptr) {
        return -1;
    }

    ucontext_t *uc  = (ucontext_t *)ucontext;
    uint64_t    far = uc->uc_mcontext->__es.__far;

    // Check if FAR matches any of our watchpoints
    for (int i = 0; i < PLATFORM_MAX_WATCHPOINTS; i++) {
        if (atomic_load(&g_watchpoint_in_use[i])) {
            void    *watched = g_watchpoint_addr[i];
            uint64_t w_start = (uint64_t)watched;
            uint64_t w_end   = w_start + 8; // Watchpoints are 8-byte aligned

            if (far >= w_start && far < w_end) {
                return i;
            }
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

#endif // PATCH_ARCH_ARM64
