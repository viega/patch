#pragma once

#if defined(__x86_64__) || defined(_M_X64)
    #define PATCH_ARCH_X86_64 1
    #define PATCH_ARCH_NAME   "x86_64"
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define PATCH_ARCH_ARM64 1
    #define PATCH_ARCH_NAME  "arm64"
#else
    #error "Unsupported architecture"
#endif

#if defined(__APPLE__) && defined(__MACH__)
    #define PATCH_PLATFORM_DARWIN 1
    #define PATCH_PLATFORM_NAME   "darwin"
#elif defined(__linux__)
    #define PATCH_PLATFORM_LINUX 1
    #define PATCH_PLATFORM_NAME  "linux"
#else
    #error "Unsupported platform"
#endif

// Architecture-specific constants
#ifdef PATCH_ARCH_X86_64
    #define PATCH_MIN_PATCH_SIZE  5   // JMP rel32
    #define PATCH_MAX_PATCH_SIZE  14  // movabs + jmp
    #define PATCH_MAX_INSN_SIZE   15  // x86-64 max instruction length
    #define PATCH_TRAMPOLINE_SIZE 64  // Conservative trampoline allocation
#endif

#ifdef PATCH_ARCH_ARM64
    #define PATCH_MIN_PATCH_SIZE  4   // Single branch instruction
    #define PATCH_MAX_PATCH_SIZE  16  // ldr + br + 8-byte address
    #define PATCH_MAX_INSN_SIZE   4   // Fixed 4-byte instructions
    #define PATCH_TRAMPOLINE_SIZE 64
#endif

// Number of register arguments in the calling convention
#ifdef PATCH_ARCH_X86_64
    #define PATCH_REG_ARGS 6  // rdi, rsi, rdx, rcx, r8, r9
#endif

#ifdef PATCH_ARCH_ARM64
    #define PATCH_REG_ARGS 8  // x0-x7
#endif
