#pragma once

/**
 * @file patch_arch.h
 * @brief Architecture and platform detection for the patch library.
 *
 * This header defines macros for detecting the target architecture and
 * platform at compile time, along with architecture-specific constants
 * used internally by the library.
 *
 * ## Detected Macros
 *
 * After including this header, exactly one of each pair will be defined:
 *
 * **Architecture:**
 * - `PATCH_ARCH_X86_64` - Intel/AMD 64-bit
 * - `PATCH_ARCH_ARM64` - ARM 64-bit (AArch64)
 *
 * **Platform:**
 * - `PATCH_PLATFORM_DARWIN` - macOS (Darwin kernel)
 * - `PATCH_PLATFORM_LINUX` - Linux
 *
 * ## String Names
 *
 * - `PATCH_ARCH_NAME` - Architecture name string ("x86_64" or "arm64")
 * - `PATCH_PLATFORM_NAME` - Platform name string ("darwin" or "linux")
 *
 * ## Example
 *
 * @code
 * #include "patch/patch_arch.h"
 *
 * #ifdef PATCH_PLATFORM_DARWIN
 *     // macOS-specific code
 * #endif
 *
 * #ifdef PATCH_ARCH_ARM64
 *     // ARM64-specific code
 * #endif
 * @endcode
 */

/* =========================================================================
 * Architecture Detection
 * ========================================================================= */

#if defined(__x86_64__) || defined(_M_X64)
    /** @brief Defined when compiling for x86-64 (AMD64) architecture. */
    #define PATCH_ARCH_X86_64 1
    /** @brief Human-readable architecture name. */
    #define PATCH_ARCH_NAME "x86_64"
#elif defined(__aarch64__) || defined(_M_ARM64)
    /** @brief Defined when compiling for ARM64 (AArch64) architecture. */
    #define PATCH_ARCH_ARM64 1
    /** @brief Human-readable architecture name. */
    #define PATCH_ARCH_NAME "arm64"
#else
    #error "Unsupported architecture: requires x86-64 or ARM64"
#endif

/* =========================================================================
 * Platform Detection
 * ========================================================================= */

#if defined(__APPLE__) && defined(__MACH__)
    /** @brief Defined when compiling for macOS (Darwin). */
    #define PATCH_PLATFORM_DARWIN 1
    /** @brief Human-readable platform name. */
    #define PATCH_PLATFORM_NAME "darwin"
#elif defined(__linux__)
    /** @brief Defined when compiling for Linux. */
    #define PATCH_PLATFORM_LINUX 1
    /** @brief Human-readable platform name. */
    #define PATCH_PLATFORM_NAME "linux"
#else
    #error "Unsupported platform: requires Linux or macOS"
#endif

/* =========================================================================
 * Architecture-Specific Constants
 * ========================================================================= */

#ifdef PATCH_ARCH_X86_64
    /**
     * @brief Minimum bytes needed for a patch jump.
     *
     * On x86-64, a near relative jump (JMP rel32) requires 5 bytes.
     */
    #define PATCH_MIN_PATCH_SIZE 5

    /**
     * @brief Maximum bytes a patch jump may use.
     *
     * On x86-64, an absolute jump via register (movabs r11, addr; jmp r11)
     * requires 13 bytes. We round up to 14 for alignment.
     */
    #define PATCH_MAX_PATCH_SIZE 14

    /**
     * @brief Maximum length of a single x86-64 instruction.
     */
    #define PATCH_MAX_INSN_SIZE 15

    /**
     * @brief Size allocated for trampolines.
     *
     * Must be large enough to hold relocated prologue bytes plus
     * the jump back to the original function.
     */
    #define PATCH_TRAMPOLINE_SIZE 64

    /**
     * @brief Number of register arguments in the System V AMD64 ABI.
     *
     * Arguments are passed in: RDI, RSI, RDX, RCX, R8, R9.
     */
    #define PATCH_REG_ARGS 6
#endif

#ifdef PATCH_ARCH_ARM64
    /**
     * @brief Minimum bytes needed for a patch jump.
     *
     * On ARM64, a single branch instruction is 4 bytes.
     */
    #define PATCH_MIN_PATCH_SIZE 4

    /**
     * @brief Maximum bytes a patch jump may use.
     *
     * On ARM64, an absolute jump (LDR x16, [pc, #8]; BR x16; .quad addr)
     * requires 16 bytes.
     */
    #define PATCH_MAX_PATCH_SIZE 16

    /**
     * @brief Size of a single ARM64 instruction.
     *
     * All ARM64 instructions are fixed at 4 bytes.
     */
    #define PATCH_MAX_INSN_SIZE 4

    /**
     * @brief Size allocated for trampolines.
     */
    #define PATCH_TRAMPOLINE_SIZE 64

    /**
     * @brief Number of register arguments in the ARM64 AAPCS.
     *
     * Arguments are passed in: X0-X7.
     */
    #define PATCH_REG_ARGS 8
#endif
