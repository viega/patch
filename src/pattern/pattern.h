#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Result of pattern matching
typedef struct {
    bool        matched;
    const char *pattern_name;
    size_t      prologue_size;
    size_t      min_patch_size;
    bool        has_pc_relative;
} pattern_match_t;

// Pattern handler interface
typedef struct pattern_handler pattern_handler_t;

struct pattern_handler {
    const char *name;
    const char *description;
    int         priority;  // Higher = try first

    bool (*match)(const uint8_t *code, size_t avail, pattern_match_t *out);

    pattern_handler_t *next;
};

// Register a pattern handler
void pattern_register(pattern_handler_t *handler);

// Try to match prologue against all registered patterns
pattern_match_t pattern_match_prologue(const uint8_t *code, size_t avail);

// Initialize default patterns for current architecture.
// Returns true if at least one pattern was registered.
bool pattern_init_defaults(void);

// Check if any patterns are registered
bool pattern_has_handlers(void);

// Architecture-specific pattern initialization
void pattern_init_x86_64(void);
void pattern_init_arm64(void);
