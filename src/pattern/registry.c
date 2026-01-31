#include "pattern.h"

#include "patch/patch_arch.h"

// Handler list is kept sorted by priority (higher first) during registration.
static pattern_handler_t *g_handlers = nullptr;

bool
pattern_has_handlers(void)
{
    return g_handlers != nullptr;
}

bool
pattern_init_defaults(void)
{
#ifdef PATCH_ARCH_X86_64
    pattern_init_x86_64();
#endif
#ifdef PATCH_ARCH_ARM64
    pattern_init_arm64();
#endif
    return g_handlers != nullptr;
}

void
pattern_register(pattern_handler_t *handler)
{
    // Insert in priority order (higher priority first).
    // This is an insertion sort - efficient for the small number of handlers
    // we typically have (5-10), and eliminates per-call sorting overhead.
    pattern_handler_t **pp = &g_handlers;
    while (*pp != nullptr && (*pp)->priority > handler->priority) {
        pp = &(*pp)->next;
    }
    handler->next = *pp;
    *pp           = handler;
}

pattern_match_t
pattern_match_prologue(const uint8_t *code, size_t avail)
{
    pattern_match_t result = {0};

    // Handlers are already sorted by priority, just iterate
    for (pattern_handler_t *h = g_handlers; h != nullptr; h = h->next) {
        pattern_match_t match = {0};
        if (h->match(code, avail, &match) && match.matched) {
            return match;
        }
    }

    return result;
}
