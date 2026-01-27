#include "pattern.h"

#include "patch/patch_arch.h"

#include <stdatomic.h>
#include <stdlib.h>

static pattern_handler_t *g_handlers = nullptr;

void
pattern_init_defaults(void)
{
#ifdef PATCH_ARCH_X86_64
    pattern_init_x86_64();
#endif
#ifdef PATCH_ARCH_ARM64
    pattern_init_arm64();
#endif
}

static int
compare_priority(const void *a, const void *b)
{
    const pattern_handler_t *ha = *(const pattern_handler_t **)a;
    const pattern_handler_t *hb = *(const pattern_handler_t **)b;
    return hb->priority - ha->priority;  // Higher priority first
}

void
pattern_register(pattern_handler_t *handler)
{
    handler->next = g_handlers;
    g_handlers    = handler;
}

pattern_match_t
pattern_match_prologue(const uint8_t *code, size_t avail)
{
    pattern_match_t result = {0};

    // Count handlers
    size_t count = 0;
    for (pattern_handler_t *h = g_handlers; h != nullptr; h = h->next) {
        count++;
    }

    if (count == 0) {
        return result;
    }

    // Sort by priority (create temporary array)
    pattern_handler_t **sorted = malloc(count * sizeof(*sorted));
    if (sorted == nullptr) {
        return result;
    }

    size_t i = 0;
    for (pattern_handler_t *h = g_handlers; h != nullptr; h = h->next) {
        sorted[i++] = h;
    }
    qsort(sorted, count, sizeof(*sorted), compare_priority);

    // Try each handler in priority order
    for (i = 0; i < count; i++) {
        pattern_match_t match = {0};
        if (sorted[i]->match(code, avail, &match) && match.matched) {
            free(sorted);
            return match;
        }
    }

    free(sorted);
    return result;
}
