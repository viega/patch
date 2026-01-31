/**
 * @file futex.h
 * @brief Platform-specific futex support for Linux and macOS.
 *
 * Provides portable futex_wait and futex_wake operations, plus a simple
 * futex-based mutex implementation.
 */
#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>

#if defined(__linux__)
#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

static inline int
futex_wait(uint32_t *futex, uint32_t val)
{
    return syscall(SYS_futex, futex, FUTEX_WAIT_PRIVATE, val, nullptr, nullptr, 0);
}

static inline int
futex_wake(uint32_t *futex, bool all)
{
    return syscall(SYS_futex, futex, FUTEX_WAKE_PRIVATE, all ? INT_MAX : 1, nullptr, nullptr, 0);
}

#elif defined(__APPLE__)
extern int __ulock_wait2(uint32_t, void *, uint64_t, uint64_t, uint64_t);
extern int __ulock_wake(uint32_t, void *, uint64_t);

#define ULOCK_COMPARE_AND_WAIT 1
#define ULOCK_WAKE_ALL         0x00000100
#define ULOCK_WAKE_THREAD      0x00000200

static inline int
futex_wait(uint32_t *futex, uint32_t val)
{
    return __ulock_wait2(ULOCK_COMPARE_AND_WAIT, futex, (uint64_t)val, 0, 0);
}

static inline int
futex_wake(uint32_t *futex, bool all)
{
    uint32_t op = ULOCK_COMPARE_AND_WAIT | (all ? ULOCK_WAKE_ALL : ULOCK_WAKE_THREAD);
    return __ulock_wake(op, futex, 0);
}

#else
#error "Unsupported platform - futex not available"
#endif

// ============================================================================
// Futex-based mutex
// ============================================================================
//
// State values:
//   0 = unlocked
//   1 = locked, no waiters
//   2 = locked, with waiters

typedef struct {
    _Atomic uint32_t state;
} futex_mutex_t;

#define FUTEX_MUTEX_INIT {0}

static inline void
futex_mutex_lock(futex_mutex_t *m)
{
    // Fast path: try to acquire unlocked mutex
    uint32_t expected = 0;
    if (atomic_compare_exchange_strong_explicit(&m->state, &expected, 1,
                                                 memory_order_acquire,
                                                 memory_order_relaxed)) {
        return;
    }

    // Slow path: mutex is locked, need to wait
    do {
        // If state is 1, change to 2 (locked with waiters)
        // If state is 2, it stays 2
        if (expected == 2 ||
            atomic_compare_exchange_strong_explicit(&m->state, &expected, 2,
                                                     memory_order_relaxed,
                                                     memory_order_relaxed)) {
            // Wait until state changes from 2
            futex_wait((uint32_t *)&m->state, 2);
        }

        // Try to acquire again
        expected = 0;
    } while (!atomic_compare_exchange_strong_explicit(&m->state, &expected, 2,
                                                       memory_order_acquire,
                                                       memory_order_relaxed));
}

static inline void
futex_mutex_unlock(futex_mutex_t *m)
{
    // Release the lock
    uint32_t prev = atomic_exchange_explicit(&m->state, 0, memory_order_release);

    // If there were waiters, wake one
    if (prev == 2) {
        futex_wake((uint32_t *)&m->state, false);
    }
}

// ============================================================================
// One-time initialization using futex
// ============================================================================
//
// State values:
//   0 = not started
//   1 = in progress
//   2 = complete

typedef struct {
    _Atomic uint32_t state;
} futex_once_t;

#define FUTEX_ONCE_INIT {0}

static inline void
futex_once(futex_once_t *once, void (*init_fn)(void))
{
    uint32_t state = atomic_load_explicit(&once->state, memory_order_acquire);

    if (state == 2) {
        // Already initialized
        return;
    }

    if (state == 0) {
        // Try to become the initializer
        uint32_t expected = 0;
        if (atomic_compare_exchange_strong_explicit(&once->state, &expected, 1,
                                                     memory_order_relaxed,
                                                     memory_order_relaxed)) {
            // We are the initializer
            init_fn();

            // Mark complete and wake any waiters
            atomic_store_explicit(&once->state, 2, memory_order_release);
            futex_wake((uint32_t *)&once->state, true);
            return;
        }
        state = expected;
    }

    // Wait for initialization to complete
    while (state != 2) {
        futex_wait((uint32_t *)&once->state, state);
        state = atomic_load_explicit(&once->state, memory_order_acquire);
    }
}
