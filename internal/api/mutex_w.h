/*
 * Copyright (C) 2018 - 2024, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _MUTEX_W_H
#define _MUTEX_W_H

#include "atomic.h"
#include "atomic_bool.h"

/**
 * @brief Writer mutex with a polling mechanism
 *
 * @param lock Mutex lock (if lock is true, the writer mutex is taken)
 *
 * This mutex and its implementation below is intended to cover the needs of
 * leancrypto and having no dependencies whatsoever. Thus, the implementation
 * is below is not intended for general-purpose use! Yet, it serves its purpose
 * for leancrypto.
 */
typedef struct {
	atomic_bool_t lock;
	atomic_t writer_pending;
} mutex_w_t;

/* 1 microsecond when using nanosleep */
#define MUTEX_DEFAULT_SLEEP_TIME_NS (1 << 10)
/** 1 << (MUTEX_DEFAULT_SLEEP_TIME_NS + MUTEX_MAX_INC_BITS) */
#define MUTEX_MAX_INC_BITS 14

#define __MUTEX_W_INITIALIZER(locked)                                          \
	{                                                                      \
		.lock = ATOMIC_BOOL_INIT(locked),                              \
		.writer_pending = ATOMIC_INIT(0),                              \
	}

#define DEFINE_MUTEX_W_UNLOCKED(name)                                          \
	mutex_w_t name = __MUTEX_W_INITIALIZER(false)

#define DEFINE_MUTEX_W_LOCKED(name) mutex_w_t name = __MUTEX_W_INITIALIZER(true)

/*
 * Instead of using a environment-dependent nanosleep implementation, we use
 * a small busy-wait loop which should serve the purpose of the short-duration
 * contentions possible in leancrypto.
 */
#if 0
#include <time.h>
static inline void mutex_w_sleep(mutex_w_t *mutex)
{
	struct timespec sleeptime = { .tv_sec = 0,
				      .tv_nsec = MUTEX_DEFAULT_SLEEP_TIME_NS};
	int pending = atomic_read(&mutex->writer_pending);

	/* Increase wait time exponentially depending on waiters */
	if (pending > MUTEX_MAX_INC_BITS)
		pending = MUTEX_MAX_INC_BITS;
	if (pending < 0)
		pending = 0;
	sleeptime.tv_nsec <<= pending;
	nanosleep(&sleeptime, NULL);
}
#else
static inline void mutex_w_sleep(mutex_w_t *mutex)
{
	uint64_t tv_nsec = MUTEX_DEFAULT_SLEEP_TIME_NS;
	/*
	 * Use volatile to ensure the compiler does not optimize the busyloop
	 * away.
	 */
	volatile uint64_t i;
	int pending = atomic_read(&mutex->writer_pending);

	/* Increase wait time exponentially depending on waiters */
	if (pending > MUTEX_MAX_INC_BITS)
		pending = MUTEX_MAX_INC_BITS;
	if (pending < 0)
		pending = 0;
	tv_nsec <<= pending;

	/* Busy-loop for sleeping */
	for (i = 0; i < tv_nsec; i++)
		;
}
#endif

/**
 * @brief Initialize a mutex
 * @param mutex [in] Lock variable to initialize.
 * @param locked [in] Specify whether the lock shall already be locked (true)
 *		      or unlocked (false).
 */
static inline void mutex_w_init(mutex_w_t *mutex, bool locked)
{
	atomic_bool_set(locked, &mutex->lock);
	atomic_set(&mutex->writer_pending, 0);
}

static inline void mutex_w_destroy(mutex_w_t *mutex)
{
	(void)mutex;
}

/**
 * Mutual exclusion lock (covering also the reader lock use case).
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_w_lock(mutex_w_t *mutex)
{
	atomic_inc(&mutex->writer_pending);

	/* Take the writer lock only if no writer lock is taken. */
	while (!atomic_bool_cmpxchg(&mutex->lock, false, true))
		mutex_w_sleep(mutex);

	atomic_dec(&mutex->writer_pending);
}

/**
 * Mutual exclusion lock: Attempt to take the lock. The function will never
 * block but return whether the lock was successfully taken or not.
 *
 * @param mutex [in] lock variable to lock
 * @return true if lock was taken, false if lock was not taken
 */
static inline bool mutex_w_trylock(mutex_w_t *mutex)
{
	return atomic_bool_cmpxchg(&mutex->lock, false, true);
}

static inline bool mutex_w_islocked(mutex_w_t *mutex)
{
	return atomic_bool_read(&mutex->lock);
}

/**
 * Unlock the lock
 * @param mutex [in] lock variable to lock
 */
static inline void mutex_w_unlock(mutex_w_t *mutex)
{
	/* Release the writer lock. */
	atomic_bool_cmpxchg(&mutex->lock, true, false);
}

#endif /* _MUTEX_W_H */
