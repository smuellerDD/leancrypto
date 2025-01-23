/*
 * Copyright (C) 2018 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef _ATOMIC_BOOL_H
#define _ATOMIC_BOOL_H

#include "bool.h"

/*
 * Atomic operations only work on:
 *	GCC >= 4.1
 *	Clang / LLVM
 */

/**
 * Atomic type and operations equivalent to the Linux kernel.
 */
typedef struct {
	volatile bool counter;
} atomic_bool_t;

/**
 * Memory barrier
 */
static inline void atomic_bool_mb(void)
{
	__sync_synchronize();
}

#define ATOMIC_BOOL_INIT(i) { (i) }

/**
 * Read atomic variable
 * @param v atomic variable
 * @return variable content
 */
static inline bool atomic_bool_read(const atomic_bool_t *v)
{
	bool i;

	atomic_bool_mb();
	i = ((v)->counter);
	atomic_bool_mb();

	return i;
}

/**
 * Set atomic variable
 * @param i value to be set
 * @param v atomic variable
 */
static inline void atomic_bool_set(bool i, atomic_bool_t *v)
{
	atomic_bool_mb();
	((v)->counter) = i;
	atomic_bool_mb();
}

/**
 * Set atomic variable to true
 * @param v atomic variable
 */
static inline void atomic_bool_set_true(atomic_bool_t *v)
{
	atomic_bool_set(true, v);
}

/**
 * Set atomic variable to false
 * @param v atomic variable
 */
static inline void atomic_bool_set_false(atomic_bool_t *v)
{
	atomic_bool_set(false, v);
}

/**
 * Atomic compare and exchange operation (if current value of atomic
 * variable is equal to the old value, set the new value)
 * @param v atomic variable
 * @param old integer value to compare with
 * @param new integer value to set atomic variable to
 * @return true if comparison is successful and new was written
 */
static inline int atomic_bool_cmpxchg(atomic_bool_t *v, bool old, bool new)
{
	return __sync_bool_compare_and_swap(&v->counter, old, new);
}

#endif /* _ATOMIC_BOOL_H */
