/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
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
/*
 * This code is derived in parts from
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 * Modifications Copyright 2020 David Schatz
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#ifndef CONSTANT_TIME_H
#define CONSTANT_TIME_H

#include "ext_headers_internal.h"

/*-
 * The boolean methods return a bitmask of all ones (0xff...f) for true
 * and 0 for false. This is useful for choosing a value based on the result
 * of a conditional in constant time. For example,
 *      if (a < b) {
 *        c = a;
 *      } else {
 *        c = b;
 *      }
 * can be written as
 *      unsigned int lt = constant_time_lt(a, b);
 *      c = constant_time_select(lt, a, b);
 */

/* Convenience method for uint32_t. */
static inline uint32_t constant_time_msb_32(uint32_t a)
{
	return 0 - (a >> 31);
}

static inline size_t constant_time_msb_s(size_t a)
{
	return 0 - (a >> (sizeof(a) * 8 - 1));
}

static inline size_t constant_time_is_zero_s(size_t a)
{
	return constant_time_msb_s(~a & (a - 1));
}

static inline uint32_t constant_time_is_zero_32(uint32_t a)
{
	return constant_time_msb_32(~a & (a - 1));
}

/*
 * Returns the value unmodified, but avoids optimizations.
 * The barriers prevent the compiler from narrowing down the
 * possible value range of the mask and ~mask in the select
 * statements, which avoids the recognition of the select
 * and turning it into a conditional load or branch.
 */
static inline unsigned int value_barrier(unsigned int a)
{
	unsigned int r;
	__asm__("" : "=r"(r) : "0"(a));
	return r;
}

/* Convenience method for uint32_t. */
static inline uint32_t value_barrier_32(uint32_t a)
{
	uint32_t r;
	__asm__("" : "=r"(r) : "0"(a));
	return r;
}

/* Convenience method for uint64_t. */
static inline uint64_t value_barrier_64(uint64_t a)
{
	uint64_t r;
	__asm__("" : "=r"(r) : "0"(a));
	return r;
}

/* Convenience method for size_t. */
static inline size_t value_barrier_s(size_t a)
{
	size_t r;
	__asm__("" : "=r"(r) : "0"(a));
	return r;
}

/*-
 * Returns (mask & a) | (~mask & b).
 *
 * When |mask| is all 1s or all 0s (as returned by the methods above),
 * the select methods return either |a| (if |mask| is nonzero) or |b|
 * (if |mask| is zero).
 */
static inline unsigned int constant_time_select(unsigned int mask,
						unsigned int a, unsigned int b)
{
	return (value_barrier(mask) & a) | (value_barrier(~mask) & b);
}

static inline size_t constant_time_select_s(size_t mask, size_t a, size_t b)
{
	return (value_barrier_s(mask) & a) | (value_barrier_s(~mask) & b);
}

/* Convenience method for unsigned chars. */
static inline unsigned char
constant_time_select_8(unsigned char mask, unsigned char a, unsigned char b)
{
	return (unsigned char)constant_time_select(mask, a, b);
}

/* Convenience method for uint32_t. */
static inline uint32_t constant_time_select_32(uint32_t mask, uint32_t a,
					       uint32_t b)
{
	return (value_barrier_32(mask) & a) | (value_barrier_32(~mask) & b);
}

/* Convenience method for uint64_t. */
static inline uint64_t constant_time_select_64(uint64_t mask, uint64_t a,
					       uint64_t b)
{
	return (value_barrier_64(mask) & a) | (value_barrier_64(~mask) & b);
}

/*
 * mask must be 0xFFFFFFFF or 0x00000000.
 *
 * if (mask) {
 *     uint32_t tmp = *a;
 *
 *     *a = *b;
 *     *b = tmp;
 * }
 */
static inline void constant_time_cond_swap_32(uint32_t mask, uint32_t *a,
					      uint32_t *b)
{
	uint32_t x = *a ^ *b;

	x &= mask;
	*a ^= x;
	*b ^= x;
}

/*
 * mask must be 0xFFFFFFFF or 0x00000000.
 *
 * if (mask) {
 *     uint64_t tmp = *a;
 *
 *     *a = *b;
 *     *b = tmp;
 * }
 */
static inline void constant_time_cond_swap_64(uint64_t mask, uint64_t *a,
					      uint64_t *b)
{
	uint64_t x = *a ^ *b;

	x &= mask;
	*a ^= x;
	*b ^= x;
}

/*
 * table is a two dimensional array of bytes. Each row has rowsize elements.
 * Copies row number idx into out. rowsize and numrows are not considered
 * private.
 */
static inline void constant_time_lookup(void *out, const void *table,
					size_t rowsize, size_t numrows,
					size_t idx)
{
	size_t i, j;
	const unsigned char *tablec = (const unsigned char *)table;
	unsigned char *outc = (unsigned char *)out;
	unsigned char mask;

	memset(out, 0, rowsize);

	/* Note idx may underflow - but that is well defined */
	for (i = 0; i < numrows; i++, idx--) {
		mask = (unsigned char)constant_time_is_zero_s(idx);
		for (j = 0; j < rowsize; j++)
			*(outc + j) |=
				constant_time_select_8(mask, *(tablec++), 0);
	}
}

#endif /* CONSTANT_TIME_H */
