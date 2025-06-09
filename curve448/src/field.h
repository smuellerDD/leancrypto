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

#ifndef FIELD_H
#define FIELD_H

#include "constant_time.h"
#include "lc_x448.h"
#include "word.h"

#define NLIMBS (64 / sizeof(word_t))
#define X_SER_BYTES 56
#define SER_BYTES 56

#if defined(__GNUC__) || defined(__clang__)
#define RESTRICT __restrict__
#define ALIGNED __attribute__((__aligned__(16)))
#else
#define RESTRICT
#define ALIGNED
#endif

typedef struct gf_s {
	word_t limb[NLIMBS];
} ALIGNED gf_s, gf[1];

static inline void gf_copy(gf out, const gf a)
{
	*out = *a;
}

static inline void gf_add_RAW(gf out, const gf a, const gf b);
static inline void gf_sub_RAW(gf out, const gf a, const gf b);
static inline void gf_bias(gf inout, unsigned int amount);
static inline void gf_weak_reduce(gf inout);

void gf_invert(gf y, const gf x);
void gf_strong_reduce(gf inout);
void gf_add(gf out, const gf a, const gf b);
void gf_sub(gf out, const gf a, const gf b);
void gf_mul(gf_s *RESTRICT out, const gf a, const gf b);
void gf_mulw_unsigned(gf_s *RESTRICT out, const gf a, uint32_t b);
void gf_sqr(gf_s *RESTRICT out, const gf a);
mask_t
gf_isr(gf a,
       const gf x); /** a^2 x = 1, QNR, or 0 if x=0.  Return true if successful */
mask_t gf_eq(const gf x, const gf y);
mask_t gf_lobit(const gf x);
mask_t gf_hibit(const gf x);

void gf_serialize(uint8_t serial[SER_BYTES], const gf x, int with_highbit);
mask_t gf_deserialize(gf x, const uint8_t serial[SER_BYTES], int with_hibit,
		      uint8_t hi_nmask);

#include "f_impl.h" /* Bring in the inline implementations */

#define LIMBPERM(i) (i)
#define LIMB_MASK(i) (((1) << LIMB_PLACE_VALUE(i)) - 1)

static const gf ZERO = { { { 0 } } }, ONE = { { { 1 } } };

/* Square x, n times. */
static inline void gf_sqrn(gf_s *RESTRICT y, const gf x, int n)
{
	gf tmp;

	assert(n > 0);
	if (n & 1) {
		gf_sqr(y, x);
		n--;
	} else {
		gf_sqr(tmp, x);
		gf_sqr(y, tmp);
		n -= 2;
	}
	for (; n; n -= 2) {
		gf_sqr(tmp, y);
		gf_sqr(y, tmp);
	}
}

#define gf_add_nr gf_add_RAW

/* Subtract mod p.  Bias by 2 and don't reduce  */
static inline void gf_sub_nr(gf c, const gf a, const gf b)
{
	gf_sub_RAW(c, a, b);
	gf_bias(c, 2);
	if (GF_HEADROOM < 3)
		gf_weak_reduce(c);
}

/* Subtract mod p. Bias by amt but don't reduce.  */
static inline void gf_subx_nr(gf c, const gf a, const gf b, unsigned int amt)
{
	gf_sub_RAW(c, a, b);
	gf_bias(c, amt);
	if (GF_HEADROOM < amt + 1)
		gf_weak_reduce(c);
}

/* Mul by signed int.  Not constant-time WRT the sign of that int. */
static inline void gf_mulw(gf c, const gf a, int32_t w)
{
	if (w > 0) {
		gf_mulw_unsigned(c, a, (uint32_t)w);
	} else {
		gf_mulw_unsigned(c, a, (uint32_t)-w);
		gf_sub(c, ZERO, c);
	}
}

/* Constant time, x = is_z ? z : y */
static inline void gf_cond_sel(gf x, const gf y, const gf z, mask_t is_z)
{
	size_t i;

	for (i = 0; i < NLIMBS; i++) {
#if ARCH_WORD_BITS == 32
		x[0].limb[i] = constant_time_select_32(is_z, z[0].limb[i],
						       y[0].limb[i]);
#else
		/* Must be 64 bit */
		x[0].limb[i] = constant_time_select_64(is_z, z[0].limb[i],
						       y[0].limb[i]);
#endif
	}
}

/* Constant time, if (neg) x=-x; */
static inline void gf_cond_neg(gf x, mask_t neg)
{
	gf y;

	gf_sub(y, ZERO, x);
	gf_cond_sel(x, x, y, neg);
}

/* Constant time, if (swap) (x,y) = (y,x); */
static inline void gf_cond_swap(gf x, gf_s *RESTRICT y, mask_t swap)
{
	size_t i;

	for (i = 0; i < NLIMBS; i++) {
#if ARCH_WORD_BITS == 32
		constant_time_cond_swap_32(swap, &(x[0].limb[i]),
					   &(y->limb[i]));
#else
		/* Must be 64 bit */
		constant_time_cond_swap_64(swap, &(x[0].limb[i]),
					   &(y->limb[i]));
#endif
	}
}

#endif /* FIELD_H */
