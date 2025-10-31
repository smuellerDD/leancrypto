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

#include "lc_memset_secure.h"
#include "point_448.h"
#include "timecop.h"
#include "word.h"

LC_FIPS_RODATA_SECTION
static const c448_word_t MONTGOMERY_FACTOR = (c448_word_t)0x3bd440fae918bc5ULL;

LC_FIPS_RODATA_SECTION
static const curve448_scalar_t
	sc_p = { { { SC_LIMB(0x2378c292ab5844f3ULL),
		     SC_LIMB(0x216cc2728dc58f55ULL),
		     SC_LIMB(0xc44edb49aed63690ULL),
		     SC_LIMB(0xffffffff7cca23e9ULL),
		     SC_LIMB(0xffffffffffffffffULL),
		     SC_LIMB(0xffffffffffffffffULL),
		     SC_LIMB(0x3fffffffffffffffULL) } } },
	sc_r2 = { { {

		SC_LIMB(0xe3539257049b9b60ULL), SC_LIMB(0x7af32c4bc1b195d9ULL),
		SC_LIMB(0x0d66de2388ea1859ULL), SC_LIMB(0xae17cf725ee4d838ULL),
		SC_LIMB(0x1a9cc14ba3c47c44ULL), SC_LIMB(0x2052bcb7e4d070afULL),
		SC_LIMB(0x3402a939f823b729ULL) } } };

#define WBITS C448_WORD_BITS /* NB this may be different from ARCH_WORD_BITS */

static const curve448_scalar_t curve448_scalar_one = { { { 1 } } };
static const curve448_scalar_t curve448_scalar_zero = { { { 0 } } };

/*
 * {extra,accum} - sub +? p
 * Must have extra <= 1
 */
static void sc_subx(curve448_scalar_t out,
		    const c448_word_t accum[C448_SCALAR_LIMBS],
		    const curve448_scalar_t sub, const curve448_scalar_t p,
		    c448_word_t extra)
{
	c448_dsword_t chain = 0;
	unsigned int i;
	c448_word_t borrow;

	for (i = 0; i < C448_SCALAR_LIMBS; i++) {
		chain = (chain + accum[i]) - sub->limb[i];
		out->limb[i] = (c448_word_t)chain;
		chain >>= WBITS;
	}
	borrow = (c448_word_t)chain + extra; /* = 0 or -1 */

	chain = 0;
	for (i = 0; i < C448_SCALAR_LIMBS; i++) {
		chain = (chain + out->limb[i]) + (p->limb[i] & borrow);
		out->limb[i] = (c448_word_t)chain;
		chain >>= WBITS;
	}
}

static void sc_montmul(curve448_scalar_t out, const curve448_scalar_t a,
		       const curve448_scalar_t b)
{
	unsigned int i, j;
	c448_word_t accum[C448_SCALAR_LIMBS + 1] = { 0 };
	c448_word_t hi_carry = 0;

	for (i = 0; i < C448_SCALAR_LIMBS; i++) {
		c448_word_t mand = a->limb[i];
		const c448_word_t *mier = b->limb;

		c448_dword_t chain = 0;
		for (j = 0; j < C448_SCALAR_LIMBS; j++) {
			chain += ((c448_dword_t)mand) * mier[j] + accum[j];
			accum[j] = (c448_word_t)chain;
			chain >>= WBITS;
		}
		accum[j] = (c448_word_t)chain;

		mand = accum[0] * MONTGOMERY_FACTOR;
		chain = 0;
		mier = sc_p->limb;
		for (j = 0; j < C448_SCALAR_LIMBS; j++) {
			chain += (c448_dword_t)mand * mier[j] + accum[j];
			if (j)
				accum[j - 1] = (c448_word_t)chain;
			chain >>= WBITS;
		}
		chain += accum[j];
		chain += hi_carry;
		accum[j - 1] = (c448_word_t)chain;
		hi_carry = (c448_word_t)(chain >> WBITS);
	}

	sc_subx(out, accum, sc_p, sc_p, hi_carry);
}

void curve448_scalar_mul(curve448_scalar_t out, const curve448_scalar_t a,
			 const curve448_scalar_t b)
{
	sc_montmul(out, a, b);
	sc_montmul(out, out, sc_r2);
}

void curve448_scalar_sub(curve448_scalar_t out, const curve448_scalar_t a,
			 const curve448_scalar_t b)
{
	sc_subx(out, a->limb, b, sc_p, 0);
}

void curve448_scalar_add(curve448_scalar_t out, const curve448_scalar_t a,
			 const curve448_scalar_t b)
{
	c448_dword_t chain = 0;
	unsigned int i;

	for (i = 0; i < C448_SCALAR_LIMBS; i++) {
		chain = (chain + a->limb[i]) + b->limb[i];
		out->limb[i] = (c448_word_t)chain;
		chain >>= WBITS;
	}
	sc_subx(out, out->limb, sc_p, sc_p, (c448_word_t)chain);
}

static inline void scalar_decode_short(curve448_scalar_t s,
				       const unsigned char *ser, size_t nbytes)
{
	size_t i, j, k = 0;

	for (i = 0; i < C448_SCALAR_LIMBS; i++) {
		c448_word_t out = 0;

		for (j = 0; j < sizeof(c448_word_t) && k < nbytes; j++, k++)
			out |= ((c448_word_t)ser[k]) << (8 * j);
		s->limb[i] = out;
	}
}

int curve448_scalar_decode(curve448_scalar_t s,
			   const unsigned char ser[C448_SCALAR_BYTES])
{
	unsigned int i;
	c448_dsword_t accum = 0;

	scalar_decode_short(s, ser, C448_SCALAR_BYTES);
	for (i = 0; i < C448_SCALAR_LIMBS; i++)
		accum = (accum + s->limb[i] - sc_p->limb[i]) >> WBITS;
	/* Here accum == 0 or -1 */

	curve448_scalar_mul(s, s, curve448_scalar_one); /* ham-handed reduce */

	return (~word_is_zero((uint32_t)accum)) ? 0 : -EFAULT;
}

void curve448_scalar_destroy(curve448_scalar_t scalar)
{
	lc_memset_secure(scalar, 0, sizeof(curve448_scalar_t));
}

void curve448_scalar_decode_long(curve448_scalar_t s, const unsigned char *ser,
				 size_t ser_len)
{
	size_t i;
	curve448_scalar_t t1, t2;

	if (ser_len == 0) {
		curve448_scalar_copy(s, curve448_scalar_zero);
		return;
	}

	i = ser_len - (ser_len % C448_SCALAR_BYTES);
	if (i == ser_len)
		i -= C448_SCALAR_BYTES;

	scalar_decode_short(t1, &ser[i], ser_len - i);

	if (ser_len == sizeof(curve448_scalar_t)) {
		/* ham-handed reduce */
		curve448_scalar_mul(s, t1, curve448_scalar_one);
		curve448_scalar_destroy(t1);
		return;
	}

	while (i) {
		i -= C448_SCALAR_BYTES;
		sc_montmul(t1, t1, sc_r2);
		(void)curve448_scalar_decode(t2, ser + i);
		curve448_scalar_add(t1, t1, t2);
	}

	curve448_scalar_copy(s, t1);
	curve448_scalar_destroy(t1);
	curve448_scalar_destroy(t2);
}

void curve448_scalar_encode(unsigned char ser[C448_SCALAR_BYTES],
			    const curve448_scalar_t s)
{
	unsigned int i, j, k = 0;

	for (i = 0; i < C448_SCALAR_LIMBS; i++) {
		for (j = 0; j < sizeof(c448_word_t); j++, k++)
			ser[k] = (unsigned char)(s->limb[i] >> (8 * j));
	}
}

void curve448_scalar_halve(curve448_scalar_t out, const curve448_scalar_t a)
{
	c448_word_t mask = 0 - (a->limb[0] & 1);
	c448_dword_t chain = 0;
	unsigned int i;

	/*
	 * Timecop: upoison the mask as it does not leak sensitive data about
	 * the secret key. Iit is either zero or all bits set depending on the
	 * sign (first bit) of the secret key.
	 */
	unpoison(&mask, sizeof(mask));

	for (i = 0; i < C448_SCALAR_LIMBS; i++) {
		chain = (chain + a->limb[i]) + (sc_p->limb[i] & mask);
		out->limb[i] = (c448_word_t)chain;
		chain >>= C448_WORD_BITS;
	}
	for (i = 0; i < C448_SCALAR_LIMBS - 1; i++)
		out->limb[i] = out->limb[i] >> 1 | out->limb[i + 1]
							   << (WBITS - 1);
	out->limb[i] = out->limb[i] >> 1 | (c448_word_t)(chain << (WBITS - 1));
}
