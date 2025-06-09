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

#include "field.h"

/* Inverse. */
void gf_invert(gf y, const gf x)
{
	gf t1, t2;

	gf_sqr(t1, x); /* o^2 */
	gf_isr(t2, t1); /* +-1/sqrt(o^2) = +-1/o */
	gf_sqr(t1, t2);
	gf_mul(t2, t1, x); /* not direct to y in case of alias. */
	gf_copy(y, t2);
}

void gf_mul(gf_s *RESTRICT cs, const gf as, const gf bs)
{
	const uint32_t *a = as->limb, *b = bs->limb;
	uint32_t *c = cs->limb;
	uint64_t accum0 = 0, accum1 = 0, accum2 = 0;
	uint32_t mask = (1 << 28) - 1;
	uint32_t aa[8], bb[8];
	int i, j;

	for (i = 0; i < 8; i++) {
		aa[i] = a[i] + a[i + 8];
		bb[i] = b[i] + b[i + 8];
	}

	for (j = 0; j < 8; j++) {
		accum2 = 0;
		for (i = 0; i < j + 1; i++) {
			accum2 += widemul(a[j - i], b[i]);
			accum1 += widemul(aa[j - i], bb[i]);
			accum0 += widemul(a[8 + j - i], b[8 + i]);
		}
		accum1 -= accum2;
		accum0 += accum2;
		accum2 = 0;
		for (i = j + 1; i < 8; i++) {
			accum0 -= widemul(a[8 + j - i], b[i]);
			accum2 += widemul(aa[8 + j - i], bb[i]);
			accum1 += widemul(a[16 + j - i], b[8 + i]);
		}
		accum1 += accum2;
		accum0 += accum2;
		c[j] = ((uint32_t)(accum0)) & mask;
		c[j + 8] = ((uint32_t)(accum1)) & mask;
		accum0 >>= 28;
		accum1 >>= 28;
	}

	accum0 += accum1;
	accum0 += c[8];
	accum1 += c[0];
	c[8] = ((uint32_t)(accum0)) & mask;
	c[0] = ((uint32_t)(accum1)) & mask;

	accum0 >>= 28;
	accum1 >>= 28;
	c[9] += ((uint32_t)(accum0));
	c[1] += ((uint32_t)(accum1));
}

void gf_mulw_unsigned(gf_s *RESTRICT cs, const gf as, uint32_t b)
{
	const uint32_t *a = as->limb;
	uint32_t *c = cs->limb;
	uint64_t accum0 = 0, accum8 = 0;
	uint32_t mask = (1 << 28) - 1;
	int i;

	assert(b <= mask);

	for (i = 0; i < 8; i++) {
		accum0 += widemul(b, a[i]);
		accum8 += widemul(b, a[i + 8]);
		c[i] = (word_t)(accum0 & mask);
		accum0 >>= 28;
		c[i + 8] = (word_t)(accum8 & mask);
		accum8 >>= 28;
	}

	accum0 += accum8 + c[8];
	c[8] = ((uint32_t)accum0) & mask;
	c[9] += (uint32_t)(accum0 >> 28);

	accum8 += c[0];
	c[0] = ((uint32_t)accum8) & mask;
	c[1] += (uint32_t)(accum8 >> 28);
}

void gf_sqr(gf_s *RESTRICT cs, const gf as)
{
	gf_mul(cs, as, as); /* Performs better with a dedicated square */
}
