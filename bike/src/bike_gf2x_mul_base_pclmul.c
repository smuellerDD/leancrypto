/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/awslabs/bike-kem
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include "bike_gf2x_internal.h"
#include "ext_headers_x86.h"

#define LOAD128(mem) _mm_loadu_si128((const void *)(mem))
#define STORE128(mem, reg) _mm_storeu_si128((void *)(mem), (reg))
#define UNPACKLO(x, y) _mm_unpacklo_epi64((x), (y))
#define UNPACKHI(x, y) _mm_unpackhi_epi64((x), (y))
#define CLMUL(x, y, imm) _mm_clmulepi64_si128((x), (y), (imm))
#define BSRLI(x, imm) _mm_bsrli_si128((x), (imm))
#define BSLLI(x, imm) _mm_bslli_si128((x), (imm))

// 4x4 Karatsuba multiplication
static inline void gf2x_mul4_int(__m128i c[4], const __m128i a_lo,
				 const __m128i a_hi, const __m128i b_lo,
				 const __m128i b_hi)
{
	// a_lo = [a1 | a0]; a_hi = [a3 | a2];
	// b_lo = [b1 | b0]; b_hi = [b3 | b2];
	// 4x4 Karatsuba requires three 2x2 multiplications:
	//   (1) a_lo * b_lo
	//   (2) a_hi * b_hi
	//   (3) aa * bb = (a_lo + a_hi) * (b_lo + b_hi)
	// Each of the three 2x2 multiplications requires three 1x1 multiplications:
	//   (1) is computed by a0*b0, a1*b1, (a0+a1)*(b0+b1)
	//   (2) is computed by a2*b2, a3*b3, (a2+a3)*(b2+b3)
	//   (3) is computed by aa0*bb0, aa1*bb1, (aa0+aa1)*(bb0+bb1)
	// All the required additions are performed in the end.

	__m128i aa, bb;
	__m128i xx, yy, uu, vv, m;
	__m128i lo[2], hi[2], mi[2];
	__m128i t[9];

	aa = a_lo ^ a_hi;
	bb = b_lo ^ b_hi;

	// xx <-- [(a2+a3) | (a0+a1)]
	// yy <-- [(b2+b3) | (b0+b1)]
	xx = UNPACKLO(a_lo, a_hi);
	yy = UNPACKLO(b_lo, b_hi);
	xx = xx ^ UNPACKHI(a_lo, a_hi);
	yy = yy ^ UNPACKHI(b_lo, b_hi);

	// uu <-- [ 0 | (aa0+aa1)]
	// vv <-- [ 0 | (bb0+bb1)]
	uu = aa ^ BSRLI(aa, 8);
	vv = bb ^ BSRLI(bb, 8);

	// 9 multiplications
	t[0] = CLMUL(a_lo, b_lo, 0x00);
	t[1] = CLMUL(a_lo, b_lo, 0x11);
	t[2] = CLMUL(a_hi, b_hi, 0x00);
	t[3] = CLMUL(a_hi, b_hi, 0x11);
	t[4] = CLMUL(xx, yy, 0x00);
	t[5] = CLMUL(xx, yy, 0x11);
	t[6] = CLMUL(aa, bb, 0x00);
	t[7] = CLMUL(aa, bb, 0x11);
	t[8] = CLMUL(uu, vv, 0x00);

	t[4] ^= (t[0] ^ t[1]);
	t[5] ^= (t[2] ^ t[3]);
	t[8] ^= (t[6] ^ t[7]);

	lo[0] = t[0] ^ BSLLI(t[4], 8);
	lo[1] = t[1] ^ BSRLI(t[4], 8);
	hi[0] = t[2] ^ BSLLI(t[5], 8);
	hi[1] = t[3] ^ BSRLI(t[5], 8);
	mi[0] = t[6] ^ BSLLI(t[8], 8);
	mi[1] = t[7] ^ BSRLI(t[8], 8);

	m = lo[1] ^ hi[0];

	c[0] = lo[0];
	c[1] = lo[0] ^ mi[0] ^ m;
	c[2] = hi[1] ^ mi[1] ^ m;
	c[3] = hi[1];
}

// 512x512bit multiplication performed by Karatsuba algorithm
// where a and b are considered as having 8 digits of size 64 bits.
void gf2x_mul_base_pclmul(uint64_t *c, const uint64_t *a, const uint64_t *b)
{
	__m128i va[4], vb[4];
	__m128i aa[2], bb[2];
	__m128i lo[4], hi[4], mi[4], m[2];
	size_t i;

	LC_FPU_ENABLE;

	for (i = 0; i < 4; i++) {
		va[i] = LOAD128(&a[LC_BIKE_QWORDS_IN_XMM * i]);
		vb[i] = LOAD128(&b[LC_BIKE_QWORDS_IN_XMM * i]);
	}

	// Multiply the low and the high halves of a and b
	// lo <-- a_lo * b_lo
	// hi <-- a_hi * b_hi
	gf2x_mul4_int(lo, va[0], va[1], vb[0], vb[1]);
	gf2x_mul4_int(hi, va[2], va[3], vb[2], vb[3]);

	// Compute the middle multiplication
	// aa <-- a_lo + a_hi
	// bb <-- b_lo + b_hi
	// mi <-- aa * bb
	aa[0] = va[0] ^ va[2];
	aa[1] = va[1] ^ va[3];
	bb[0] = vb[0] ^ vb[2];
	bb[1] = vb[1] ^ vb[3];
	gf2x_mul4_int(mi, aa[0], aa[1], bb[0], bb[1]);

	m[0] = lo[2] ^ hi[0];
	m[1] = lo[3] ^ hi[1];

	STORE128(&c[0 * LC_BIKE_QWORDS_IN_XMM], lo[0]);
	STORE128(&c[1 * LC_BIKE_QWORDS_IN_XMM], lo[1]);
	STORE128(&c[2 * LC_BIKE_QWORDS_IN_XMM], mi[0] ^ lo[0] ^ m[0]);
	STORE128(&c[3 * LC_BIKE_QWORDS_IN_XMM], mi[1] ^ lo[1] ^ m[1]);
	STORE128(&c[4 * LC_BIKE_QWORDS_IN_XMM], mi[2] ^ hi[2] ^ m[0]);
	STORE128(&c[5 * LC_BIKE_QWORDS_IN_XMM], mi[3] ^ hi[3] ^ m[1]);
	STORE128(&c[6 * LC_BIKE_QWORDS_IN_XMM], hi[2]);
	STORE128(&c[7 * LC_BIKE_QWORDS_IN_XMM], hi[3]);

	LC_FPU_DISABLE;
}

void gf2x_sqr_pclmul(dbl_pad_r_t *c, const pad_r_t *a)
{
	__m128i va, vr0, vr1;

	const uint64_t *a64 = (const uint64_t *)a;
	uint64_t *c64 = (uint64_t *)c;
	size_t i;

	LC_FPU_ENABLE;

	for (i = 0; i < (LC_BIKE_R_XMM * LC_BIKE_QWORDS_IN_XMM);
	     i += LC_BIKE_QWORDS_IN_XMM) {
		va = LOAD128(&a64[i]);

		vr0 = CLMUL(va, va, 0x00);
		vr1 = CLMUL(va, va, 0x11);

		STORE128(&c64[i * 2], vr0);
		STORE128(&c64[i * 2 + LC_BIKE_QWORDS_IN_XMM], vr1);
	}

	LC_FPU_DISABLE;
}
