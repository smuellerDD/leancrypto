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
#include "ext_headers.h"
#include "ext_headers_x86.h"
#include "lc_memset_secure.h"

#define AVX2_INTERNAL
#include "x86_64_intrinsic.h"

void karatzuba_add1_avx2(uint64_t *alah, uint64_t *blbh, const uint64_t *a,
			 const uint64_t *b, const size_t qwords_len)
{
	//assert(qwords_len % REG_QWORDS == 0);

	LC_FPU_ENABLE;
	REG_T va0, va1, vb0, vb1;

	for (size_t i = 0; i < qwords_len; i += REG_QWORDS) {
		va0 = LOAD(&a[i]);
		va1 = LOAD(&a[i + qwords_len]);
		vb0 = LOAD(&b[i]);
		vb1 = LOAD(&b[i + qwords_len]);

		STORE(&alah[i], va0 ^ va1);
		STORE(&blbh[i], vb0 ^ vb1);
	}
	LC_FPU_DISABLE;
}

void karatzuba_add2_avx2(uint64_t *z, const uint64_t *x, const uint64_t *y,
			 const size_t qwords_len)
{
	//assert(qwords_len % REG_QWORDS == 0);

	LC_FPU_ENABLE;
	REG_T vx, vy;

	for (size_t i = 0; i < qwords_len; i += REG_QWORDS) {
		vx = LOAD(&x[i]);
		vy = LOAD(&y[i]);

		STORE(&z[i], vx ^ vy);
	}
	LC_FPU_DISABLE;
}

void karatzuba_add3_avx2(uint64_t *c, const uint64_t *mid,
			 const size_t qwords_len)
{
	//assert(qwords_len % REG_QWORDS == 0);

	LC_FPU_ENABLE;
	REG_T vr0, vr1, vr2, vr3, vt;

	uint64_t *c0 = c;
	uint64_t *c1 = &c[qwords_len];
	uint64_t *c2 = &c[2 * qwords_len];
	uint64_t *c3 = &c[3 * qwords_len];

	for (size_t i = 0; i < qwords_len; i += REG_QWORDS) {
		vr0 = LOAD(&c0[i]);
		vr1 = LOAD(&c1[i]);
		vr2 = LOAD(&c2[i]);
		vr3 = LOAD(&c3[i]);
		vt = LOAD(&mid[i]);

		STORE(&c1[i], vt ^ vr0 ^ vr1);
		STORE(&c2[i], vt ^ vr2 ^ vr3);
	}
	LC_FPU_DISABLE;
}

// c = a mod (x^r - 1)
void gf2x_red_avx2(pad_r_t *c, const dbl_pad_r_t *a)
{
	const uint64_t *a64 = (const uint64_t *)a;
	uint64_t *c64 = (uint64_t *)c;

	LC_FPU_ENABLE;

	for (size_t i = 0; i < LC_BIKE_R_QWORDS; i += REG_QWORDS) {
		REG_T vt0 = LOAD(&a64[i]);
		REG_T vt1 = LOAD(&a64[i + LC_BIKE_R_QWORDS]);
		REG_T vt2 = LOAD(&a64[i + LC_BIKE_R_QWORDS - 1]);

		vt1 = SLLI_I64(vt1, LC_BIKE_LAST_R_QWORD_TRAIL);
		vt2 = SRLI_I64(vt2, LC_BIKE_LAST_R_QWORD_LEAD);

		vt0 ^= (vt1 | vt2);

		STORE(&c64[i], vt0);
	}

	c64[LC_BIKE_R_QWORDS - 1] &= LC_BIKE_LAST_R_QWORD_MASK;

	// Clean the secrets from the upper part of c
	lc_memset_secure((uint8_t *)&c64[LC_BIKE_R_QWORDS], 0,
			 (LC_BIKE_R_PADDED_QWORDS - LC_BIKE_R_QWORDS) *
				 sizeof(uint64_t));

	LC_FPU_DISABLE;
}
