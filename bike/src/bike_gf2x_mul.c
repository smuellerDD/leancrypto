/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/awslabs/bike-kem
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include "alignment.h"
#include "bike_gf2x.h"
#include "bike_gf2x_internal.h"
#include "build_bug_on.h"
#include "ext_headers.h"
#include "lc_memset_secure.h"

// Karatsuba multiplication algorithm.
// Input arguments a and b are padded with zeros, here:
//   - n: real number of digits in a and b (R_QWORDS)
//   - n_padded: padded number of digits of a and b (assumed to be power of 2)
// A buffer sec_buf is used for storing temporary data between recursion calls.
// It might contain secrets, and therefore should be securely cleaned after
// completion.
static inline void karatzuba(uint64_t *c, const uint64_t *a, const uint64_t *b,
			     const size_t qwords_len,
			     const size_t qwords_len_pad, uint64_t *sec_buf,
			     const gf2x_ctx *ctx)
{
	if (qwords_len <= ctx->mul_base_qwords) {
		ctx->mul_base(c, a, b);
		return;
	}

	const size_t half_qw_len = qwords_len_pad >> 1;

	// Split a and b into low and high parts of size n_padded/2
	const uint64_t *a_lo = a;
	const uint64_t *b_lo = b;
	const uint64_t *a_hi = &a[half_qw_len];
	const uint64_t *b_hi = &b[half_qw_len];

	// Split c into 4 parts of size n_padded/2 (the last ptr is not needed)
	uint64_t *c0 = c;
	uint64_t *c1 = &c[half_qw_len];
	uint64_t *c2 = &c[half_qw_len * 2];

	// Allocate 3 ptrs of size n_padded/2  on sec_buf
	uint64_t *alah = sec_buf;
	uint64_t *blbh = &sec_buf[half_qw_len];
	uint64_t *tmp = &sec_buf[half_qw_len * 2];

	// Move sec_buf ptr to the first free location for the next recursion call
	sec_buf = &sec_buf[half_qw_len * 3];

	// Compute a_lo*b_lo and store the result in (c1|c0)
	karatzuba(c0, a_lo, b_lo, half_qw_len, half_qw_len, sec_buf, ctx);

	// If the real number of digits n is less or equal to n_padded/2 then:
	//     a_hi = 0 and b_hi = 0
	// and
	//     (a_hi|a_lo)*(b_hi|b_lo) = a_lo*b_lo
	// so we can skip the remaining two multiplications
	if (qwords_len > half_qw_len) {
		// Compute a_hi*b_hi and store the result in (c3|c2)
		karatzuba(c2, a_hi, b_hi, qwords_len - half_qw_len, half_qw_len,
			  sec_buf, ctx);

		// Compute alah = (a_lo + a_hi) and blbh = (b_lo + b_hi)
		ctx->karatzuba_add1(alah, blbh, a, b, half_qw_len);

		// Compute (c1 + c2) and store the result in tmp
		ctx->karatzuba_add2(tmp, c1, c2, half_qw_len);

		// Compute alah*blbh and store the result in (c2|c1)
		karatzuba(c1, alah, blbh, half_qw_len, half_qw_len, sec_buf,
			  ctx);

		// Add (tmp|tmp) and (c3|c0) to (c2|c1)
		ctx->karatzuba_add3(c0, tmp, half_qw_len);
	}
}

void gf2x_mod_mul_with_ctx(pad_r_t *c, const pad_r_t *a, const pad_r_t *b,
			   const gf2x_ctx *ctx, dbl_pad_r_t *t,
			   uint64_t secure_buffer[LC_SECURE_BUFFER_QWORDS])
{
	BUILD_BUG_ON(LC_BIKE_R_PADDED_BYTES % 2 != 0);

	lc_memset_secure(t, 0, sizeof(*t));
	karatzuba((uint64_t *)t, (const uint64_t *)a, (const uint64_t *)b,
		  LC_BIKE_R_QWORDS, LC_BIKE_R_PADDED_QWORDS, secure_buffer,
		  ctx);

	ctx->red(c, t);
}

void gf2x_mod_mul(pad_r_t *c, const pad_r_t *a, const pad_r_t *b,
		  dbl_pad_r_t *t,
		  uint64_t secure_buffer[LC_SECURE_BUFFER_QWORDS])
{
	// Initialize gf2x methods struct
	gf2x_ctx ctx;

	BUILD_BUG_ON(LC_BIKE_R_PADDED_BYTES % 2 != 0);

	gf2x_ctx_init(&ctx);

	gf2x_mod_mul_with_ctx(c, a, b, &ctx, t, secure_buffer);
}
