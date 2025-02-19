/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
 *
 * The inversion algorithm in this file is based on:
 * [1] Nir Drucker, Shay Gueron, and Dusan Kostic. 2020. "Fast polynomial
 * inversion for post quantum QC-MDPC cryptography". Cryptology ePrint Archive,
 * 2020. https://eprint.iacr.org/2020/298.pdf
 */

#include "bike_gf2x.h"
#include "bike_gf2x_internal.h"
#include "build_bug_on.h"
#include "lc_memset_secure.h"
#include "small_stack_support.h"
#include "ret_checkers.h"

// a = a^2 mod (x^r - 1)
static inline void gf2x_mod_sqr_in_place(pad_r_t *a, dbl_pad_r_t *secure_buffer,
					 const gf2x_ctx *ctx)
{
	ctx->sqr(secure_buffer, a);
	ctx->red(a, secure_buffer);
}

// c = a^2^2^num_sqrs
static inline void repeated_squaring(pad_r_t *c, const pad_r_t *a,
				     const size_t num_sqrs,
				     dbl_pad_r_t *sec_buf, const gf2x_ctx *ctx)
{
	size_t i;

	c->val = a->val;

	for (i = 0; i < num_sqrs; i++)
		gf2x_mod_sqr_in_place(c, sec_buf, ctx);
}

// The gf2x_mod_inv function implements inversion in F_2[x]/(x^R - 1)
// based on [1](Algorithm 2).

// In every iteration, [1](Algorithm 2) performs two exponentiations:
// exponentiation 0 (exp0) and exponentiation 1 (exp1) of the form f^(2^k).
// These exponentiations are computed either by repeated squaring of f, k times,
// or by a single k-squaring of f. The method for a specific value of k
// is chosen based on the performance of squaring and k-squaring.
//
// Benchmarks on several platforms indicate that a good threshold
// for switching from repeated squaring to k-squaring is k = 64.
#define K_SQR_THR (64)

// k-squaring is computed by a permutation of bits of the input polynomial,
// as defined in [1](Observation 1). The required parameter for the permutation
// is l = (2^k)^-1 % R.
// Therefore, there are two sets of parameters for every exponentiation:
//   - exp0_k and exp1_k
//   - exp0_l and exp1_l

// Exponentiation 0 computes f^2^2^(i-1) for 0 < i < MAX_I.
// Exponentiation 1 computes f^2^((r-2) % 2^i) for 0 < i < MAX_I,
// only when the i-th bit of (r-2) is 1. Therefore, the value 0 in
// exp1_k[i] and exp1_l[i] means that exp1 is skipped in i-th iteration.

// To quickly generate all the required parameters in Sage:
//   r = DESIRED_R
//   max_i = floor(log(r-2, 2)) + 1
//   exp0_k = [2^i for i in range(max_i)]
//   exp0_l = [inverse_mod((2^k) % r, r) for k in exp0_k]
//   exp1_k = [(r-2)%(2^i) if ((r-2) & (1<<i)) else 0 for i in range(max_i)]
//   exp1_l = [inverse_mod((2^k) % r, r) if k != 0 else 0 for k in exp1_k]

#if (LC_BIKE_LEVEL == 1)

// MAX_I = floor(log(r-2)) + 1
#define MAX_I (14)
#define EXP0_K_VALS                                                            \
	1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192
#define EXP0_L_VALS                                                            \
	6162, 3081, 3851, 5632, 22, 484, 119, 1838, 1742, 3106, 10650, 1608,   \
		10157, 8816
#define EXP1_K_VALS 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 33, 4129
#define EXP1_L_VALS 0, 0, 0, 0, 0, 6162, 0, 0, 0, 0, 0, 0, 242, 5717

#elif (LC_BIKE_LEVEL == 3)

// MAX_I = floor(log(r-2)) + 1
#define MAX_I (15)
#define EXP0_K_VALS                                                            \
	1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384
#define EXP0_L_VALS                                                            \
	12330, 6165, 7706, 3564, 2711, 1139, 15053, 1258, 4388, 20524, 9538,   \
		6393, 10486, 1715, 6804
#define EXP1_K_VALS 0, 0, 0, 0, 1, 0, 17, 0, 0, 0, 0, 0, 0, 81, 8273
#define EXP1_L_VALS 0, 0, 0, 0, 12330, 0, 13685, 0, 0, 0, 0, 0, 0, 23678, 19056

#else

// MAX_I = floor(log(r-2)) + 1
#define MAX_I (16)
#define EXP0_K_VALS                                                            \
	1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,  \
		32768
#define EXP0_L_VALS                                                            \
	20487, 30730, 28169, 9443, 13001, 12376, 8302, 6618, 38760, 21582,     \
		1660, 10409, 14669, 30338, 17745, 7520
#define EXP1_K_VALS 0, 1, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 8203
#define EXP1_L_VALS                                                            \
	0, 20487, 0, 15365, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6302, 0, 10058

#endif

// Inversion in F_2[x]/(x^R - 1), [1](Algorithm 2).
// c = a^{-1} mod x^r-1
int gf2x_mod_inv(pad_r_t *c, const pad_r_t *a)
{
	/*
	 * Note that exp0/1_k/l are predefined constants that depend
	 * only on the value of R. This value is public. Therefore,
	 * branches in this function, which depends on R, are also
	 * "public". Code that releases these branches
	 * (taken/not-taken) does not leak secret information.
	 */
	static const unsigned short exp0_k[MAX_I] = { EXP0_K_VALS };
	static const unsigned short exp0_l[MAX_I] = { EXP0_L_VALS };
	static const unsigned short exp1_k[MAX_I] = { EXP1_K_VALS };
	static const unsigned short exp1_l[MAX_I] = { EXP1_L_VALS };
	struct workspace {
		pad_r_t f, g, t;
		dbl_pad_r_t sec_buf, tmp;
		uint64_t secure_buffer[LC_SECURE_BUFFER_QWORDS];
	};
	// Initialize gf2x methods struct
	gf2x_ctx ctx;
	unsigned int i;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, 64);

	gf2x_ctx_init(&ctx);

#if (LC_BIKE_LEVEL == 1)
	// The parameters below are hard-coded for R=12323
	BUILD_BUG_ON(LC_BIKE_R_BITS != 12323);
#elif (LC_BIKE_LEVEL == 3)
	// The parameters below are hard-coded for R=24659
	BUILD_BUG_ON(LC_BIKE_R_BITS != 24659);
#else
	// The parameters below are hard-coded for R=40973
	BUILD_BUG_ON(LC_BIKE_R_BITS != 40973);
#endif

	// Steps 2 and 3 in [1](Algorithm 2)
	ws->f.val = a->val;
	ws->t.val = a->val;

	for (i = 1; i < MAX_I; i++) {
		// Step 5 in [1](Algorithm 2), exponentiation 0: g = f^2^2^(i-1)
		if (exp0_k[i - 1] <= K_SQR_THR) {
			repeated_squaring(&ws->g, &ws->f, exp0_k[i - 1],
					  &ws->sec_buf, &ctx);
		} else {
			CKINT(ctx.k_sqr(&ws->g, &ws->f, exp0_l[i - 1]));
		}

		lc_memset_secure(ws->secure_buffer, 0,
				 sizeof(ws->secure_buffer));
		// Step 6, [1](Algorithm 2): f = f*g
		gf2x_mod_mul_with_ctx(&ws->f, &ws->g, &ws->f, &ctx, &ws->tmp,
				      ws->secure_buffer);

		if (exp1_k[i] != 0) {
			// Step 8, [1](Algorithm 2), exponentiation 1: g = f^2^((r-2) % 2^i)
			if (exp1_k[i] <= K_SQR_THR) {
				repeated_squaring(&ws->g, &ws->f, exp1_k[i],
						  &ws->sec_buf, &ctx);
			} else {
				CKINT(ctx.k_sqr(&ws->g, &ws->f, exp1_l[i]));
			}

			lc_memset_secure(ws->secure_buffer, 0,
					 sizeof(ws->secure_buffer));
			// Step 9, [1](Algorithm 2): t = t*g;
			gf2x_mod_mul_with_ctx(&ws->t, &ws->g, &ws->t, &ctx,
					      &ws->tmp, ws->secure_buffer);
		}
	}

	// Step 10, [1](Algorithm 2): c = t^2
	gf2x_mod_sqr_in_place(&ws->t, &ws->sec_buf, &ctx);
	c->val = ws->t.val;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}
