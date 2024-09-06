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
 *
 * [1] The optimizations are based on the description developed in the paper:
 *     Drucker, Nir, and Shay Gueron. 2019. “A Toolbox for Software Optimization
 *     of QC-MDPC Code-Based Cryptosystems.” Journal of Cryptographic Engineering,
 *     January, 1–17. https://doi.org/10.1007/s13389-018-00200-4.
 *
 * [2] The decoder algorithm is the Black-Gray decoder in
 *     the early submission of CAKE (due to N. Sandrier and R Misoczki).
 *
 * [3] The analysis for the constant time implementation is given in
 *     Drucker, Nir, Shay Gueron, and Dusan Kostic. 2019.
 *     “On Constant-Time QC-MDPC Decoding with Negligible Failure Rate.”
 *     Cryptology EPrint Archive, 2019. https://eprint.iacr.org/2019/1289.
 *
 * [4] it was adapted to BGF in:
 *     Drucker, Nir, Shay Gueron, and Dusan Kostic. 2019.
 *     “QC-MDPC decoders with several shades of gray.”
 *     Cryptology EPrint Archive, 2019. To be published.
 *
 * [5] Chou, T.: QcBits: Constant-Time Small-Key Code-Based Cryptography.
 *     In: Gier-lichs, B., Poschmann, A.Y. (eds.) Cryptographic Hardware
 *     and Embedded Systems– CHES 2016. pp. 280–300. Springer Berlin Heidelberg,
 *     Berlin, Heidelberg (2016)
 *
 * [6] The rotate512_small funciton is a derivative of the code described in:
 *     Guimarães, Antonio, Diego F Aranha, and Edson Borin. 2019.
 *     “Optimized Implementation of QC-MDPC Code-Based Cryptography.”
 *     Concurrency and Computation: Practice and Experience 31 (18):
 *     e5089. https://doi.org/10.1002/cpe.5089.
 */

#include "bike_decode.h"
#include "bike_decode_internal.h"
#include "bike_gf2x.h"
#include "bike_utilities.h"
#include "build_bug_on.h"
#include "lc_memset_secure.h"

//#include "cleanup.h"
//#include "decode_internal.h"
//#include "gf2x.h"
//#include "utilities.h"

// Decoding (bit-flipping) parameter
#if defined(LC_BIKE_BG_DECODER)
#if (LEVEL == 1)
#define LC_BIKE_MAX_IT 3
#elif (LEVEL == 3)
#define LC_BIKE_MAX_IT 4
#else
#error "Level can only be 1/3"
#endif
#elif defined(LC_BIKE_BGF_DECODER)
#define LC_BIKE_MAX_IT 5
#endif

static void compute_syndrome(syndrome_t *syndrome, const pad_r_t *c0,
			     const pad_r_t *h0, const decode_ctx *ctx)
{
	pad_r_t pad_s;

	gf2x_mod_mul(&pad_s, c0, h0);

	memcpy((uint8_t *)syndrome->qw, pad_s.val.raw, LC_BIKE_R_BYTES);
	ctx->dup(syndrome);

	lc_memset_secure(&pad_s, 0, sizeof(pad_s));
}

static inline void recompute_syndrome(syndrome_t *syndrome, const pad_r_t *c0,
				      const pad_r_t *h0, const pad_r_t *pk,
				      const e_t *e, const decode_ctx *ctx)
{
	pad_r_t tmp_c0;
	pad_r_t e0 = { 0 };
	pad_r_t e1 = { 0 };

	e0.val = e->val[0];
	e1.val = e->val[1];

	// tmp_c0 = pk * e1 + c0 + e0
	gf2x_mod_mul(&tmp_c0, &e1, pk);
	gf2x_mod_add(&tmp_c0, &tmp_c0, c0);
	gf2x_mod_add(&tmp_c0, &tmp_c0, &e0);

	// Recompute the syndrome using the updated ciphertext
	compute_syndrome(syndrome, &tmp_c0, h0, ctx);

	lc_memset_secure(&tmp_c0, 0, sizeof(tmp_c0));
	lc_memset_secure(&e0, 0, sizeof(e0));
	lc_memset_secure(&e1, 0, sizeof(e1));
}

#define MUL64HIGH(c, a, b)                                                     \
	do {                                                                   \
		uint64_t a_lo, a_hi, b_lo, b_hi;                               \
		a_lo = a & 0xffffffff;                                         \
		b_lo = b & 0xffffffff;                                         \
		a_hi = a >> 32;                                                \
		b_hi = b >> 32;                                                \
		c = a_hi * b_hi + ((a_hi * b_lo + a_lo * b_hi) >> 32);         \
	} while (0)

static inline uint8_t get_threshold(const syndrome_t *s)
{
	BUILD_BUG_ON(sizeof(*s) < sizeof(r_t));

	const uint64_t syndrome_weight =
		r_bits_vector_weight((const r_t *)s->qw);

	// The threshold coefficients are defined in the spec as floating point values.
	// Since we want to avoid floating point operations for constant-timeness,
	// we use integer arithmetic to compute the threshold.
	// For example, in the case of Level-1 parameters, instead of having:
	//   T0 = 13.530 and T1 = 0.0069722,
	// we multipy the values by 10^8 and work with integers:
	//   T0' = 1353000000 and T1' = 697220.
	// Then, instead of computing the threshold by:
	//   T0 + T1*S,
	// we compute:
	//   (T0' + T1'*S)/10^8,
	// where S is the syndrome weight. Additionally, instead of dividing by 10^8,
	// we compute the result by a multiplication and a right shift (both
	// constant-time operations), as described in:
	//   https://dl.acm.org/doi/pdf/10.1145/178243.178249
	uint64_t thr = LC_BIKE_THRESHOLD_COEFF0 +
		       (LC_BIKE_THRESHOLD_COEFF1 * syndrome_weight);

	MUL64HIGH(thr, thr, LC_BIKE_THRESHOLD_MUL_CONST);
	thr >>= LC_BIKE_THRESHOLD_SHR_CONST;

	const uint32_t mask =
		secure_l32_mask((uint32_t)thr, LC_BIKE_THRESHOLD_MIN);
	thr = (u32_barrier(mask) & thr) |
	      (u32_barrier(~mask) & LC_BIKE_THRESHOLD_MIN);

	//DMSG("    Threshold: %d\n", thr);
	return (uint8_t)thr;
}

// Calculate the Unsatisfied Parity Checks (UPCs) and update the errors
// vector (e) accordingly. In addition, update the black and gray errors vector
// with the relevant values.
static inline void find_err1(e_t *e, e_t *black_e, e_t *gray_e,
			     const syndrome_t *syndrome,
			     const compressed_idx_d_ar_t wlist,
			     const uint8_t threshold, const decode_ctx *ctx)
{
	// This function uses the bit-slice-adder methodology of [5]:
	syndrome_t rotated_syndrome = { 0 };
	upc_t upc;
	unsigned int i;

	for (i = 0; i < LC_BIKE_N0; i++) {
		unsigned int j, l;

		// UPC must start from zero at every iteration
		memset(&upc, 0, sizeof(upc));

		// 1) Right-rotate the syndrome for every secret key set bit index
		//    Then slice-add it to the UPC array.
		for (j = 0; j < LC_BIKE_D; j++) {
			ctx->rotate_right(&rotated_syndrome, syndrome,
					  wlist[i].val[j]);
			ctx->bit_sliced_adder(&upc, &rotated_syndrome,
					      LC_BIKE_LOG2_MSB(j + 1));
		}

		// 2) Subtract the threshold from the UPC counters
		ctx->bit_slice_full_subtract(&upc, threshold);

		// 3) Update the errors and the black errors vectors.
		//    The last slice of the UPC array holds the MSB of the accumulated values
		//    minus the threshold. Every zero bit indicates a potential error bit.
		//    The errors values are stored in the black array and xored with the
		//    errors Of the previous iteration.
		const r_t *last_slice =
			&(upc.slice[LC_BIKE_SLICES - 1].u.r.val);
		for (j = 0; j < LC_BIKE_R_BYTES; j++) {
			const uint8_t sum_msb = (~last_slice->raw[j]);

			black_e->val[i].raw[j] = sum_msb;
			e->val[i].raw[j] ^= sum_msb;
		}

		// Ensure that the padding bits (upper bits of the last byte) are zero so
		// they will not be included in the multiplication and in the hash function.
		e->val[i].raw[LC_BIKE_R_BYTES - 1] &= LC_BIKE_LAST_R_BYTE_MASK;

		// 4) Calculate the gray error array by adding "DELTA" to the UPC array.
		//    For that we reuse the rotated_syndrome variable setting it to all "1".
		for (l = 0; l < LC_BIKE_DELTA; l++) {
			memset((uint8_t *)rotated_syndrome.qw, 0xff,
			       LC_BIKE_R_BYTES);
			ctx->bit_sliced_adder(&upc, &rotated_syndrome,
					      LC_BIKE_SLICES);
		}

		// 5) Update the gray list with the relevant bits that are not
		//    set in the black list.
		for (j = 0; j < LC_BIKE_R_BYTES; j++) {
			const uint8_t sum_msb = (~last_slice->raw[j]);
			gray_e->val[i].raw[j] =
				(~(black_e->val[i].raw[j])) & sum_msb;
		}
	}

	lc_memset_secure(&rotated_syndrome, 0, sizeof(rotated_syndrome));
	lc_memset_secure(&upc, 0, sizeof(upc));
}

// Recalculate the UPCs and update the errors vector (e) according to it
// and to the black/gray vectors.
static inline void find_err2(e_t *e, e_t *pos_e, const syndrome_t *syndrome,
			     const compressed_idx_d_ar_t wlist,
			     const uint8_t threshold, const decode_ctx *ctx)
{
	syndrome_t rotated_syndrome = { 0 };
	upc_t upc;
	unsigned int i;

	for (i = 0; i < LC_BIKE_N0; i++) {
		unsigned int j;

		// UPC must start from zero at every iteration
		memset(&upc, 0, sizeof(upc));

		// 1) Right-rotate the syndrome, for every index of a set bit in the secret
		// key. Then slice-add it to the UPC array.
		for (j = 0; j < LC_BIKE_D; j++) {
			ctx->rotate_right(&rotated_syndrome, syndrome,
					  wlist[i].val[j]);
			ctx->bit_sliced_adder(&upc, &rotated_syndrome,
					      LC_BIKE_LOG2_MSB(j + 1));
		}

		// 2) Subtract the threshold from the UPC counters
		ctx->bit_slice_full_subtract(&upc, threshold);

		// 3) Update the errors vector.
		//    The last slice of the UPC array holds the MSB of the accumulated values
		//    minus the threshold. Every zero bit indicates a potential error bit.
		const r_t *last_slice =
			&(upc.slice[LC_BIKE_SLICES - 1].u.r.val);
		for (j = 0; j < LC_BIKE_R_BYTES; j++) {
			const uint8_t sum_msb = (~last_slice->raw[j]);
			e->val[i].raw[j] ^= (pos_e->val[i].raw[j] & sum_msb);
		}

		// Ensure that the padding bits (upper bits of the last byte) are zero, so
		// they are not included in the multiplication, and in the hash function.
		e->val[i].raw[LC_BIKE_R_BYTES - 1] &= LC_BIKE_LAST_R_BYTE_MASK;
	}

	lc_memset_secure(&rotated_syndrome, 0, sizeof(rotated_syndrome));
	lc_memset_secure(&upc, 0, sizeof(upc));
}

void bike_decode(e_t *e, const struct lc_bike_ct *ct, const struct lc_bike_sk *sk)
{
	// Initialize the decode methods struct
	decode_ctx ctx;
	decode_ctx_init(&ctx);

	e_t black_e = { 0 };
	e_t gray_e = { 0 };

	pad_r_t c0 = { 0 };
	pad_r_t h0 = { 0 };
	pad_r_t pk = { 0 };

	// Pad ciphertext (c0), secret key (h0), and public key (h)
	c0.val = ct->c0;
	h0.val = sk->bin[0];
	pk.val = sk->pk;

	syndrome_t s = { 0 };
	unsigned int iter;

	//DMSG("  Computing s.\n");
	compute_syndrome(&s, &c0, &h0, &ctx);
	ctx.dup(&s);

	// Reset (init) the error because it is xored in the find_err functions.
	memset(e, 0, sizeof(*e));

	for (iter = 0; iter < LC_BIKE_MAX_IT; iter++) {
		const uint8_t threshold = get_threshold(&s);

		//DMSG("    Iteration: %d\n", iter);
		//DMSG("    Weight of e: %lu\n",
		//     r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
		//DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

		find_err1(e, &black_e, &gray_e, &s, sk->wlist, threshold, &ctx);
		recompute_syndrome(&s, &c0, &h0, &pk, e, &ctx);
#if defined(BGF_DECODER)
		if (iter >= 1) {
			continue;
		}
#endif
		//DMSG("    Weight of e: %lu\n",
		//     r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
		//DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

		//find_err2(e, &black_e, &s, sk->wlist, ((D + 1) / 2) + 1, &ctx);
		recompute_syndrome(&s, &c0, &h0, &pk, e, &ctx);

		//DMSG("    Weight of e: %lu\n",
		//     r_bits_vector_weight(&e->val[0]) + r_bits_vector_weight(&e->val[1]));
		//DMSG("    Weight of syndrome: %lu\n", r_bits_vector_weight((r_t *)s.qw));

		find_err2(e, &gray_e, &s, sk->wlist, ((LC_BIKE_D + 1) / 2) + 1,
			  &ctx);
		recompute_syndrome(&s, &c0, &h0, &pk, e, &ctx);
	}

	lc_memset_secure(&black_e, 0, sizeof(black_e));
	lc_memset_secure(&gray_e, 0, sizeof(gray_e));
	lc_memset_secure(&c0, 0, sizeof(c0));
	lc_memset_secure(&h0, 0, sizeof(h0));
	lc_memset_secure(&s, 0, sizeof(s));
}
