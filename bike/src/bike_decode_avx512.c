/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * The rotation functions are based on the Barrel shifter described in [1]
 * and some modifed snippet from [2]
 * [1] Chou, T.: QcBits: Constant-Time Small-Key Code-Based Cryptography.
 *     In: Gier-lichs, B., Poschmann, A.Y. (eds.) Cryptographic Hardware
 *     and Embedded Systems– CHES 2016. pp. 280–300. Springer Berlin Heidelberg,
 *     Berlin, Heidelberg (2016)
 *
 * [2] Guimarães, Antonio, Diego F Aranha, and Edson Borin. 2019.
 *     “Optimized Implementation of QC-MDPC Code-Based Cryptography.”
 *     Concurrency and Computation: Practice and Experience 31 (18):
 *     e5089. https://doi.org/10.1002/cpe.5089.
 */

#include "bike_decode.h"
#include "bike_decode_internal.h"
#include "bike_utilities.h"
#include "build_bug_on.h"
#include "ext_headers_x86.h"
#include "small_stack_support.h"

#define AVX512_INTERNAL
#include "x86_64_intrinsic.h"

#define R_ZMM_HALF_LOG2 LC_BIKE_UPTOPOW2(LC_BIKE_R_ZMM / 2)

static inline void rotate512_big(syndrome_t *out, const syndrome_t *in,
				 uint32_t zmm_num)
{
	uint32_t idx;

	// For preventing overflows (comparison in bytes)
	BUILD_BUG_ON(sizeof(*out) <= (LC_BIKE_BYTES_IN_ZMM *
				      (LC_BIKE_R_ZMM + (2 * R_ZMM_HALF_LOG2))));
	*out = *in;

	for (idx = R_ZMM_HALF_LOG2; idx >= 1; idx >>= 1) {
		const uint8_t mask = (uint8_t)secure_l32_mask(zmm_num, idx);
		size_t i;

		zmm_num = zmm_num - (idx & mask);

		for (i = 0; i < (LC_BIKE_R_ZMM + idx); i++) {
			const __m512i a = LOAD(&out->qw[8 * (i + idx)]);
			MSTORE64(&out->qw[8 * i], mask, a);
		}
	}
}

// The rotate512_small function is a derivative of the code described in [1]
static inline void rotate512_small(syndrome_t *out, const syndrome_t *in,
				   size_t bitscount)
{
	__m512i previous = SET_ZERO;
	const int count64 = (int)bitscount & 0x3f;
	const __m512i count64_512 = SET1_I64(count64);
	const __m512i count64_512r = SET1_I64((int)64 - count64);

	const __m512i num_full_qw = SET1_I64((int64_t)(bitscount >> 6));
	const __m512i one = SET1_I64(1);
	__m512i a0, a1;

	__m512i idx1, idx = SET_I64(7, 6, 5, 4, 3, 2, 1, 0);
	int i;

	// Positions above 7 are taken from the second register in
	// _mm512_permutex2var_epi64
	idx = ADD_I64(idx, num_full_qw);
	idx1 = ADD_I64(idx, one);

	for (i = LC_BIKE_R_ZMM; i >= 0; i--) {
		// Load the next 512 bits
		const __m512i in512 = LOAD(&in->qw[8 * i]);

		// Rotate the current and previous 512 registers so that their quadwords
		// would be in the right positions.
		a0 = PERMX2VAR_I64(in512, idx, previous);
		a1 = PERMX2VAR_I64(in512, idx1, previous);

		a0 = SRLV_I64(a0, count64_512);
		a1 = SLLV_I64(a1, count64_512r);

		// Shift less than 64 (quadwords internal)
		const __m512i out512 = a0 | a1;

		// Store the rotated value
		STORE(&out->qw[8 * i], out512);
		previous = in512;
	}
}

void rotate_right_avx512(syndrome_t *out, const syndrome_t *in,
			 const uint32_t bitscount)
{
	LC_FPU_ENABLE;

	// 1) Rotate in granularity of 512 bits blocks, using ZMMs
	rotate512_big(out, in, (bitscount / LC_BIKE_BITS_IN_ZMM));
	// 2) Rotate in smaller granularity (less than 512 bits), using ZMMs
	rotate512_small(out, out, (bitscount % LC_BIKE_BITS_IN_ZMM));

	LC_FPU_DISABLE;
}

// Duplicates the first R_BITS of the syndrome three times
// |------------------------------------------|
// |  Third copy | Second copy | first R_BITS |
// |------------------------------------------|
// This is required by the rotate functions.
void dup_avx512(syndrome_t *s)
{
	size_t i;

	s->qw[LC_BIKE_R_QWORDS - 1] =
		(s->qw[0] << LC_BIKE_LAST_R_QWORD_LEAD) |
		(s->qw[LC_BIKE_R_QWORDS - 1] & LC_BIKE_LAST_R_QWORD_MASK);

	for (i = 0; i < (2 * LC_BIKE_R_QWORDS) - 1; i++) {
		s->qw[LC_BIKE_R_QWORDS + i] =
			(s->qw[i] >> LC_BIKE_LAST_R_QWORD_TRAIL) |
			(s->qw[i + 1] << LC_BIKE_LAST_R_QWORD_LEAD);
	}
}

// Use half-adder as described in [1].
void bit_sliced_adder_avx512(upc_t *upc, syndrome_t *rotated_syndrome,
			     const size_t num_of_slices)
{
	size_t j;

	// From cache-memory perspective this loop should be the outside loop
	for (j = 0; j < num_of_slices; j++) {
		size_t i;

		for (i = 0; i < LC_BIKE_R_QWORDS; i++) {
			const uint64_t carry = (upc->slice[j].u.qw[i] &
						rotated_syndrome->qw[i]);
			upc->slice[j].u.qw[i] ^= rotated_syndrome->qw[i];
			rotated_syndrome->qw[i] = carry;
		}
	}
}

int bit_slice_full_subtract_avx512(upc_t *upc, uint8_t val)
{
	struct workspace {
		// Borrow
		uint64_t br[LC_BIKE_R_QWORDS];
	};
	size_t j;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	for (j = 0; j < LC_BIKE_SLICES; j++) {
		const uint64_t lsb_mask = 0 - (val & 0x1);
		size_t i;

		val >>= 1;

		// Perform a - b with c as the input/output carry
		// br = 0 0 0 0 1 1 1 1
		// a  = 0 0 1 1 0 0 1 1
		// b  = 0 1 0 1 0 1 0 1
		// -------------------
		// o  = 0 1 1 0 0 1 1 1
		// c  = 0 1 0 0 1 1 0 1
		//
		// o  = a^b^c
		//            _     __    _ _   _ _     _
		// br = abc + abc + abc + abc = abc + ((a+b))c

		for (i = 0; i < LC_BIKE_R_QWORDS; i++) {
			const uint64_t a = upc->slice[j].u.qw[i];
			const uint64_t b = lsb_mask;
			const uint64_t tmp = ((~a) & b & (~ws->br[i])) |
					     ((((~a) | b) & ws->br[i]));
			upc->slice[j].u.qw[i] = a ^ b ^ ws->br[i];
			ws->br[i] = tmp;
		}
	}

	LC_RELEASE_MEM(ws);
	return 0;
}
