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

#include "bike_type.h"
#include "bike_utilities.h"
#include "bike_sampling_internal.h"
#include "ext_headers.h"
#include "ext_headers_x86.h"

#define AVX512_INTERNAL
#include "x86_64_intrinsic.h"

// For improved performance, we process NUM_ZMMS amount of data in parallel.
#define NUM_ZMMS (8)
#define ZMMS_QWORDS (LC_BIKE_QWORDS_IN_ZMM * NUM_ZMMS)

int secure_set_bits_avx512(pad_r_t *r, const uint32_t first_pos,
			   const idx_t *wlist, const uint32_t w_size)
{
	size_t i;

	// The function assumes that the size of r is a multiple
	// of the cumulative size of used ZMM registers.
	//assert((sizeof(*r) / sizeof(uint64_t)) % ZMMS_QWORDS == 0);

	// va vectors hold the bits of the output array "r"
	// va_pos_qw vectors hold the qw position indices of "r"
	// The algorithm works as follows:
	//   1. Initialize va_pos_qw with starting positions of qw's of "r"
	//      va_pos_qw = (7, 6, 5, 4, 3, 2, 1, 0);
	//   2. While the size of "r" is not exceeded:
	//   3.   For each w in wlist:
	//   4.     Compare the pos_qw of w with positions in va_pos_qw
	//          and for the position which is equal set the appropriate
	//          bit in va vector.
	//   5.   Set va_pos_qw to the next qw positions of "r"
	__m512i va[NUM_ZMMS], va_pos_qw[NUM_ZMMS];
	__m512i w_pos_qw, w_pos_bit, one, inc;
	__mmask8 va_mask;

	uint64_t *r64 = (uint64_t *)r;

	LC_FPU_ENABLE;

	one = SET1_I64(1);
	inc = SET1_I64(LC_BIKE_QWORDS_IN_ZMM);

	// 1. Initialize
	va_pos_qw[0] = SET_I64(7, 6, 5, 4, 3, 2, 1, 0);
	for (i = 1; i < NUM_ZMMS; i++) {
		va_pos_qw[i] = ADD_I64(va_pos_qw[i - 1], inc);
	}

	// va_pos_qw vectors hold qw positions 0 .. (NUM_ZMMS * QWORDS_IN_ZMM - 1)
	// Therefore, we set the increment vector inc such that by adding it to
	// va_pos_qw vectors they hold the next ZMMS_QWORDS qw positions.
	inc = SET1_I64(ZMMS_QWORDS);

	for (i = 0; i < (sizeof(*r) / sizeof(uint64_t)); i += ZMMS_QWORDS) {
		size_t va_iter, w_iter;

		for (va_iter = 0; va_iter < NUM_ZMMS; va_iter++) {
			va[va_iter] = SET_ZERO;
		}

		for (w_iter = 0; w_iter < w_size; w_iter++) {
			int32_t w = (int32_t)(wlist[w_iter] - first_pos);
			w_pos_qw = SET1_I64(w >> 6);
			w_pos_bit = SLLI_I64(one, ((unsigned int)w &
						   LC_BIKE_MASK(6)));

			// 4. Compare the positions in va_pos_qw with w_pos_qw
			//    and set the appropriate bit in va
			for (va_iter = 0; va_iter < NUM_ZMMS; va_iter++) {
				va_mask = CMPMEQ_I64(va_pos_qw[va_iter],
						     w_pos_qw);
				va[va_iter] = MOR_I64(va[va_iter], va_mask,
						      va[va_iter], w_pos_bit);
			}
		}

		// 5. Set the va_pos_qw to the next qw positions of r
		//    and store the previously computed data in r
		for (va_iter = 0; va_iter < NUM_ZMMS; va_iter++) {
			STORE(&r64[i + (va_iter * LC_BIKE_QWORDS_IN_ZMM)],
			      va[va_iter]);
			va_pos_qw[va_iter] = ADD_I64(va_pos_qw[va_iter], inc);
		}
	}

	LC_FPU_DISABLE;

	return 0;
}

#if defined(UNIFORM_SAMPLING)
// We need the list of indices to be a multiple of avx512 register.
#define WLIST_SIZE_ADJUSTED_T (REG_DWORDS * DIVIDE_AND_CEIL(T, REG_DWORDS))

void sample_error_vec_indices_avx512(idx_t *out, struct lc_hash_ctx *prf_state)
{
	// To generate T indices in constant-time, i.e. without rejection sampling,
	// we generate MAX_RAND_INDICES_T random values with the appropriate bit
	// length (the bit size of N) and in constant time copy the first T valid
	// indices to the output.

	size_t ctr = 0; // Current number of valid and distinct indices.
	const idx_t bit_mask =
		MASK(bit_scan_reverse_vartime(2 * LC_BIKE_R_BITS));

	idx_t wlist[WLIST_SIZE_ADJUSTED_T];
	// Label all indices as invalid.
	memset((uint8_t *)wlist, 0xff, WLIST_SIZE_ADJUSTED_T * sizeof(idx_t));

	lc_hash_set_digestsize(prf_state, sizeof(idx_t));

	// Generate MAX_RAND_INDICES_T random values.
	for (size_t i = 0; i < LC_BIKE_MAX_RAND_INDICES_T; i++) {
		// Generate random index with the required bit length.
		idx_t idx;

		lc_hash_final(prf_state, (uint8_t *)&idx);
		idx &= bit_mask;

		// Loop over the output array to determine if |idx| is a duplicate,
		// and store it in the lcoation pointed to by |ctr|.
		uint16_t is_dup = 0;
		REG_T vidx = SET1_I32(idx);
		REG_T vctr = SET1_I32(ctr);
		REG_T step = SET1_I32(16);
		REG_T tmp = SET_I32(15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3,
				    2, 1, 0);

		for (size_t j = 0; j < WLIST_SIZE_ADJUSTED_T; j += REG_DWORDS) {
			REG_T vout = LOAD(&wlist[j]);
			is_dup |= CMPM_U32(vidx, vout, _MM_CMPINT_EQ);

			uint16_t write_mask =
				CMPM_U32(vctr, tmp, _MM_CMPINT_EQ);
			tmp = ADD_I32(tmp, step);

			MSTORE32(&wlist[j], write_mask, vidx);
		}

		// Check if |idx| is a valid index (< N) and increase the counter
		// only if |idx| is valid and it is not a duplicate.
		uint32_t is_valid = secure_l32(idx, 2 * R_BITS);
		ctr += ((is_dup == 0) & is_valid);
	}

	// Copy the indices to the output.
	memcpy((uint8_t *)out, (uint8_t *)wlist, T * sizeof(idx_t));
}
#endif
