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
 * The k-squaring algorithm in this file is based on:
 * [1] Nir Drucker, Shay Gueron, and Dusan Kostic. 2020. "Fast polynomial
 * inversion for post quantum QC-MDPC cryptography". Cryptology ePrint Archive,
 * 2020. https://eprint.iacr.org/2020/298.pdf
 */

#include "alignment.h"
#include "bike_gf2x_internal.h"
#include "ext_headers_x86.h"
#include "lc_memset_secure.h"
#include "small_stack_support.h"

#define AVX2_INTERNAL
#include "x86_64_intrinsic.h"

// If R_BITS >= 32768 then adding two elements of the permutation map can
// exceed the size of uin16_t type. Therefore, in this case we have to work
// with uint32_t type and use appropriate AVX2 instructions to compute the
// permutation map. Otherwise, uint16_t suffices, which allows us to work with
// this type and have a more efficient implementation (a single AVX2 register
// can hold eight 32-bit elements or sixteen 16-bit elements).
#if (LC_BIKE_R_BITS < 32768)

#define MAP_WORDS_IN_YMM LC_BIKE_WORDS_IN_YMM

#define map_word_t uint16_t
#define map_wordi_t int16_t
#define SET1(x) SET1_I16(x)
#define SUB(x, y) SUB_I16(x, y)
#define ADD(x, y) ADD_I16(x, y)
#define CMPGT(x, y) CMPGT_I16(x, y)

#else

#define MAP_WORDS_IN_YMM LC_BIKE_DWORDS_IN_YMM

#define map_word_t uint32_t
#define map_wordi_t int32_t
#define SET1(x) SET1_I32(x)
#define SUB(x, y) SUB_I32(x, y)
#define ADD(x, y) ADD_I32(x, y)
#define CMPGT(x, y) CMPGT_I32(x, y)

#endif

#define NUM_YMMS (2)
#define NUM_OF_VALS (NUM_YMMS * MAP_WORDS_IN_YMM)

static inline void generate_map(map_word_t *map, const map_word_t l_param)
{
	__m256i vmap[NUM_YMMS], vtmp[NUM_YMMS], vr, inc, zero;
	size_t i;

	// The permutation map is generated in the following way:
	//   1. for i = 0 to map size:
	//   2.  map[i] = (i * l_param) % r
	// However, to avoid the expensive multiplication and modulo operations
	// we modify the algorithm to:
	//   1. map[0] = l_param
	//   2. for i = 1 to map size:
	//   3.   map[i] = map[i - 1] + l_param
	//   4.   if map[i] >= r:
	//   5.     map[i] = map[i] - r
	// This algorithm is parallelized with vector instructions by processing
	// certain number of values (NUM_OF_VALS) in parallel. Therefore,
	// in the beginning we need to initialize the first NUM_OF_VALS elements.
	for (i = 0; i < NUM_OF_VALS; i++) {
		map[i] = (map_word_t)((i * l_param) % LC_BIKE_R_BITS);
	}

	vr = SET1(LC_BIKE_R_BITS);
	zero = SET_ZERO;

	// Set the increment vector such that adding it to vmap vectors
	// gives the next NUM_OF_VALS elements of the map. AVX2 does not
	// support comparison of vectors where vector elements are considered
	// as unsigned integers. This is a problem when r > 2^14 because
	// sum of two values can be greater than 2^15 which would make the it
	// a negative number when considered as a signed 16-bit integer,
	// and therefore, the condition in step 4 of the algorithm would be
	// evaluated incorrectly. So, we use the following trick:
	// we subtract R from the increment and modify the algorithm:
	//   1. map[0] = l_param
	//   2. for i = 1 to map size:
	//   3.   map[i] = map[i - 1] + (l_param - r)
	//   4.   if map[i] < 0:
	//   5.     map[i] = map[i] + r
	inc = SET1((map_wordi_t)((l_param * NUM_OF_VALS) % LC_BIKE_R_BITS));
	inc = SUB(inc, vr);

	// Load the first NUM_OF_VALS elements in the vmap vectors
	for (i = 0; i < NUM_YMMS; i++) {
		vmap[i] = LOAD(&map[i * MAP_WORDS_IN_YMM]);
	}

	for (i = NUM_YMMS; i < (LC_BIKE_R_PADDED / MAP_WORDS_IN_YMM);
	     i += NUM_YMMS) {
		size_t j;

		for (j = 0; j < NUM_YMMS; j++) {
			vmap[j] = ADD(vmap[j], inc);
			vtmp[j] = CMPGT(zero, vmap[j]);
			vmap[j] = ADD(vmap[j], vtmp[j] & vr);

			STORE(&map[(i + j) * MAP_WORDS_IN_YMM], vmap[j]);
		}
	}
}

// Convert from bytes representation, where every byte holds a single bit,
// of the polynomial, to a binary representation where every byte
// holds 8 bits of the polynomial.
static inline void bytes_to_bin(pad_r_t *bin_buf, const uint8_t *bytes_buf)
{
	size_t i;
	uint32_t *bin32 = (uint32_t *)bin_buf;

	for (i = 0; i < LC_BIKE_R_QWORDS * 2; i++) {
		__m256i t = LOAD(&bytes_buf[i * LC_BIKE_BYTES_IN_YMM]);
		bin32[i] = (uint32_t)MOVEMASK(t);
	}
}

// Convert from binary representation where every byte holds 8 bits
// of the polynomial, to byte representation where
// every byte holds a single bit of the polynomial.
static inline void bin_to_bytes(uint8_t *bytes_buf, const pad_r_t *bin_buf)
{
	// The algorithm works by taking every 32 bits of the input and converting
	// them to 32 bytes where each byte holds one of the bits. The first step is
	// to broadcast a 32-bit value (call it a)  to all elements of vector t.
	// Then t contains bytes of a in the following order:
	//   t = [ a3 a2 a1 a0 ... a3 a2 a1 a0 ]
	// where a0 contains the first 8 bits of a, a1 the second 8 bits, etc.
	// Let the output vector be [ out31 out30 ... out0 ]. We want to store
	// bit 0 of a in out0 byte, bit 1 of a in out1 byte, ect. (note that
	// we want to store the bit in the most significant position of a byte
	// because this is required by MOVEMASK instruction used in bytes_to_bin.)
	//
	// Ideally, we would shuffle the bytes of t such that the byte in
	// i-th position contains i-th bit of val, shift t appropriately and obtain
	// the result. However, AVX2 doesn't support shift operation on bytes, only
	// shifts of individual QWORDS (64 bit) and DWORDS (32 bit) are allowed.
	// Consider the two least significant DWORDS of t:
	//   t = [ ... | a3 a2 a1 a0 | a3 a2 a1 a0 ]
	// and shift them by 6 and 4 to the left, respectively, to obtain:
	//   t = [ ... | t7 t6 t5 t4 | t3 t2 t1 t0 ]
	// where t3 = a3 << 6, t2 = a2 << 6, t1 = a1 << 6, t0 = a0 << 6,
	// and   t7 = a3 << 4, t6 = a2 << 4, t5 = a1 << 4, t4 = a0 << 4.
	// Now we shuffle vector t to obtain vector p such that:
	//   p = [ ... | t12 t12 t8 t8 | t4 t4 t0 t0 ]
	// Note that in every even position of the vector p we have the right byte
	// of the input shifted by the required shift. The values in the odd
	// positions contain the right bytes of the input but they need to be shifted
	// one more time to the left by 1. By shifting each DWORD of p by 1 we get:
	//   q = [ ... | p7 p6 p5 p4 | p3 p2 p1 p0 ]
	// where p1 = t0 << 1 = a0 << 7, p3 = t4 << 1 = 5, etc. Therefore, by
	// blending p and q (taking even positions from p and odd positions from q)
	// we obtain the desired result.

	__m256i t, p, q;

	const __m256i shift_mask = SET_I32(0, 2, 4, 6, 0, 2, 4, 6);

	const __m256i shuffle_mask =
		SET_I8(15, 15, 11, 11, 7, 7, 3, 3, 14, 14, 10, 10, 6, 6, 2, 2,
		       13, 13, 9, 9, 5, 5, 1, 1, 12, 12, 8, 8, 4, 4, 0, 0);

	const __m256i blend_mask = SET1_I16(0x00ff);

	const uint32_t *bin32 = (const uint32_t *)bin_buf;
	unsigned int i;

	for (i = 0; i < LC_BIKE_R_QWORDS * 2; i++) {
		t = SET1_I32((const int)bin32[i]);
		t = SLLV_I32(t, shift_mask);

		p = SHUF_I8(t, shuffle_mask);
		q = SLLI_I32(p, 1);

		STORE(&bytes_buf[i * 32], BLENDV_I8(p, q, blend_mask));
	}
}

// The k-squaring function computes c = a^(2^k) % (x^r - 1).
// By [1](Observation 1), if
//     a = sum_{j in supp(a)} x^j,
// then
//     a^(2^k) % (x^r - 1) = sum_{j in supp(a)} x^((j * 2^k) % r).
// Therefore, k-squaring can be computed as permutation of the bits of "a":
//     pi0 : j --> (j * 2^k) % r.
// For improved performance, we compute the result by inverted permutation pi1:
//     pi1 : (j * 2^-k) % r --> j.
// Input argument l_param is defined as the value (2^-k) % r.
int k_sqr_avx2(pad_r_t *c, const pad_r_t *a, const size_t l_param)
{
	struct workspace {
		map_word_t map[LC_BIKE_R_PADDED];
		uint8_t a_bytes[LC_BIKE_R_PADDED];
		uint8_t c_bytes[LC_BIKE_R_PADDED];
	};
	unsigned int i;
	LC_DECLARE_MEM(ws, struct workspace, LC_BIKE_ALIGN_BYTES);

	LC_FPU_ENABLE;

	// Generate the permutation map defined by pi1 and l_param.
	generate_map(ws->map, (map_word_t)l_param);

	bin_to_bytes(ws->a_bytes, a);

	// Permute "a" using the generated permutation map.
	for (i = 0; i < LC_BIKE_R_BITS; i++)
		ws->c_bytes[i] = ws->a_bytes[ws->map[i]];

	bytes_to_bin(c, ws->c_bytes);

	LC_FPU_DISABLE;

	LC_RELEASE_MEM(ws);
	return 0;
}
