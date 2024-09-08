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
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OF THE
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
#include "lc_memset_secure.h"
#include "small_stack_support.h"

#define AVX512_INTERNAL
#include "x86_64_intrinsic.h"

// If R_BITS >= 32768 then adding two elements of the permutation map can
// exceed the size of uin16_t type. Therefore, in this case we have to work
// with uint32_t type and use appropriate AVX512 instructions to compute the
// permutation map. Otherwise, uint16_t suffices, which allows us to work with
// this type and have a more efficient implementation (a single AVX512 register
// can hold sixteen 32-bit elements or thirty-two 16-bit elements).
#if (LC_BIKE_R_BITS < 32768)

#define MAP_WORDS_IN_ZMM LC_BIKE_WORDS_IN_ZMM

#define map_word_t uint16_t
#define mmask_t __mmask32
#define SET1(x) SET1_I16(x)
#define ADD(x, y) ADD_I16(x, y)
#define CMPM(x, y, z) CMPM_U16(x, y, z)
#define MSUB(x, y, z, w) MSUB_I16(x, y, z, w)

#else

#define MAP_WORDS_IN_ZMM LC_BIKE_DWORDS_IN_ZMM

#define map_word_t uint32_t
#define mmask_t __mmask16
#define SET1(x) SET1_I32(x)
#define ADD(x, y) ADD_I32(x, y)
#define CMPM(x, y, z) CMPM_U32(x, y, z)
#define MSUB(x, y, z, w) MSUB_I32(x, y, z, w)

#endif

#define NUM_ZMMS (2)
#define NUM_OF_VALS (NUM_ZMMS * MAP_WORDS_IN_ZMM)

// clang-3.9 doesn't recognize these two macros
#if !defined(_MM_CMPINT_EQ)
#define _MM_CMPINT_EQ (0)
#endif

#if !defined(_MM_CMPINT_NLT)
#define _MM_CMPINT_NLT (5)
#endif

static inline void generate_map(map_word_t *map, const map_word_t l_param)
{
	__m512i vmap[NUM_ZMMS], vr, inc;
	mmask_t mask[NUM_ZMMS];

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
	for (size_t i = 0; i < NUM_OF_VALS; i++) {
		map[i] = (map_word_t)((i * l_param) % LC_BIKE_R_BITS);
	}

	// Set the increment vector such that by adding it to vmap vectors
	// we will obtain the next NUM_OF_VALS elements of the map.
	inc = SET1((short)((l_param * NUM_OF_VALS) % LC_BIKE_R_BITS));
	vr = SET1((short)LC_BIKE_R_BITS);

	// Load the first NUM_OF_VALS elements in the vmap vectors
	for (size_t i = 0; i < NUM_ZMMS; i++) {
		vmap[i] = LOAD(&map[i * MAP_WORDS_IN_ZMM]);
	}

	for (size_t i = NUM_ZMMS; i < (LC_BIKE_R_PADDED / MAP_WORDS_IN_ZMM);
	     i += NUM_ZMMS) {
		for (size_t j = 0; j < NUM_ZMMS; j++) {
			vmap[j] = ADD(vmap[j], inc);
			mask[j] = CMPM(vmap[j], vr, _MM_CMPINT_NLT);
			vmap[j] = MSUB(vmap[j], mask[j], vmap[j], vr);

			STORE(&map[(i + j) * MAP_WORDS_IN_ZMM], vmap[j]);
		}
	}
}

// Convert from bytes representation where each byte holds a single bit
// to binary representation where each byte holds 8 bits of the polynomial
static inline void bytes_to_bin(pad_r_t *bin_buf, const uint8_t *bytes_buf)
{
	uint64_t *bin64 = (uint64_t *)bin_buf;

	__m512i first_bit_mask = SET1_I8(1);
	for (size_t i = 0; i < LC_BIKE_R_QWORDS; i++) {
		__m512i t = LOAD(&bytes_buf[i * LC_BIKE_BYTES_IN_ZMM]);
		bin64[i] = CMPM_U8(t, first_bit_mask, _MM_CMPINT_EQ);
	}
}

// Convert from binary representation where each byte holds 8 bits
// to byte representation where each byte holds a single bit of the polynomial
static inline void bin_to_bytes(uint8_t *bytes_buf, const pad_r_t *bin_buf)
{
	const uint64_t *bin64 = (const uint64_t *)bin_buf;

	for (size_t i = 0; i < LC_BIKE_R_QWORDS; i++) {
		__m512i t = SET1MZ_I8(bin64[i], 1);
		STORE(&bytes_buf[i * LC_BIKE_BYTES_IN_ZMM], t);
	}
}

// The k-squaring function computes c = a^(2^k) % (x^r - 1),
// By [1](Observation 1), if
//     a = sum_{j in supp(a)} x^j,
// then
//     a^(2^k) % (x^r - 1) = sum_{j in supp(a)} x^((j * 2^k) % r).
// Therefore, k-squaring can be computed as permutation of the bits of "a":
//     pi0 : j --> (j * 2^k) % r.
// For improved performance, we compute the result by inverted permutation pi1:
//     pi1 : (j * 2^-k) % r --> j.
// Input argument l_param is defined as the value (2^-k) % r.
int k_sqr_avx512(pad_r_t *c, const pad_r_t *a, const size_t l_param)
{
	struct workspace {
		map_word_t map[LC_BIKE_R_PADDED];
		uint8_t a_bytes[LC_BIKE_R_PADDED];
		uint8_t c_bytes[LC_BIKE_R_PADDED];
	};
	LC_DECLARE_MEM(ws, struct workspace, LC_BIKE_ALIGN_BYTES);

	// Generate the permutation map defined by pi1 and l_param.
	generate_map(ws->map, (map_word_t)l_param);

	bin_to_bytes(ws->a_bytes, a);

	// Permute "a" using the generated permutation map.
	for (size_t i = 0; i < LC_BIKE_R_BITS; i++) {
		ws->c_bytes[i] = ws->a_bytes[ws->map[i]];
	}

	bytes_to_bin(c, ws->c_bytes);

	LC_RELEASE_MEM(ws);
	return 0;
}
