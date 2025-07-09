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
 * This file is derived from https://github.com/YuriMyakotin/ChaCha20-SIMD which
 * uses the following license:
 *
 * MIT License
 *
 * Copyright (c) 2023 Yury Myakotin
 */

#include "alignment.h"
#include "chacha20_asm_avx512.h"
#include "ext_headers_x86.h"
#include "lc_chacha20_private.h"
#include "lc_memset_secure.h"
#include "small_stack_support.h"
#include "timecop.h"

static inline void ChaCha20AddCounter(uint32_t *State32bits,
				      const uint64_t value_to_add)
{
	uint32_t hi = (uint32_t)(value_to_add >> 32);
	uint32_t lo = (uint32_t)value_to_add;

	if (hi) {
		unsigned int overflow =
			(0 - hi) < State32bits[LC_CC20_KEY_SIZE_WORDS + 1];

		State32bits[LC_CC20_KEY_SIZE_WORDS + 1] += hi;
		if (overflow) {
			State32bits[LC_CC20_KEY_SIZE_WORDS + 2]++;
			if (State32bits[LC_CC20_KEY_SIZE_WORDS + 2] == 0)
				State32bits[LC_CC20_KEY_SIZE_WORDS + 3]++;
		}
	}

	if (lo) {
		unsigned int overflow =
			(0 - lo) < State32bits[LC_CC20_KEY_SIZE_WORDS + 0];

		State32bits[LC_CC20_KEY_SIZE_WORDS + 0] += lo;
		if (overflow) {
			State32bits[LC_CC20_KEY_SIZE_WORDS + 1]++;
			if (State32bits[LC_CC20_KEY_SIZE_WORDS + 1] == 0) {
				State32bits[LC_CC20_KEY_SIZE_WORDS + 2]++;
				if (State32bits[LC_CC20_KEY_SIZE_WORDS + 2] ==
				    0)
					State32bits[LC_CC20_KEY_SIZE_WORDS +
						    3]++;
			}
		}
	}
}

static inline void PartialXor(const __m512i val, const uint8_t *Src,
			      uint8_t *Dest, uint64_t Size)
{
	uint8_t BuffForPartialOp[64] __align(64);

	memcpy(BuffForPartialOp, Src, Size);
	_mm512_storeu_si512(
		(__m512i *)(BuffForPartialOp),
		_mm512_xor_si512(
			val,
			_mm512_loadu_si512((const __m512i *)BuffForPartialOp)));
	memcpy(Dest, BuffForPartialOp, Size);
	lc_memset_secure(BuffForPartialOp, 0, sizeof(BuffForPartialOp));
}

static inline void PartialStore(const __m512i val, uint8_t *Dest, uint64_t Size)
{
	uint8_t BuffForPartialOp[64] __align(64);

	_mm512_storeu_si512((__m512i *)(BuffForPartialOp), val);
	memcpy(Dest, BuffForPartialOp, Size);
	lc_memset_secure(BuffForPartialOp, 0, sizeof(BuffForPartialOp));
}

#define DISABLE_16_BLOCKS
int cc20_crypt_bytes_avx512(uint32_t *state, const uint8_t *in, uint8_t *out,
			    uint64_t len)
{
#define LC_CC20_AVX512_STATE_OFFSET(x) (x / sizeof(uint32_t))
	struct workspace {
		__m512i state0, state1, state2, state3_0, state3_1, state3_2,
			state3_3;
		__m512i T1, T2, T3, T4; //temporary registers
		__m512i ctr_increment;
		__m512i P1, P2, P3, P4;
		__m512i X0_0, X0_1, X0_2, X0_3;
#ifdef DISABLE_16_BLOCKS
		__m512i X1_0, X1_1, X1_2, X1_3;
		__m512i X2_0, X2_1, X2_2, X2_3;
		__m512i X3_0, X3_1, X3_2, X3_3;
#endif
	};
	const uint8_t *CurrentIn = in;
	uint8_t *CurrentOut = out;

#ifdef DISABLE_16_BLOCKS
	uint64_t RemainingBytes = len;
#else
	const uint64_t FullBlocksCount = len / 1024;
	uint64_t RemainingBytes = len % 1024;
#endif
	LC_DECLARE_MEM(ws, struct workspace, 64);

	ws->state0 = _mm512_broadcast_i32x4(
		_mm_set_epi32(1797285236, 2036477234, 857760878,
			      1634760805)); //"expand 32-byte k"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	ws->state1 = _mm512_broadcast_i32x4(
		_mm_loadu_si128((const __m128i *)(state)));
	ws->state2 = _mm512_broadcast_i32x4(_mm_loadu_si128(
		(const __m128i *)(state + LC_CC20_AVX512_STATE_OFFSET(16))));
#pragma GCC diagnostic pop

	//permutation indexes for results
	ws->P1 = _mm512_set_epi64(13, 12, 5, 4, 9, 8, 1, 0);
	ws->P2 = _mm512_set_epi64(15, 14, 7, 6, 11, 10, 3, 2);
	ws->P3 = _mm512_set_epi64(11, 10, 9, 8, 3, 2, 1, 0);
	ws->P4 = _mm512_set_epi64(15, 14, 13, 12, 7, 6, 5, 4);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	ws->T1 = _mm512_broadcast_i32x4(_mm_load_si128(
		(const __m128i *)(state + LC_CC20_AVX512_STATE_OFFSET(32))));
#pragma GCC diagnostic pop
	ws->T2 = _mm512_set_epi64(0, 3, 0, 2, 0, 1, 0, 0);

	ws->state3_0 = _mm512_add_epi32(ws->T1, ws->T2);

#ifndef DISABLE_16_BLOCKS
	if (FullBlocksCount > 0) {
		ws->T3 = _mm512_set_epi64(0, 7, 0, 6, 0, 5, 0, 4);

		ws->state3_1 = _mm512_add_epi32(ws->T1, ws->T3);

		ws->T2 = _mm512_set_epi64(0, 11, 0, 10, 0, 9, 0, 8);
		ws->T3 = _mm512_set_epi64(0, 15, 0, 14, 0, 13, 0, 12);

		ws->state3_2 = _mm512_add_epi32(ws->T1, ws->T2);
		ws->ws->state3_3 = _mm512_add_epi32(ws->T1, ws->T3);

		ws->ctr_increment =
			_mm512_set_epi64(0, 16, 0, 16, 0, 16, 0, 16);

		for (uint64_t n = 0; n < FullBlocksCount; n++) {
			ws->X0_0 = ws->state0;
			ws->X0_1 = ws->state1;
			ws->X0_2 = ws->state2;
			ws->X0_3 = ws->state3_0;

			ws->X1_0 = ws->state0;
			ws->X1_1 = ws->state1;
			ws->X1_2 = ws->state2;
			ws->X1_3 = ws->state3_1;

			ws->X2_0 = ws->state0;
			ws->X2_1 = ws->state1;
			ws->X2_2 = ws->state2;
			ws->X2_3 = ws->state3_2;

			ws->X3_0 = ws->state0;
			ws->X3_1 = ws->state1;
			ws->X3_2 = ws->state2;
			ws->X3_3 = ws->state3_3;

			for (int i = 20; i > 0; i -= 2) {
				ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->X0_1);
				ws->X1_0 = _mm512_add_epi32(ws->X1_0, ws->X1_1);
				ws->X2_0 = _mm512_add_epi32(ws->X2_0, ws->X2_1);
				ws->X3_0 = _mm512_add_epi32(ws->X3_0, ws->X3_1);

				ws->X0_3 = _mm512_xor_si512(ws->X0_3, ws->X0_0);
				ws->X1_3 = _mm512_xor_si512(ws->X1_3, ws->X1_0);
				ws->X2_3 = _mm512_xor_si512(ws->X2_3, ws->X2_0);
				ws->X3_3 = _mm512_xor_si512(ws->X3_3, ws->X3_0);

				ws->X0_3 = _mm512_rol_epi32(ws->X0_3, 16);
				ws->X1_3 = _mm512_rol_epi32(ws->X1_3, 16);
				ws->X2_3 = _mm512_rol_epi32(ws->X2_3, 16);
				ws->X3_3 = _mm512_rol_epi32(ws->X3_3, 16);

				ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->X0_3);
				ws->X1_2 = _mm512_add_epi32(ws->X1_2, ws->X1_3);
				ws->X2_2 = _mm512_add_epi32(ws->X2_2, ws->X2_3);
				ws->X3_2 = _mm512_add_epi32(ws->X3_2, ws->X3_3);

				ws->X0_1 = _mm512_xor_si512(ws->X0_1, ws->X0_2);
				ws->X1_1 = _mm512_xor_si512(ws->X1_1, ws->X1_2);
				ws->X2_1 = _mm512_xor_si512(ws->X2_1, ws->X2_2);
				ws->X3_1 = _mm512_xor_si512(ws->X3_1, ws->X3_2);

				ws->X0_1 = _mm512_rol_epi32(ws->X0_1, 12);
				ws->X1_1 = _mm512_rol_epi32(ws->X1_1, 12);
				ws->X2_1 = _mm512_rol_epi32(ws->X2_1, 12);
				ws->X3_1 = _mm512_rol_epi32(ws->X3_1, 12);

				ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->X0_1);
				ws->X1_0 = _mm512_add_epi32(ws->X1_0, ws->X1_1);
				ws->X2_0 = _mm512_add_epi32(ws->X2_0, ws->X2_1);
				ws->X3_0 = _mm512_add_epi32(ws->X3_0, ws->X3_1);

				ws->X0_3 = _mm512_xor_si512(ws->X0_3, ws->X0_0);
				ws->X1_3 = _mm512_xor_si512(ws->X1_3, ws->X1_0);
				ws->X2_3 = _mm512_xor_si512(ws->X2_3, ws->X2_0);
				ws->X3_3 = _mm512_xor_si512(ws->X3_3, ws->X3_0);

				ws->X0_3 = _mm512_rol_epi32(ws->X0_3, 8);
				ws->X1_3 = _mm512_rol_epi32(ws->X1_3, 8);
				ws->X2_3 = _mm512_rol_epi32(ws->X2_3, 8);
				ws->X3_3 = _mm512_rol_epi32(ws->X3_3, 8);

				ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->X0_3);
				ws->X1_2 = _mm512_add_epi32(ws->X1_2, ws->X1_3);
				ws->X2_2 = _mm512_add_epi32(ws->X2_2, ws->X2_3);
				ws->X3_2 = _mm512_add_epi32(ws->X3_2, ws->X3_3);

				ws->X0_1 = _mm512_xor_si512(ws->X0_1, ws->X0_2);
				ws->X1_1 = _mm512_xor_si512(ws->X1_1, ws->X1_2);
				ws->X2_1 = _mm512_xor_si512(ws->X2_1, ws->X2_2);
				ws->X3_1 = _mm512_xor_si512(ws->X3_1, ws->X3_2);

				ws->X0_1 = _mm512_rol_epi32(ws->X0_1, 7);
				ws->X1_1 = _mm512_rol_epi32(ws->X1_1, 7);
				ws->X2_1 = _mm512_rol_epi32(ws->X2_1, 7);
				ws->X3_1 = _mm512_rol_epi32(ws->X3_1, 7);

				ws->X0_1 = _mm512_shuffle_epi32(
					ws->X0_1, _MM_SHUFFLE(0, 3, 2, 1));
				ws->X0_2 = _mm512_shuffle_epi32(
					ws->X0_2, _MM_SHUFFLE(1, 0, 3, 2));
				ws->X0_3 = _mm512_shuffle_epi32(
					ws->X0_3, _MM_SHUFFLE(2, 1, 0, 3));

				ws->X1_1 = _mm512_shuffle_epi32(
					ws->X1_1, _MM_SHUFFLE(0, 3, 2, 1));
				ws->X1_2 = _mm512_shuffle_epi32(
					ws->X1_2, _MM_SHUFFLE(1, 0, 3, 2));
				ws->X1_3 = _mm512_shuffle_epi32(
					ws->X1_3, _MM_SHUFFLE(2, 1, 0, 3));

				ws->X2_1 = _mm512_shuffle_epi32(
					ws->X2_1, _MM_SHUFFLE(0, 3, 2, 1));
				ws->X2_2 = _mm512_shuffle_epi32(
					ws->X2_2, _MM_SHUFFLE(1, 0, 3, 2));
				ws->X2_3 = _mm512_shuffle_epi32(
					ws->X2_3, _MM_SHUFFLE(2, 1, 0, 3));

				ws->X3_1 = _mm512_shuffle_epi32(
					ws->X3_1, _MM_SHUFFLE(0, 3, 2, 1));
				ws->X3_2 = _mm512_shuffle_epi32(
					ws->X3_2, _MM_SHUFFLE(1, 0, 3, 2));
				ws->X3_3 = _mm512_shuffle_epi32(
					ws->X3_3, _MM_SHUFFLE(2, 1, 0, 3));

				ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->X0_1);
				ws->X1_0 = _mm512_add_epi32(ws->X1_0, ws->X1_1);
				ws->X2_0 = _mm512_add_epi32(ws->X2_0, ws->X2_1);
				ws->X3_0 = _mm512_add_epi32(ws->X3_0, ws->X3_1);

				ws->X0_3 = _mm512_xor_si512(ws->X0_3, ws->X0_0);
				ws->X1_3 = _mm512_xor_si512(ws->X1_3, ws->X1_0);
				ws->X2_3 = _mm512_xor_si512(ws->X2_3, ws->X2_0);
				ws->X3_3 = _mm512_xor_si512(ws->X3_3, ws->X3_0);

				ws->X0_3 = _mm512_rol_epi32(ws->X0_3, 16);
				ws->X1_3 = _mm512_rol_epi32(ws->X1_3, 16);
				ws->X2_3 = _mm512_rol_epi32(ws->X2_3, 16);
				ws->X3_3 = _mm512_rol_epi32(ws->X3_3, 16);

				ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->X0_3);
				ws->X1_2 = _mm512_add_epi32(ws->X1_2, ws->X1_3);
				ws->X2_2 = _mm512_add_epi32(ws->X2_2, ws->X2_3);
				ws->X3_2 = _mm512_add_epi32(ws->X3_2, ws->X3_3);

				ws->X0_1 = _mm512_xor_si512(ws->X0_1, ws->X0_2);
				ws->X1_1 = _mm512_xor_si512(ws->X1_1, ws->X1_2);
				ws->X2_1 = _mm512_xor_si512(ws->X2_1, ws->X2_2);
				ws->X3_1 = _mm512_xor_si512(ws->X3_1, ws->X3_2);

				ws->X0_1 = _mm512_rol_epi32(ws->X0_1, 12);
				ws->X1_1 = _mm512_rol_epi32(ws->X1_1, 12);
				ws->X2_1 = _mm512_rol_epi32(ws->X2_1, 12);
				ws->X3_1 = _mm512_rol_epi32(ws->X3_1, 12);

				ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->X0_1);
				ws->X1_0 = _mm512_add_epi32(ws->X1_0, ws->X1_1);
				ws->X2_0 = _mm512_add_epi32(ws->X2_0, ws->X2_1);
				ws->X3_0 = _mm512_add_epi32(ws->X3_0, ws->X3_1);

				ws->X0_3 = _mm512_xor_si512(ws->X0_3, ws->X0_0);
				ws->X1_3 = _mm512_xor_si512(ws->X1_3, ws->X1_0);
				ws->X2_3 = _mm512_xor_si512(ws->X2_3, ws->X3_0);
				ws->X3_3 = _mm512_xor_si512(ws->X3_3, ws->X3_0);

				ws->X0_3 = _mm512_rol_epi32(ws->X0_3, 8);
				ws->X1_3 = _mm512_rol_epi32(ws->X1_3, 8);
				ws->X2_3 = _mm512_rol_epi32(ws->X2_3, 8);
				ws->X3_3 = _mm512_rol_epi32(ws->X3_3, 8);

				ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->X0_3);
				ws->X1_2 = _mm512_add_epi32(ws->X1_2, ws->X1_3);
				ws->X2_2 = _mm512_add_epi32(ws->X2_2, ws->X3_3);
				ws->X3_2 = _mm512_add_epi32(ws->X2_2, ws->X3_3);

				ws->X0_1 = _mm512_xor_si512(ws->X0_1, ws->X0_2);
				ws->X1_1 = _mm512_xor_si512(ws->X1_1, ws->X1_2);
				ws->X2_1 = _mm512_xor_si512(ws->X2_1, ws->X2_2);
				ws->X3_1 = _mm512_xor_si512(ws->X3_1, ws->X3_2);

				ws->X0_1 = _mm512_rol_epi32(ws->X0_1, 7);
				ws->X1_1 = _mm512_rol_epi32(ws->X1_1, 7);
				ws->X2_1 = _mm512_rol_epi32(ws->X2_1, 7);
				ws->X3_1 = _mm512_rol_epi32(ws->X3_1, 7);

				ws->X0_1 = _mm512_shuffle_epi32(
					ws->X0_1, _MM_SHUFFLE(2, 1, 0, 3));
				ws->X0_2 = _mm512_shuffle_epi32(
					ws->X0_2, _MM_SHUFFLE(1, 0, 3, 2));
				ws->X0_3 = _mm512_shuffle_epi32(
					ws->X0_3, _MM_SHUFFLE(0, 3, 2, 1));

				ws->X1_1 = _mm512_shuffle_epi32(
					ws->X1_1, _MM_SHUFFLE(2, 1, 0, 3));
				ws->X1_2 = _mm512_shuffle_epi32(
					ws->X1_2, _MM_SHUFFLE(1, 0, 3, 2));
				ws->X1_3 = _mm512_shuffle_epi32(
					ws->X1_3, _MM_SHUFFLE(0, 3, 2, 1));

				ws->X2_1 = _mm512_shuffle_epi32(
					ws->X2_1, _MM_SHUFFLE(2, 1, 0, 3));
				ws->X2_2 = _mm512_shuffle_epi32(
					ws->X2_2, _MM_SHUFFLE(1, 0, 3, 2));
				ws->X2_3 = _mm512_shuffle_epi32(
					ws->X2_3, _MM_SHUFFLE(0, 3, 2, 1));

				ws->X3_1 = _mm512_shuffle_epi32(
					ws->X3_1, _MM_SHUFFLE(2, 1, 0, 3));
				ws->X3_2 = _mm512_shuffle_epi32(
					ws->X3_2, _MM_SHUFFLE(1, 0, 3, 2));
				ws->X3_3 = _mm512_shuffle_epi32(
					ws->X3_3, _MM_SHUFFLE(0, 3, 2, 1));
			}

			ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->state0);
			ws->X0_1 = _mm512_add_epi32(ws->X0_1, ws->state1);
			ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->state2);
			ws->X0_3 = _mm512_add_epi32(ws->X0_3, ws->state3_0);

			ws->X1_0 = _mm512_add_epi32(ws->X1_0, ws->state0);
			ws->X1_1 = _mm512_add_epi32(ws->X1_1, ws->state1);
			ws->X1_2 = _mm512_add_epi32(ws->X1_2, ws->state2);
			ws->X1_3 = _mm512_add_epi32(ws->X1_3, ws->state3_1);

			ws->X2_0 = _mm512_add_epi32(ws->X2_0, ws->state0);
			ws->X2_1 = _mm512_add_epi32(ws->X2_1, ws->state1);
			ws->X2_2 = _mm512_add_epi32(ws->X2_2, ws->state2);
			ws->X2_3 = _mm512_add_epi32(ws->X2_3, ws->state3_2);

			ws->X3_0 = _mm512_add_epi32(ws->X3_0, ws->state0);
			ws->X3_1 = _mm512_add_epi32(ws->X3_1, ws->state1);
			ws->X3_2 = _mm512_add_epi32(ws->X3_2, ws->state2);
			ws->X3_3 = _mm512_add_epi32(ws->X3_3, ws->state3_3);

			//now making results contiguous, one 64-bytes block per register
			ws->T1 = _mm512_permutex2var_epi64(ws->X0_0, ws->P1,
							   ws->X0_1);
			ws->T2 = _mm512_permutex2var_epi64(ws->X0_0, ws->P2,
							   ws->X0_1);
			ws->T3 = _mm512_permutex2var_epi64(ws->X0_2, ws->P1,
							   ws->X0_3);
			ws->T4 = _mm512_permutex2var_epi64(ws->X0_2, ws->P2,
							   ws->X0_3);

			ws->X0_0 = _mm512_permutex2var_epi64(ws->T1, ws->P3,
							     ws->T3);
			ws->X0_2 = _mm512_permutex2var_epi64(ws->T1, ws->P4,
							     ws->T3);
			ws->X0_1 = _mm512_permutex2var_epi64(ws->T2, ws->P3,
							     ws->T4);
			ws->X0_3 = _mm512_permutex2var_epi64(ws->T2, ws->P4,
							     ws->T4);

			ws->T1 = _mm512_permutex2var_epi64(ws->X1_0, ws->P1,
							   ws->X1_1);
			ws->T2 = _mm512_permutex2var_epi64(ws->X1_0, ws->P2,
							   ws->X1_1);
			ws->T3 = _mm512_permutex2var_epi64(ws->X1_2, ws->P1,
							   ws->X1_3);
			ws->T4 = _mm512_permutex2var_epi64(ws->X1_2, ws->P2,
							   ws->X1_3);

			ws->X1_0 = _mm512_permutex2var_epi64(ws->T1, ws->P3,
							     ws->T3);
			ws->X1_2 = _mm512_permutex2var_epi64(ws->T1, ws->P4,
							     ws->T3);
			ws->X1_1 = _mm512_permutex2var_epi64(ws->T2, ws->P3,
							     ws->T4);
			ws->X1_3 = _mm512_permutex2var_epi64(ws->T2, ws->P4,
							     ws->T4);

			ws->T1 = _mm512_permutex2var_epi64(ws->X2_0, ws->P1,
							   ws->X2_1);
			ws->T2 = _mm512_permutex2var_epi64(ws->X2_0, ws->P2,
							   ws->X2_1);
			ws->T3 = _mm512_permutex2var_epi64(ws->X2_2, ws->P1,
							   ws->X2_3);
			ws->T4 = _mm512_permutex2var_epi64(ws->X2_2, ws->P2,
							   ws->X2_3);

			ws->X2_0 = _mm512_permutex2var_epi64(ws->T1, ws->P3,
							     ws->T3);
			ws->X2_2 = _mm512_permutex2var_epi64(ws->T1, ws->P4,
							     ws->T3);
			ws->X2_1 = _mm512_permutex2var_epi64(ws->T2, ws->P3,
							     ws->T4);
			ws->X2_3 = _mm512_permutex2var_epi64(ws->T2, ws->P4,
							     ws->T4);

			ws->T1 = _mm512_permutex2var_epi64(ws->X3_0, ws->P1,
							   ws->X3_1);
			ws->T2 = _mm512_permutex2var_epi64(ws->X3_0, ws->P2,
							   ws->X3_1);
			ws->T3 = _mm512_permutex2var_epi64(ws->X3_2, ws->P1,
							   ws->X3_3);
			ws->T4 = _mm512_permutex2var_epi64(ws->X3_2, ws->P2,
							   ws->X3_3);

			ws->X3_0 = _mm512_permutex2var_epi64(ws->T1, ws->P3,
							     ws->T3);
			ws->X3_2 = _mm512_permutex2var_epi64(ws->T1, ws->P4,
							     ws->T3);
			ws->X3_1 = _mm512_permutex2var_epi64(ws->T2, ws->P3,
							     ws->T4);
			ws->X3_3 = _mm512_permutex2var_epi64(ws->T2, ws->P4,
							     ws->T4);

			if (in) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				ws->T1 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 0 * 64));
				ws->T2 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 1 * 64));
				ws->T3 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 2 * 64));
				ws->T4 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 3 * 64));
#pragma GCC diagnostic pop

				ws->T1 = _mm512_xor_si512(ws->T1, ws->X0_0);
				ws->T2 = _mm512_xor_si512(ws->T2, ws->X0_1);
				ws->T3 = _mm512_xor_si512(ws->T3, ws->X0_2);
				ws->T4 = _mm512_xor_si512(ws->T4, ws->X0_3);

				_mm512_storeu_si512(CurrentOut + 0 * 64,
						    ws->T1);
				_mm512_storeu_si512(CurrentOut + 1 * 64,
						    ws->T2);
				_mm512_storeu_si512(CurrentOut + 2 * 64,
						    ws->T3);
				_mm512_storeu_si512(CurrentOut + 3 * 64,
						    ws->T4);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				ws->T1 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 4 * 64));
				ws->T2 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 5 * 64));
				ws->T3 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 6 * 64));
				ws->T4 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 7 * 64));
#pragma GCC diagnostic pop

				ws->T1 = _mm512_xor_si512(ws->T1, ws->X1_0);
				ws->T2 = _mm512_xor_si512(ws->T2, ws->X1_1);
				ws->T3 = _mm512_xor_si512(ws->T3, ws->X1_2);
				ws->T4 = _mm512_xor_si512(ws->T4, ws->X1_3);

				_mm512_storeu_si512(CurrentOut + 4 * 64,
						    ws->T1);
				_mm512_storeu_si512(CurrentOut + 5 * 64,
						    ws->T2);
				_mm512_storeu_si512(CurrentOut + 6 * 64,
						    ws->T3);
				_mm512_storeu_si512(CurrentOut + 7 * 64,
						    ws->T4);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				ws->T1 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 8 * 64));
				ws->T2 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 9 * 64));
				ws->T3 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 10 * 64));
				ws->T4 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 11 * 64));
#pragma GCC diagnostic pop

				ws->T1 = _mm512_xor_si512(ws->T1, ws->X2_0);
				ws->T2 = _mm512_xor_si512(ws->T2, ws->X2_1);
				ws->T3 = _mm512_xor_si512(ws->T3, ws->X2_2);
				ws->T4 = _mm512_xor_si512(ws->T4, ws->X2_3);

				_mm512_storeu_si512(CurrentOut + 8 * 64,
						    ws->T1);
				_mm512_storeu_si512(CurrentOut + 9 * 64,
						    ws->T2);
				_mm512_storeu_si512(CurrentOut + 10 * 64,
						    ws->T3);
				_mm512_storeu_si512(CurrentOut + 11 * 64,
						    ws->T4);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				ws->T1 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 12 * 64));
				ws->T2 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 13 * 64));
				ws->T3 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 14 * 64));
				T4 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 15 * 64));
#pragma GCC diagnostic pop

				ws->T1 = _mm512_xor_si512(ws->T1, ws->X3_0);
				ws->T2 = _mm512_xor_si512(ws->T2, ws->X3_1);
				ws->T3 = _mm512_xor_si512(ws->T3, ws->X3_2);
				ws->T4 = _mm512_xor_si512(ws->T4, ws->X3_3);

				_mm512_storeu_si512(CurrentOut + 12 * 64,
						    ws->T1);
				_mm512_storeu_si512(CurrentOut + 13 * 64,
						    ws->T2);
				_mm512_storeu_si512(CurrentOut + 14 * 64,
						    ws->T3);
				_mm512_storeu_si512(CurrentOut + 15 * 64,
						    ws->T4);
			} else {
				_mm512_storeu_si512(CurrentOut + 0 * 64,
						    ws->X0_0);
				_mm512_storeu_si512(CurrentOut + 1 * 64,
						    ws->X0_1);
				_mm512_storeu_si512(CurrentOut + 2 * 64,
						    ws->X0_2);
				_mm512_storeu_si512(CurrentOut + 3 * 64,
						    ws->X0_3);

				_mm512_storeu_si512(CurrentOut + 4 * 64,
						    ws->X1_0);
				_mm512_storeu_si512(CurrentOut + 5 * 64,
						    ws->X1_1);
				_mm512_storeu_si512(CurrentOut + 6 * 64,
						    ws->X1_2);
				_mm512_storeu_si512(CurrentOut + 7 * 64,
						    ws->X1_3);

				_mm512_storeu_si512(CurrentOut + 8 * 64,
						    ws->X2_0);
				_mm512_storeu_si512(CurrentOut + 9 * 64,
						    ws->X2_1);
				_mm512_storeu_si512(CurrentOut + 10 * 64,
						    ws->X2_2);
				_mm512_storeu_si512(CurrentOut + 11 * 64,
						    ws->X2_3);

				_mm512_storeu_si512(CurrentOut + 12 * 64,
						    ws->X3_0);
				_mm512_storeu_si512(CurrentOut + 13 * 64,
						    ws->X3_1);
				_mm512_storeu_si512(CurrentOut + 14 * 64,
						    ws->X3_2);
				_mm512_storeu_si512(CurrentOut + 15 * 64,
						    ws->X3_3);
			}

			/*
			 * Timecop: output is not sensitive regarding
			 * side-channels.
			 */
			unpoison(CurrentOut, 1024);

			if (CurrentIn)
				CurrentIn += 1024;
			CurrentOut += 1024;

			ws->state3_0 = _mm512_add_epi32(ws->state3_0,
							ws->ctr_increment);
			ws->state3_1 = _mm512_add_epi32(ws->state3_1,
							ws->ctr_increment);
			ws->state3_2 = _mm512_add_epi32(ws->state3_2,
							ws->ctr_increment);
			ws->state3_3 = _mm512_add_epi32(ws->state3_3,
							ws->ctr_increment);
		}

		ChaCha20AddCounter(state, FullBlocksCount * 16);
	}
#endif

	if (RemainingBytes == 0)
		goto out;
	//now computing rest in 4-blocks cycle
	ws->ctr_increment = _mm512_set_epi64(0, 4, 0, 4, 0, 4, 0, 4);

	while (1) {
		ws->X0_0 = ws->state0;
		ws->X0_1 = ws->state1;
		ws->X0_2 = ws->state2;
		ws->X0_3 = ws->state3_0;

		for (int i = 20; i > 0; i -= 2) {
			ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->X0_1);

			ws->X0_3 = _mm512_xor_si512(ws->X0_3, ws->X0_0);

			ws->X0_3 = _mm512_rol_epi32(ws->X0_3, 16);

			ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->X0_3);

			ws->X0_1 = _mm512_xor_si512(ws->X0_1, ws->X0_2);

			ws->X0_1 = _mm512_rol_epi32(ws->X0_1, 12);

			ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->X0_1);

			ws->X0_3 = _mm512_xor_si512(ws->X0_3, ws->X0_0);

			ws->X0_3 = _mm512_rol_epi32(ws->X0_3, 8);

			ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->X0_3);

			ws->X0_1 = _mm512_xor_si512(ws->X0_1, ws->X0_2);

			ws->X0_1 = _mm512_rol_epi32(ws->X0_1, 7);

			ws->X0_1 = _mm512_shuffle_epi32(
				ws->X0_1, _MM_SHUFFLE(0, 3, 2, 1));
			ws->X0_2 = _mm512_shuffle_epi32(
				ws->X0_2, _MM_SHUFFLE(1, 0, 3, 2));
			ws->X0_3 = _mm512_shuffle_epi32(
				ws->X0_3, _MM_SHUFFLE(2, 1, 0, 3));

			ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->X0_1);

			ws->X0_3 = _mm512_xor_si512(ws->X0_3, ws->X0_0);

			ws->X0_3 = _mm512_rol_epi32(ws->X0_3, 16);

			ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->X0_3);
			ws->X0_1 = _mm512_xor_si512(ws->X0_1, ws->X0_2);

			ws->X0_1 = _mm512_rol_epi32(ws->X0_1, 12);

			ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->X0_1);

			ws->X0_3 = _mm512_xor_si512(ws->X0_3, ws->X0_0);

			ws->X0_3 = _mm512_rol_epi32(ws->X0_3, 8);

			ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->X0_3);

			ws->X0_1 = _mm512_xor_si512(ws->X0_1, ws->X0_2);

			ws->X0_1 = _mm512_rol_epi32(ws->X0_1, 7);

			ws->X0_1 = _mm512_shuffle_epi32(
				ws->X0_1, _MM_SHUFFLE(2, 1, 0, 3));
			ws->X0_2 = _mm512_shuffle_epi32(
				ws->X0_2, _MM_SHUFFLE(1, 0, 3, 2));
			ws->X0_3 = _mm512_shuffle_epi32(
				ws->X0_3, _MM_SHUFFLE(0, 3, 2, 1));
		}

		ws->X0_0 = _mm512_add_epi32(ws->X0_0, ws->state0);
		ws->X0_1 = _mm512_add_epi32(ws->X0_1, ws->state1);
		ws->X0_2 = _mm512_add_epi32(ws->X0_2, ws->state2);
		ws->X0_3 = _mm512_add_epi32(ws->X0_3, ws->state3_0);

		//now making results contiguous, one 64-bytes block per register
		ws->T1 = _mm512_permutex2var_epi64(ws->X0_0, ws->P1, ws->X0_1);
		ws->T2 = _mm512_permutex2var_epi64(ws->X0_0, ws->P2, ws->X0_1);
		ws->T3 = _mm512_permutex2var_epi64(ws->X0_2, ws->P1, ws->X0_3);
		ws->T4 = _mm512_permutex2var_epi64(ws->X0_2, ws->P2, ws->X0_3);

		ws->X0_0 = _mm512_permutex2var_epi64(ws->T1, ws->P3, ws->T3);
		ws->X0_2 = _mm512_permutex2var_epi64(ws->T1, ws->P4, ws->T3);
		ws->X0_1 = _mm512_permutex2var_epi64(ws->T2, ws->P3, ws->T4);
		ws->X0_3 = _mm512_permutex2var_epi64(ws->T2, ws->P4, ws->T4);

		if (RemainingBytes >= 256) {
			if (in) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				ws->T1 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 0 * 64));
				ws->T2 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 1 * 64));
				ws->T3 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 2 * 64));
				ws->T4 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 3 * 64));
#pragma GCC diagnostic pop

				ws->T1 = _mm512_xor_si512(ws->T1, ws->X0_0);
				ws->T2 = _mm512_xor_si512(ws->T2, ws->X0_1);
				ws->T3 = _mm512_xor_si512(ws->T3, ws->X0_2);
				ws->T4 = _mm512_xor_si512(ws->T4, ws->X0_3);

				_mm512_storeu_si512(CurrentOut + 0 * 64,
						    ws->T1);
				_mm512_storeu_si512(CurrentOut + 1 * 64,
						    ws->T2);
				_mm512_storeu_si512(CurrentOut + 2 * 64,
						    ws->T3);
				_mm512_storeu_si512(CurrentOut + 3 * 64,
						    ws->T4);
			} else {
				_mm512_storeu_si512(CurrentOut + 0 * 64,
						    ws->X0_0);
				_mm512_storeu_si512(CurrentOut + 1 * 64,
						    ws->X0_1);
				_mm512_storeu_si512(CurrentOut + 2 * 64,
						    ws->X0_2);
				_mm512_storeu_si512(CurrentOut + 3 * 64,
						    ws->X0_3);
			}

			ChaCha20AddCounter(state, 4);

			/*
			 * Timecop: output is not sensitive regarding
			 * side-channels.
			 */
			unpoison(CurrentOut, 256);

			RemainingBytes -= 256;
			if (RemainingBytes == 0)
				goto out;

			if (CurrentIn)
				CurrentIn += 256;
			CurrentOut += 256;
			ws->state3_0 = _mm512_add_epi32(ws->state3_0,
							ws->ctr_increment);
			continue;
		} else {
			if (in) {
				if (RemainingBytes < 64) {
					PartialXor(ws->X0_0, CurrentIn,
						   CurrentOut, RemainingBytes);

					/*
					 * Timecop: output is not sensitive
					 * regarding side-channels.
					 */
					unpoison(CurrentOut, RemainingBytes);

					ChaCha20AddCounter(state, 1);
					goto out;
				}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				ws->T1 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn + 0 * 64));
#pragma GCC diagnostic pop
				ws->T1 = _mm512_xor_si512(ws->T1, ws->X0_0);
				_mm512_storeu_si512(CurrentOut + 0 * 64,
						    ws->T1);

				/*
				 * Timecop: output is not sensitive
				 * regarding side-channels.
				 */
				unpoison(CurrentOut, 64);

				RemainingBytes -= 64;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 1);
					goto out;
				}

				CurrentIn += 64;
				CurrentOut += 64;

				if (RemainingBytes < 64) {
					PartialXor(ws->X0_1, CurrentIn,
						   CurrentOut, RemainingBytes);

					/*
					 * Timecop: output is not sensitive
					 * regarding side-channels.
					 */
					unpoison(CurrentOut, RemainingBytes);

					ChaCha20AddCounter(state, 2);
					goto out;
				}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				ws->T1 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn));
#pragma GCC diagnostic pop
				ws->T1 = _mm512_xor_si512(ws->T1, ws->X0_1);
				_mm512_storeu_si512(CurrentOut, ws->T1);

				/*
				 * Timecop: output is not sensitive
				 * regarding side-channels.
				 */
				unpoison(CurrentOut, 64);

				RemainingBytes -= 64;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 2);
					goto out;
				}

				CurrentIn += 64;
				CurrentOut += 64;

				if (RemainingBytes < 64) {
					PartialXor(ws->X0_2, CurrentIn,
						   CurrentOut, RemainingBytes);

					/*
					 * Timecop: output is not sensitive
					 * regarding side-channels.
					 */
					unpoison(CurrentOut, RemainingBytes);

					ChaCha20AddCounter(state, 3);
					goto out;
				}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				ws->T1 = _mm512_loadu_si512(
					(const __m512i *)(CurrentIn));
#pragma GCC diagnostic pop
				ws->T1 = _mm512_xor_si512(ws->T1, ws->X0_2);
				_mm512_storeu_si512(CurrentOut, ws->T1);

				/*
				 * Timecop: output is not sensitive
				 * regarding side-channels.
				 */
				unpoison(CurrentOut, 64);

				RemainingBytes -= 64;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 3);
					goto out;
				}

				PartialXor(ws->X0_3, CurrentIn, CurrentOut,
					   RemainingBytes);

				/*
				 * Timecop: output is not sensitive
				 * regarding side-channels.
				 */
				unpoison(CurrentOut, RemainingBytes);

				ChaCha20AddCounter(state, 4);
				goto out;

			} else {
				if (RemainingBytes < 64) {
					PartialStore(ws->X0_0, CurrentOut,
						     RemainingBytes);

					/*
					 * Timecop: output is not sensitive
					 * regarding side-channels.
					 */
					unpoison(CurrentOut, RemainingBytes);

					ChaCha20AddCounter(state, 1);
					goto out;
				}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				_mm512_storeu_si512((__m512i *)(CurrentOut),
						    ws->X0_0);
#pragma GCC diagnostic pop

				/*
				 * Timecop: output is not sensitive
				 * regarding side-channels.
				 */
				unpoison(CurrentOut, 64);

				RemainingBytes -= 64;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 1);
					goto out;
				}
				CurrentOut += 64;

				if (RemainingBytes < 64) {
					PartialStore(ws->X0_1, CurrentOut,
						     RemainingBytes);

					/*
					 * Timecop: output is not sensitive
					 * regarding side-channels.
					 */
					unpoison(CurrentOut, RemainingBytes);

					ChaCha20AddCounter(state, 2);
					goto out;
				}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				_mm512_storeu_si512((__m512i *)(CurrentOut),
						    ws->X0_1);
#pragma GCC diagnostic pop

				/*
				 * Timecop: output is not sensitive
				 * regarding side-channels.
				 */
				unpoison(CurrentOut, 64);

				RemainingBytes -= 64;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 2);
					goto out;
				}
				CurrentOut += 64;

				if (RemainingBytes < 64) {
					PartialStore(ws->X0_2, CurrentOut,
						     RemainingBytes);

					/*
					 * Timecop: output is not sensitive
					 * regarding side-channels.
					 */
					unpoison(CurrentOut, RemainingBytes);

					ChaCha20AddCounter(state, 3);
					goto out;
				}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
				_mm512_storeu_si512((__m512i *)(CurrentOut),
						    ws->X0_2);
#pragma GCC diagnostic pop

				/*
				 * Timecop: output is not sensitive
				 * regarding side-channels.
				 */
				unpoison(CurrentOut, 64);

				RemainingBytes -= 64;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 3);
					goto out;
				}
				CurrentOut += 64;

				PartialStore(ws->X0_3, CurrentOut,
					     RemainingBytes);

				/*
				 * Timecop: output is not sensitive
				 * regarding side-channels.
				 */
				unpoison(CurrentOut, RemainingBytes);

				ChaCha20AddCounter(state, 4);
				goto out;
			}
		}
	}

out:
	LC_RELEASE_MEM(ws);
	return 0;
}
