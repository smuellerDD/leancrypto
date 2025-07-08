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
#include "chacha20_asm_avx2.h"
#include "ext_headers_x86.h"
#include "lc_chacha20_private.h"
#include "lc_memset_secure.h"
#include "small_stack_support.h"
#include "timecop.h"

static inline void ChaCha20AddCounter(uint32_t *State32bits,
				      const uint32_t value_to_add)
{
	unsigned int overflow =
		(0 - value_to_add) < State32bits[LC_CC20_KEY_SIZE_WORDS + 0];

	State32bits[LC_CC20_KEY_SIZE_WORDS + 0] += value_to_add;
	if (overflow) {
		State32bits[LC_CC20_KEY_SIZE_WORDS + 1]++;
		if (State32bits[LC_CC20_KEY_SIZE_WORDS + 1] == 0) {
			State32bits[LC_CC20_KEY_SIZE_WORDS + 2]++;
			if (State32bits[LC_CC20_KEY_SIZE_WORDS + 2] == 0)
				State32bits[LC_CC20_KEY_SIZE_WORDS + 3]++;
		}
	}
}

static inline void PartialXor(const __m256i val, const uint8_t *Src,
			      uint8_t *Dest, uint64_t Size)
{
	uint8_t BuffForPartialOp[32] __align(32);

	memcpy(BuffForPartialOp, Src, Size);
	_mm256_storeu_si256(
		(__m256i *)(BuffForPartialOp),
		_mm256_xor_si256(
			val,
			_mm256_loadu_si256((const __m256i *)BuffForPartialOp)));
	memcpy(Dest, BuffForPartialOp, Size);
	lc_memset_secure(BuffForPartialOp, 0, sizeof(BuffForPartialOp));
}

static inline void PartialStore(const __m256i val, uint8_t *Dest, uint64_t Size)
{
	uint8_t BuffForPartialOp[32] __align(32);

	_mm256_storeu_si256((__m256i *)(BuffForPartialOp), val);
	memcpy(Dest, BuffForPartialOp, Size);
	lc_memset_secure(BuffForPartialOp, 0, sizeof(BuffForPartialOp));
}

static inline __m256i RotateLeft7(const __m256i val)
{
	return _mm256_or_si256(_mm256_slli_epi32(val, 7),
			       _mm256_srli_epi32(val, 32 - 7));
}

static inline __m256i RotateLeft12(const __m256i val)
{
	return _mm256_or_si256(_mm256_slli_epi32(val, 12),
			       _mm256_srli_epi32(val, 32 - 12));
}

static inline __m256i RotateLeft8(const __m256i val)
{
	const __m256i mask =
		_mm256_set_epi8(14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7, 2, 1,
				0, 3, 14, 13, 12, 15, 10, 9, 8, 11, 6, 5, 4, 7,
				2, 1, 0, 3);
	return _mm256_shuffle_epi8(val, mask);
}

static inline __m256i RotateLeft16(const __m256i val)
{
	const __m256i mask =
		_mm256_set_epi8(13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6, 1, 0,
				3, 2, 13, 12, 15, 14, 9, 8, 11, 10, 5, 4, 7, 6,
				1, 0, 3, 2);
	return _mm256_shuffle_epi8(val, mask);
}

int cc20_crypt_bytes_avx2(uint32_t *state, const uint8_t *in, uint8_t *out,
			  uint64_t len)
{
#define LC_CC20_AVX2_STATE_OFFSET(x) (x / sizeof(uint32_t))
	struct workspace {
		__m256i state0, state1, state2, state3;
		__m256i CTR0, CTR1, CTR2, CTR3;
		__m256i X0_0, X0_1, X0_2, X0_3;
		__m256i X1_0, X1_1, X1_2, X1_3;
		__m256i X2_0, X2_1, X2_2, X2_3;
		__m256i X3_0, X3_1, X3_2, X3_3;
	};

	const uint8_t *CurrentIn = in;
	uint8_t *CurrentOut = out;

	const uint64_t FullBlocksCount = len / 512;
	uint64_t RemainingBytes = len % 512;

	LC_DECLARE_MEM(ws, struct workspace, 32);

	ws->state0 = _mm256_broadcastsi128_si256(
		_mm_set_epi32(1797285236, 2036477234, 857760878,
			      1634760805)); //"expand 32-byte k"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	ws->state1 = _mm256_broadcastsi128_si256(
		_mm_load_si128((const __m128i *)(state)));
	ws->state2 = _mm256_broadcastsi128_si256(_mm_load_si128(
		(const __m128i *)(state + LC_CC20_AVX2_STATE_OFFSET(16))));
#pragma GCC diagnostic pop

	ws->CTR0 = _mm256_set_epi32(0, 0, 0, 0, 0, 0, 0, 4);
	ws->CTR1 = _mm256_set_epi32(0, 0, 0, 1, 0, 0, 0, 5);
	ws->CTR2 = _mm256_set_epi32(0, 0, 0, 2, 0, 0, 0, 6);
	ws->CTR3 = _mm256_set_epi32(0, 0, 0, 3, 0, 0, 0, 7);

	for (uint64_t n = 0; n < FullBlocksCount; n++) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		ws->state3 = _mm256_broadcastsi128_si256(_mm_load_si128(
			(const __m128i *)(state +
					  LC_CC20_AVX2_STATE_OFFSET(32))));
#pragma GCC diagnostic pop

		ws->X0_0 = ws->state0;
		ws->X0_1 = ws->state1;
		ws->X0_2 = ws->state2;
		ws->X0_3 = _mm256_add_epi32(ws->state3, ws->CTR0);

		ws->X1_0 = ws->state0;
		ws->X1_1 = ws->state1;
		ws->X1_2 = ws->state2;
		ws->X1_3 = _mm256_add_epi32(ws->state3, ws->CTR1);

		ws->X2_0 = ws->state0;
		ws->X2_1 = ws->state1;
		ws->X2_2 = ws->state2;
		ws->X2_3 = _mm256_add_epi32(ws->state3, ws->CTR2);

		ws->X3_0 = ws->state0;
		ws->X3_1 = ws->state1;
		ws->X3_2 = ws->state2;
		ws->X3_3 = _mm256_add_epi32(ws->state3, ws->CTR3);

		for (int i = 20; i > 0; i -= 2) {
			ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->X0_1);
			ws->X1_0 = _mm256_add_epi32(ws->X1_0, ws->X1_1);
			ws->X2_0 = _mm256_add_epi32(ws->X2_0, ws->X2_1);
			ws->X3_0 = _mm256_add_epi32(ws->X3_0, ws->X3_1);

			ws->X0_3 = _mm256_xor_si256(ws->X0_3, ws->X0_0);
			ws->X1_3 = _mm256_xor_si256(ws->X1_3, ws->X1_0);
			ws->X2_3 = _mm256_xor_si256(ws->X2_3, ws->X2_0);
			ws->X3_3 = _mm256_xor_si256(ws->X3_3, ws->X3_0);

			ws->X0_3 = RotateLeft16(ws->X0_3);
			ws->X1_3 = RotateLeft16(ws->X1_3);
			ws->X2_3 = RotateLeft16(ws->X2_3);
			ws->X3_3 = RotateLeft16(ws->X3_3);

			ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->X0_3);
			ws->X1_2 = _mm256_add_epi32(ws->X1_2, ws->X1_3);
			ws->X2_2 = _mm256_add_epi32(ws->X2_2, ws->X2_3);
			ws->X3_2 = _mm256_add_epi32(ws->X3_2, ws->X3_3);

			ws->X0_1 = _mm256_xor_si256(ws->X0_1, ws->X0_2);
			ws->X1_1 = _mm256_xor_si256(ws->X1_1, ws->X1_2);
			ws->X2_1 = _mm256_xor_si256(ws->X2_1, ws->X2_2);
			ws->X3_1 = _mm256_xor_si256(ws->X3_1, ws->X3_2);

			ws->X0_1 = RotateLeft12(ws->X0_1);
			ws->X1_1 = RotateLeft12(ws->X1_1);
			ws->X2_1 = RotateLeft12(ws->X2_1);
			ws->X3_1 = RotateLeft12(ws->X3_1);

			ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->X0_1);
			ws->X1_0 = _mm256_add_epi32(ws->X1_0, ws->X1_1);
			ws->X2_0 = _mm256_add_epi32(ws->X2_0, ws->X2_1);
			ws->X3_0 = _mm256_add_epi32(ws->X3_0, ws->X3_1);

			ws->X0_3 = _mm256_xor_si256(ws->X0_3, ws->X0_0);
			ws->X1_3 = _mm256_xor_si256(ws->X1_3, ws->X1_0);
			ws->X2_3 = _mm256_xor_si256(ws->X2_3, ws->X2_0);
			ws->X3_3 = _mm256_xor_si256(ws->X3_3, ws->X3_0);

			ws->X0_3 = RotateLeft8(ws->X0_3);
			ws->X1_3 = RotateLeft8(ws->X1_3);
			ws->X2_3 = RotateLeft8(ws->X2_3);
			ws->X3_3 = RotateLeft8(ws->X3_3);

			ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->X0_3);
			ws->X1_2 = _mm256_add_epi32(ws->X1_2, ws->X1_3);
			ws->X2_2 = _mm256_add_epi32(ws->X2_2, ws->X2_3);
			ws->X3_2 = _mm256_add_epi32(ws->X3_2, ws->X3_3);

			ws->X0_1 = _mm256_xor_si256(ws->X0_1, ws->X0_2);
			ws->X1_1 = _mm256_xor_si256(ws->X1_1, ws->X1_2);
			ws->X2_1 = _mm256_xor_si256(ws->X2_1, ws->X2_2);
			ws->X3_1 = _mm256_xor_si256(ws->X3_1, ws->X3_2);

			ws->X0_1 = RotateLeft7(ws->X0_1);
			ws->X1_1 = RotateLeft7(ws->X1_1);
			ws->X2_1 = RotateLeft7(ws->X2_1);
			ws->X3_1 = RotateLeft7(ws->X3_1);

			ws->X0_1 = _mm256_shuffle_epi32(ws->X0_1,
						    _MM_SHUFFLE(0, 3, 2, 1));
			ws->X0_2 = _mm256_shuffle_epi32(ws->X0_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X0_3 = _mm256_shuffle_epi32(ws->X0_3,
						    _MM_SHUFFLE(2, 1, 0, 3));

			ws->X1_1 = _mm256_shuffle_epi32(ws->X1_1,
						    _MM_SHUFFLE(0, 3, 2, 1));
			ws->X1_2 = _mm256_shuffle_epi32(ws->X1_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X1_3 = _mm256_shuffle_epi32(ws->X1_3,
						    _MM_SHUFFLE(2, 1, 0, 3));

			ws->X2_1 = _mm256_shuffle_epi32(ws->X2_1,
						    _MM_SHUFFLE(0, 3, 2, 1));
			ws->X2_2 = _mm256_shuffle_epi32(ws->X2_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X2_3 = _mm256_shuffle_epi32(ws->X2_3,
						    _MM_SHUFFLE(2, 1, 0, 3));

			ws->X3_1 = _mm256_shuffle_epi32(ws->X3_1,
						    _MM_SHUFFLE(0, 3, 2, 1));
			ws->X3_2 = _mm256_shuffle_epi32(ws->X3_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X3_3 = _mm256_shuffle_epi32(ws->X3_3,
						    _MM_SHUFFLE(2, 1, 0, 3));

			ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->X0_1);
			ws->X1_0 = _mm256_add_epi32(ws->X1_0, ws->X1_1);
			ws->X2_0 = _mm256_add_epi32(ws->X2_0, ws->X2_1);
			ws->X3_0 = _mm256_add_epi32(ws->X3_0, ws->X3_1);

			ws->X0_3 = _mm256_xor_si256(ws->X0_3, ws->X0_0);
			ws->X1_3 = _mm256_xor_si256(ws->X1_3, ws->X1_0);
			ws->X2_3 = _mm256_xor_si256(ws->X2_3, ws->X2_0);
			ws->X3_3 = _mm256_xor_si256(ws->X3_3, ws->X3_0);

			ws->X0_3 = RotateLeft16(ws->X0_3);
			ws->X1_3 = RotateLeft16(ws->X1_3);
			ws->X2_3 = RotateLeft16(ws->X2_3);
			ws->X3_3 = RotateLeft16(ws->X3_3);

			ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->X0_3);
			ws->X1_2 = _mm256_add_epi32(ws->X1_2, ws->X1_3);
			ws->X2_2 = _mm256_add_epi32(ws->X2_2, ws->X2_3);
			ws->X3_2 = _mm256_add_epi32(ws->X3_2, ws->X3_3);

			ws->X0_1 = _mm256_xor_si256(ws->X0_1, ws->X0_2);
			ws->X1_1 = _mm256_xor_si256(ws->X1_1, ws->X1_2);
			ws->X2_1 = _mm256_xor_si256(ws->X2_1, ws->X2_2);
			ws->X3_1 = _mm256_xor_si256(ws->X3_1, ws->X3_2);

			ws->X0_1 = RotateLeft12(ws->X0_1);
			ws->X1_1 = RotateLeft12(ws->X1_1);
			ws->X2_1 = RotateLeft12(ws->X2_1);
			ws->X3_1 = RotateLeft12(ws->X3_1);

			ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->X0_1);
			ws->X1_0 = _mm256_add_epi32(ws->X1_0, ws->X1_1);
			ws->X2_0 = _mm256_add_epi32(ws->X2_0, ws->X2_1);
			ws->X3_0 = _mm256_add_epi32(ws->X3_0, ws->X3_1);

			ws->X0_3 = _mm256_xor_si256(ws->X0_3, ws->X0_0);
			ws->X1_3 = _mm256_xor_si256(ws->X1_3, ws->X1_0);
			ws->X2_3 = _mm256_xor_si256(ws->X2_3, ws->X2_0);
			ws->X3_3 = _mm256_xor_si256(ws->X3_3, ws->X3_0);

			ws->X0_3 = RotateLeft8(ws->X0_3);
			ws->X1_3 = RotateLeft8(ws->X1_3);
			ws->X2_3 = RotateLeft8(ws->X2_3);
			ws->X3_3 = RotateLeft8(ws->X3_3);

			ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->X0_3);
			ws->X1_2 = _mm256_add_epi32(ws->X1_2, ws->X1_3);
			ws->X2_2 = _mm256_add_epi32(ws->X2_2, ws->X2_3);
			ws->X3_2 = _mm256_add_epi32(ws->X3_2, ws->X3_3);

			ws->X0_1 = _mm256_xor_si256(ws->X0_1, ws->X0_2);
			ws->X1_1 = _mm256_xor_si256(ws->X1_1, ws->X1_2);
			ws->X2_1 = _mm256_xor_si256(ws->X2_1, ws->X2_2);
			ws->X3_1 = _mm256_xor_si256(ws->X3_1, ws->X3_2);

			ws->X0_1 = RotateLeft7(ws->X0_1);
			ws->X1_1 = RotateLeft7(ws->X1_1);
			ws->X2_1 = RotateLeft7(ws->X2_1);
			ws->X3_1 = RotateLeft7(ws->X3_1);

			ws->X0_1 = _mm256_shuffle_epi32(ws->X0_1,
						    _MM_SHUFFLE(2, 1, 0, 3));
			ws->X0_2 = _mm256_shuffle_epi32(ws->X0_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X0_3 = _mm256_shuffle_epi32(ws->X0_3,
						    _MM_SHUFFLE(0, 3, 2, 1));

			ws->X1_1 = _mm256_shuffle_epi32(ws->X1_1,
						    _MM_SHUFFLE(2, 1, 0, 3));
			ws->X1_2 = _mm256_shuffle_epi32(ws->X1_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X1_3 = _mm256_shuffle_epi32(ws->X1_3,
						    _MM_SHUFFLE(0, 3, 2, 1));

			ws->X2_1 = _mm256_shuffle_epi32(ws->X2_1,
						    _MM_SHUFFLE(2, 1, 0, 3));
			ws->X2_2 = _mm256_shuffle_epi32(ws->X2_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X2_3 = _mm256_shuffle_epi32(ws->X2_3,
						    _MM_SHUFFLE(0, 3, 2, 1));

			ws->X3_1 = _mm256_shuffle_epi32(ws->X3_1,
						    _MM_SHUFFLE(2, 1, 0, 3));
			ws->X3_2 = _mm256_shuffle_epi32(ws->X3_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X3_3 = _mm256_shuffle_epi32(ws->X3_3,
						    _MM_SHUFFLE(0, 3, 2, 1));
		}

		ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->state0);
		ws->X0_1 = _mm256_add_epi32(ws->X0_1, ws->state1);
		ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->state2);
		ws->X0_3 = _mm256_add_epi32(ws->X0_3, ws->state3);
		ws->X0_3 = _mm256_add_epi32(ws->X0_3, ws->CTR0);

		ws->X1_0 = _mm256_add_epi32(ws->X1_0, ws->state0);
		ws->X1_1 = _mm256_add_epi32(ws->X1_1, ws->state1);
		ws->X1_2 = _mm256_add_epi32(ws->X1_2, ws->state2);
		ws->X1_3 = _mm256_add_epi32(ws->X1_3, ws->state3);
		ws->X1_3 = _mm256_add_epi32(ws->X1_3, ws->CTR1);

		ws->X2_0 = _mm256_add_epi32(ws->X2_0, ws->state0);
		ws->X2_1 = _mm256_add_epi32(ws->X2_1, ws->state1);
		ws->X2_2 = _mm256_add_epi32(ws->X2_2, ws->state2);
		ws->X2_3 = _mm256_add_epi32(ws->X2_3, ws->state3);
		ws->X2_3 = _mm256_add_epi32(ws->X2_3, ws->CTR2);

		ws->X3_0 = _mm256_add_epi32(ws->X3_0, ws->state0);
		ws->X3_1 = _mm256_add_epi32(ws->X3_1, ws->state1);
		ws->X3_2 = _mm256_add_epi32(ws->X3_2, ws->state2);
		ws->X3_3 = _mm256_add_epi32(ws->X3_3, ws->state3);
		ws->X3_3 = _mm256_add_epi32(ws->X3_3, ws->CTR3);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		if (in) {
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 0 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X0_0, ws->X0_1,
								  1 + (3 << 4)),
					_mm256_loadu_si256(
						(__m256i *)(CurrentIn +
							    0 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 1 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X0_2, ws->X0_3,
								  1 + (3 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  1 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 2 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X1_0, ws->X1_1,
								  1 + (3 << 4)),
					_mm256_loadu_si256(
						((const __m256i *)(CurrentIn +
								   2 * 32)))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 3 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X1_2, ws->X1_3,
								  1 + (3 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  3 * 32))));

			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 4 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X2_0, ws->X2_1,
								  1 + (3 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  4 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 5 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X2_2, ws->X2_3,
								  1 + (3 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  5 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 6 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X3_0, ws->X3_1,
								  1 + (3 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  6 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 7 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X3_2, ws->X3_3,
								  1 + (3 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  7 * 32))));

			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 8 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X0_0, ws->X0_1,
								  0 + (2 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  8 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 9 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X0_2, ws->X0_3,
								  0 + (2 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  9 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 10 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X1_0, ws->X1_1,
								  0 + (2 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  10 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 11 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X1_2, ws->X1_3,
								  0 + (2 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  11 * 32))));

			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 12 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X2_0, ws->X2_1,
								  0 + (2 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  12 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 13 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X2_2, ws->X2_3,
								  0 + (2 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  13 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 14 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X3_0, ws->X3_1,
								  0 + (2 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  14 * 32))));
			_mm256_storeu_si256(
				(__m256i *)(CurrentOut + 15 * 32),
				_mm256_xor_si256(
					_mm256_permute2x128_si256(ws->X3_2, ws->X3_3,
								  0 + (2 << 4)),
					_mm256_loadu_si256(
						(const __m256i *)(CurrentIn +
								  15 * 32))));
		} else {
			_mm256_storeu_si256((__m256i *)(CurrentOut + 0 * 32),
					    _mm256_permute2x128_si256(
						    ws->X0_0, ws->X0_1, 1 + (3 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 1 * 32),
					    _mm256_permute2x128_si256(
						    ws->X0_2, ws->X0_3, 1 + (3 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 2 * 32),
					    _mm256_permute2x128_si256(
						    ws->X1_0, ws->X1_1, 1 + (3 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 3 * 32),
					    _mm256_permute2x128_si256(
						    ws->X1_2, ws->X1_3, 1 + (3 << 4)));

			_mm256_storeu_si256((__m256i *)(CurrentOut + 4 * 32),
					    _mm256_permute2x128_si256(
						    ws->X2_0, ws->X2_1, 1 + (3 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 5 * 32),
					    _mm256_permute2x128_si256(
						    ws->X2_2, ws->X2_3, 1 + (3 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 6 * 32),
					    _mm256_permute2x128_si256(
						    ws->X3_0, ws->X3_1, 1 + (3 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 7 * 32),
					    _mm256_permute2x128_si256(
						    ws->X3_2, ws->X3_3, 1 + (3 << 4)));

			_mm256_storeu_si256((__m256i *)(CurrentOut + 8 * 32),
					    _mm256_permute2x128_si256(
						    ws->X0_0, ws->X0_1, 0 + (2 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 9 * 32),
					    _mm256_permute2x128_si256(
						    ws->X0_2, ws->X0_3, 0 + (2 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 10 * 32),
					    _mm256_permute2x128_si256(
						    ws->X1_0, ws->X1_1, 0 + (2 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 11 * 32),
					    _mm256_permute2x128_si256(
						    ws->X1_2, ws->X1_3, 0 + (2 << 4)));

			_mm256_storeu_si256((__m256i *)(CurrentOut + 12 * 32),
					    _mm256_permute2x128_si256(
						    ws->X2_0, ws->X2_1, 0 + (2 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 13 * 32),
					    _mm256_permute2x128_si256(
						    ws->X2_2, ws->X2_3, 0 + (2 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 14 * 32),
					    _mm256_permute2x128_si256(
						    ws->X3_0, ws->X3_1, 0 + (2 << 4)));
			_mm256_storeu_si256((__m256i *)(CurrentOut + 15 * 32),
					    _mm256_permute2x128_si256(
						    ws->X3_2, ws->X3_3, 0 + (2 << 4)));
		}
#pragma GCC diagnostic pop

		/* Timecop: output is not sensitive regarding side-channels. */
		unpoison(CurrentOut, 512);

		ChaCha20AddCounter(state, 8);
		if (CurrentIn)
			CurrentIn += 512;
		CurrentOut += 512;
	}

	if (RemainingBytes == 0)
		goto out;

	ws->CTR0 = _mm256_set_epi32(0, 0, 0, 0, 0, 0, 0, 1);

	while (1) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		ws->state3 =
			_mm256_broadcastsi128_si256(_mm_load_si128(
				(const __m128i *)(state +
						  LC_CC20_AVX2_STATE_OFFSET(
							  32))));
#pragma GCC diagnostic pop

		ws->X0_0 = ws->state0;
		ws->X0_1 = ws->state1;
		ws->X0_2 = ws->state2;
		ws->X0_3 = _mm256_add_epi32(ws->state3, ws->CTR0);

		for (unsigned int i = 20; i > 0; i -= 2) {
			ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->X0_1);

			ws->X0_3 = _mm256_xor_si256(ws->X0_3, ws->X0_0);

			ws->X0_3 = RotateLeft16(ws->X0_3);

			ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->X0_3);

			ws->X0_1 = _mm256_xor_si256(ws->X0_1, ws->X0_2);

			ws->X0_1 = RotateLeft12(ws->X0_1);

			ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->X0_1);

			ws->X0_3 = _mm256_xor_si256(ws->X0_3, ws->X0_0);

			ws->X0_3 = RotateLeft8(ws->X0_3);

			ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->X0_3);

			ws->X0_1 = _mm256_xor_si256(ws->X0_1, ws->X0_2);

			ws->X0_1 = RotateLeft7(ws->X0_1);

			ws->X0_1 = _mm256_shuffle_epi32(ws->X0_1,
						    _MM_SHUFFLE(0, 3, 2, 1));
			ws->X0_2 = _mm256_shuffle_epi32(ws->X0_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X0_3 = _mm256_shuffle_epi32(ws->X0_3,
						    _MM_SHUFFLE(2, 1, 0, 3));

			ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->X0_1);

			ws->X0_3 = _mm256_xor_si256(ws->X0_3, ws->X0_0);

			ws->X0_3 = RotateLeft16(ws->X0_3);

			ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->X0_3);

			ws->X0_1 = _mm256_xor_si256(ws->X0_1, ws->X0_2);

			ws->X0_1 = RotateLeft12(ws->X0_1);

			ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->X0_1);

			ws->X0_3 = _mm256_xor_si256(ws->X0_3, ws->X0_0);

			ws->X0_3 = RotateLeft8(ws->X0_3);

			ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->X0_3);

			ws->X0_1 = _mm256_xor_si256(ws->X0_1, ws->X0_2);

			ws->X0_1 = RotateLeft7(ws->X0_1);

			ws->X0_1 = _mm256_shuffle_epi32(ws->X0_1,
						    _MM_SHUFFLE(2, 1, 0, 3));
			ws->X0_2 = _mm256_shuffle_epi32(ws->X0_2,
						    _MM_SHUFFLE(1, 0, 3, 2));
			ws->X0_3 = _mm256_shuffle_epi32(ws->X0_3,
						    _MM_SHUFFLE(0, 3, 2, 1));
		}

		ws->X0_0 = _mm256_add_epi32(ws->X0_0, ws->state0);
		ws->X0_1 = _mm256_add_epi32(ws->X0_1, ws->state1);
		ws->X0_2 = _mm256_add_epi32(ws->X0_2, ws->state2);
		ws->X0_3 = _mm256_add_epi32(ws->X0_3, ws->state3);
		ws->X0_3 = _mm256_add_epi32(ws->X0_3, ws->CTR0);

		if (RemainingBytes >= 128) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			if (in) {
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut + 0 * 32),
					_mm256_xor_si256(
						_mm256_permute2x128_si256(
							ws->X0_0, ws->X0_1,
							1 + (3 << 4)),
						_mm256_loadu_si256(
							(__m256i *)(CurrentIn +
								    0 * 32))));
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut + 1 * 32),
					_mm256_xor_si256(
						_mm256_permute2x128_si256(
							ws->X0_2, ws->X0_3,
							1 + (3 << 4)),
						_mm256_loadu_si256(
							(const __m256i
								 *)(CurrentIn +
								    1 * 32))));
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut + 2 * 32),
					_mm256_xor_si256(
						_mm256_permute2x128_si256(
							ws->X0_0, ws->X0_1,
							0 + (2 << 4)),
						_mm256_loadu_si256(
							(const __m256i
								 *)(CurrentIn +
								    2 * 32))));
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut + 3 * 32),
					_mm256_xor_si256(
						_mm256_permute2x128_si256(
							ws->X0_2, ws->X0_3,
							0 + (2 << 4)),
						_mm256_loadu_si256(
							(const __m256i
								 *)(CurrentIn +
								    3 * 32))));

			} else {
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut + 0 * 32),
					_mm256_permute2x128_si256(
						ws->X0_0, ws->X0_1, 1 + (3 << 4)));
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut + 1 * 32),
					_mm256_permute2x128_si256(
						ws->X0_2, ws->X0_3, 1 + (3 << 4)));
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut + 2 * 32),
					_mm256_permute2x128_si256(
						ws->X0_0, ws->X0_1, 0 + (2 << 4)));
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut + 3 * 32),
					_mm256_permute2x128_si256(
						ws->X0_2, ws->X0_3, 0 + (2 << 4)));
			}
#pragma GCC diagnostic pop
			ChaCha20AddCounter(state, 2);

			/* Timecop: output is not sensitive regarding side-channels. */
			unpoison(CurrentOut, 128);

			RemainingBytes -= 128;
			if (RemainingBytes == 0)
				goto out;
			if (CurrentIn)
				CurrentIn += 128;
			CurrentOut += 128;
			continue;
		} else //last, partial block
		{
			__m256i tmp;
			if (in) // encrypt
			{
				tmp = _mm256_permute2x128_si256(ws->X0_0, ws->X0_1,
								1 + (3 << 4));
				if (RemainingBytes < 32) {
					PartialXor(tmp, CurrentIn, CurrentOut,
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
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut),
					_mm256_xor_si256(
						tmp,
						_mm256_loadu_si256((
							const __m256i
								*)(CurrentIn))));
#pragma GCC diagnostic pop
				/*
				 * Timecop: output is not sensitive regarding
				 * side-channels.
				 */
				unpoison(CurrentOut, 32);

				RemainingBytes -= 32;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 1);
					goto out;
				}

				CurrentIn += 32;
				CurrentOut += 32;

				tmp = _mm256_permute2x128_si256(ws->X0_2, ws->X0_3,
								1 + (3 << 4));
				if (RemainingBytes < 32) {
					PartialXor(tmp, CurrentIn, CurrentOut,
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
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut),
					_mm256_xor_si256(
						tmp,
						_mm256_loadu_si256((
							const __m256i
								*)(CurrentIn))));
#pragma GCC diagnostic pop
				/*
				 * Timecop: output is not sensitive regarding
				 * side-channels.
				 */
				unpoison(CurrentOut, 32);

				RemainingBytes -= 32;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 1);
					goto out;
				}
				CurrentIn += 32;
				CurrentOut += 32;

				tmp = _mm256_permute2x128_si256(ws->X0_0, ws->X0_1,
								0 + (2 << 4));
				if (RemainingBytes < 32) {
					PartialXor(tmp, CurrentIn, CurrentOut,
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
				_mm256_storeu_si256(
					(__m256i *)(CurrentOut),
					_mm256_xor_si256(
						tmp,
						_mm256_loadu_si256((
							const __m256i
								*)(CurrentIn))));
#pragma GCC diagnostic pop
				/*
				 * Timecop: output is not sensitive regarding
				 * side-channels.
				 */
				unpoison(CurrentOut, 32);

				RemainingBytes -= 32;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 2);
					goto out;
				}
				CurrentIn += 32;
				CurrentOut += 32;

				tmp = _mm256_permute2x128_si256(ws->X0_2, ws->X0_3,
								0 + (2 << 4));
				PartialXor(tmp, CurrentIn, CurrentOut,
					   RemainingBytes);

				/*
				 * Timecop: output is not sensitive regarding
				 * side-channels.
				 */
				unpoison(CurrentOut, RemainingBytes);

				ChaCha20AddCounter(state, 2);
				goto out;
			} else {
				tmp = _mm256_permute2x128_si256(ws->X0_0, ws->X0_1,
								1 + (3 << 4));
				if (RemainingBytes < 32) {
					PartialStore(tmp, CurrentOut,
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
				_mm256_storeu_si256((__m256i *)(CurrentOut),
						    tmp);
#pragma GCC diagnostic pop
				/*
				 * Timecop: output is not sensitive regarding
				 * side-channels.
				 */
				unpoison(CurrentOut, 32);

				RemainingBytes -= 32;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 1);
					goto out;
				}
				CurrentOut += 32;

				tmp = _mm256_permute2x128_si256(ws->X0_2, ws->X0_3,
								1 + (3 << 4));

				if (RemainingBytes < 32) {
					PartialStore(tmp, CurrentOut,
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
				_mm256_storeu_si256((__m256i *)(CurrentOut),
						    tmp);
#pragma GCC diagnostic pop
				/*
				 * Timecop: output is not sensitive regarding
				 * side-channels.
				 */
				unpoison(CurrentOut, 32);

				RemainingBytes -= 32;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 1);
					goto out;
				}
				CurrentOut += 32;

				tmp = _mm256_permute2x128_si256(ws->X0_0, ws->X0_1,
								0 + (2 << 4));
				if (RemainingBytes < 32) {
					PartialStore(tmp, CurrentOut,
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
				_mm256_storeu_si256((__m256i *)(CurrentOut),
						    tmp);
#pragma GCC diagnostic pop
				/*
				 * Timecop: output is not sensitive regarding
				 * side-channels.
				 */
				unpoison(CurrentOut, 32);

				RemainingBytes -= 32;
				if (RemainingBytes == 0) {
					ChaCha20AddCounter(state, 2);
					goto out;
				}
				CurrentOut += 32;

				tmp = _mm256_permute2x128_si256(ws->X0_2, ws->X0_3,
								0 + (2 << 4));
				PartialStore(tmp, CurrentOut, RemainingBytes);

				/*
				 * Timecop: output is not sensitive regarding
				 * side-channels.
				 */
				unpoison(CurrentOut, RemainingBytes);

				ChaCha20AddCounter(state, 2);
				goto out;
			}
		}
	}

out:
	return 0;
}
