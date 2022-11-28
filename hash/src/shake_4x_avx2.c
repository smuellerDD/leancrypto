/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "ext_headers.h"
#include "ext_headers_x86.h"
#include "lc_sha3.h"
#include "memcmp_secure.h"
#include "shake_4x_avx2.h"
#include "visibility.h"

/* Use implementation from the Keccak Code Package */
#define KeccakF1600_StatePermute4x KeccakP1600times4_PermuteAll_24rounds
extern void KeccakF1600_StatePermute4x(__m256i *s);

static void keccakx4_absorb_once(__m256i s[25],
				 unsigned int r,
				 const uint8_t *in0,
				 const uint8_t *in1,
				 const uint8_t *in2,
				 const uint8_t *in3,
				 size_t inlen,
				 uint8_t p)
{
	size_t i;
	uint64_t pos = 0;
	__m256i t, idx;

	for(i = 0; i < 25; ++i)
		s[i] = _mm256_setzero_si256();

	idx = _mm256_set_epi64x((long long)in3, (long long)in2,
				(long long)in1, (long long)in0);
	while (inlen >= r) {
		for (i = 0; i < r / 8; ++i) {
			t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
			s[i] = _mm256_xor_si256(s[i], t);
			pos += 8;
		}
		inlen -= r;

		KeccakF1600_StatePermute4x(s);
	}

	for (i = 0; i < inlen/8; ++i) {
		t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
		s[i] = _mm256_xor_si256(s[i], t);
		pos += 8;
	}
	inlen -= 8*i;

	if (inlen) {
		t = _mm256_i64gather_epi64((long long *)pos, idx, 1);
		idx = _mm256_set1_epi64x((1LL << (8*inlen)) - 1);
		t = _mm256_and_si256(t, idx);
		s[i] = _mm256_xor_si256(s[i], t);
	}

	t = _mm256_set1_epi64x((int64_t)p << 8*inlen);
	s[i] = _mm256_xor_si256(s[i], t);
	t = _mm256_set1_epi64x(1LL << 63);
	s[r / 8 - 1] = _mm256_xor_si256(s[r / 8 - 1], t);
}

static void keccakx4_squeezeblocks(uint8_t *out0,
				   uint8_t *out1,
				   uint8_t *out2,
				   uint8_t *out3,
				   size_t nblocks,
				   unsigned int r,
				   __m256i s[25])
{
	unsigned int i;
	__m128d t;

	while (nblocks > 0) {
		KeccakF1600_StatePermute4x(s);
		for (i = 0; i < r / 8; ++i) {
			/*
			 * We can ignore the alignment warning as we checked
			 * for proper alignment.
			 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			t = _mm_castsi128_pd(_mm256_castsi256_si128(s[i]));
			_mm_storel_pd((__attribute__((__may_alias__)) double *)&out0[8*i], t);
			_mm_storeh_pd((__attribute__((__may_alias__)) double *)&out1[8*i], t);
			t = _mm_castsi128_pd(_mm256_extracti128_si256(s[i],1));
			_mm_storel_pd((__attribute__((__may_alias__)) double *)&out2[8*i], t);
			_mm_storeh_pd((__attribute__((__may_alias__)) double *)&out3[8*i], t);
#pragma GCC diagnostic pop
		}

		out0 += r;
		out1 += r;
		out2 += r;
		out3 += r;
		--nblocks;
	}
}

void shake128x4_absorb_once(keccakx4_state *state,
			    const uint8_t *in0,
			    const uint8_t *in1,
			    const uint8_t *in2,
			    const uint8_t *in3,
			    size_t inlen)
{
	LC_FPU_ENABLE;
	keccakx4_absorb_once(state->s, LC_SHAKE_128_SIZE_BLOCK,
			     in0, in1, in2, in3, inlen, 0x1F);
	LC_FPU_DISABLE;
}

void shake128x4_squeezeblocks(uint8_t *out0,
			      uint8_t *out1,
			      uint8_t *out2,
			      uint8_t *out3,
			      size_t nblocks,
			      keccakx4_state *state)
{
	LC_FPU_ENABLE;
	keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks,
			       LC_SHAKE_128_SIZE_BLOCK, state->s);
	LC_FPU_DISABLE;
}

void shake256x4_absorb_once(keccakx4_state *state,
			    const uint8_t *in0,
			    const uint8_t *in1,
			    const uint8_t *in2,
			    const uint8_t *in3,
			    size_t inlen)
{
	LC_FPU_ENABLE;
	keccakx4_absorb_once(state->s, LC_SHAKE_256_SIZE_BLOCK,
			     in0, in1, in2, in3, inlen, 0x1F);
	LC_FPU_DISABLE;
}

void shake256x4_squeezeblocks(uint8_t *out0,
			      uint8_t *out1,
			      uint8_t *out2,
			      uint8_t *out3,
			      size_t nblocks,
			      keccakx4_state *state)
{
	LC_FPU_ENABLE;
	keccakx4_squeezeblocks(out0, out1, out2, out3, nblocks,
			       LC_SHAKE_256_SIZE_BLOCK, state->s);
	LC_FPU_DISABLE;
}

LC_INTERFACE_FUNCTION(
void, shake128x4, uint8_t *out0,
		  uint8_t *out1,
		  uint8_t *out2,
		  uint8_t *out3,
		  size_t outlen,
		  const uint8_t *in0,
		  const uint8_t *in1,
		  const uint8_t *in2,
		  const uint8_t *in3,
		  size_t inlen)
{
	unsigned int i;
	size_t nblocks = outlen/LC_SHAKE_128_SIZE_BLOCK;
	uint8_t t[4][LC_SHAKE_128_SIZE_BLOCK];
	keccakx4_state state;

	shake128x4_absorb_once(&state, in0, in1, in2, in3, inlen);
	shake128x4_squeezeblocks(out0, out1, out2, out3, nblocks, &state);

	out0 += nblocks * LC_SHAKE_128_SIZE_BLOCK;
	out1 += nblocks * LC_SHAKE_128_SIZE_BLOCK;
	out2 += nblocks * LC_SHAKE_128_SIZE_BLOCK;
	out3 += nblocks * LC_SHAKE_128_SIZE_BLOCK;
	outlen -= nblocks * LC_SHAKE_128_SIZE_BLOCK;

	if (outlen) {
		shake128x4_squeezeblocks(t[0], t[1], t[2], t[3], 1, &state);
		for (i = 0; i < outlen; ++i) {
			out0[i] = t[0][i];
			out1[i] = t[1][i];
			out2[i] = t[2][i];
			out3[i] = t[3][i];
		}
	}

	memset_secure(&state, 0, sizeof(state));
}

LC_INTERFACE_FUNCTION(
void, shake256x4, uint8_t *out0,
		  uint8_t *out1,
		  uint8_t *out2,
		  uint8_t *out3,
		  size_t outlen,
		  const uint8_t *in0,
		  const uint8_t *in1,
		  const uint8_t *in2,
		  const uint8_t *in3,
		  size_t inlen)
{
	unsigned int i;
	size_t nblocks = outlen/LC_SHAKE_256_SIZE_BLOCK;
	uint8_t t[4][LC_SHAKE_256_SIZE_BLOCK];
	keccakx4_state state;

	shake256x4_absorb_once(&state, in0, in1, in2, in3, inlen);
	shake256x4_squeezeblocks(out0, out1, out2, out3, nblocks, &state);

	out0 += nblocks*LC_SHAKE_256_SIZE_BLOCK;
	out1 += nblocks*LC_SHAKE_256_SIZE_BLOCK;
	out2 += nblocks*LC_SHAKE_256_SIZE_BLOCK;
	out3 += nblocks*LC_SHAKE_256_SIZE_BLOCK;
	outlen -= nblocks*LC_SHAKE_256_SIZE_BLOCK;

	if (outlen) {
		shake256x4_squeezeblocks(t[0], t[1], t[2], t[3], 1, &state);
		for (i = 0; i < outlen; ++i) {
			out0[i] = t[0][i];
			out1[i] = t[1][i];
			out2[i] = t[2][i];
			out3[i] = t[3][i];
		}
	}

	memset_secure(&state, 0, sizeof(state));
}
