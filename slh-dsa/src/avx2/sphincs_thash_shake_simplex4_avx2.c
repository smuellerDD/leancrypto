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
 * https://github.com/sphincs/sphincsplus
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "ext_headers_x86.h"
#include "shake_4x_avx2.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_thashx4_avx2.h"
#include "sphincs_utils.h"

#define KeccakF1600_StatePermute4x KeccakP1600times4_PermuteAll_24rounds
extern void KeccakF1600_StatePermute4x(__m256i *s);

/**
 * 4-way parallel version of thash; takes 4x as much input and output
 */
void thashx4_12(unsigned char *out0, unsigned char *out1, unsigned char *out2,
		unsigned char *out3, const unsigned char *in0,
		const unsigned char *in1, const unsigned char *in2,
		const unsigned char *in3, unsigned int inblocks,
		const spx_ctx *ctx, uint32_t addrx4[4 * 8])
{
	unsigned int i;

	/*
	 * As we write and read only a few quadwords, it is more efficient to
         * build and extract from the fourway SHAKE256 state by hand.
	 */
	__m256i state[25];

	LC_FPU_ENABLE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0; i < LC_SPX_N / 8; i++) {
		state[i] = _mm256_set1_epi64x(((int64_t *)ctx->pub_seed)[i]);
	}
#pragma GCC diagnostic pop

	for (i = 0; i < 4; i++) {
		state[LC_SPX_N / 8 + i] =
			_mm256_set_epi32((int32_t)addrx4[3 * 8 + 1 + 2 * i],
					 (int32_t)addrx4[3 * 8 + 2 * i],
					 (int32_t)addrx4[2 * 8 + 1 + 2 * i],
					 (int32_t)addrx4[2 * 8 + 2 * i],
					 (int32_t)addrx4[8 + 1 + 2 * i],
					 (int32_t)addrx4[8 + 2 * i],
					 (int32_t)addrx4[1 + 2 * i],
					 (int32_t)addrx4[2 * i]);
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0; i < (LC_SPX_N / 8) * inblocks; i++) {
		state[LC_SPX_N / 8 + 4 + i] = _mm256_set_epi64x(
			((int64_t *)in3)[i], ((int64_t *)in2)[i],
			((int64_t *)in1)[i], ((int64_t *)in0)[i]);
	}
#pragma GCC diagnostic pop

	/* Domain separator and padding. */
	for (i = (LC_SPX_N / 8) * (1 + inblocks) + 4; i < 16; i++) {
		state[i] = _mm256_set1_epi64x(0);
	}

	state[16] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

	state[(LC_SPX_N / 8) * (1 + inblocks) + 4] =
		_mm256_xor_si256(state[(LC_SPX_N / 8) * (1 + inblocks) + 4],
				 _mm256_set1_epi64x(0x1f));
	for (i = 17; i < 25; i++) {
		state[i] = _mm256_set1_epi64x(0);
	}

	KeccakP1600times4_PermuteAll_24rounds(&state[0]);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0; i < LC_SPX_N / 8; i++) {
		((int64_t *)out0)[i] = _mm256_extract_epi64(state[i], 0);
		((int64_t *)out1)[i] = _mm256_extract_epi64(state[i], 1);
		((int64_t *)out2)[i] = _mm256_extract_epi64(state[i], 2);
		((int64_t *)out3)[i] = _mm256_extract_epi64(state[i], 3);
	}
#pragma GCC diagnostic pop

	LC_FPU_DISABLE;
}

void thashx4(unsigned char *out0, unsigned char *out1, unsigned char *out2,
	     unsigned char *out3, const unsigned char *in0,
	     const unsigned char *in1, const unsigned char *in2,
	     const unsigned char *in3, unsigned int inblocks,
	     const spx_ctx *ctx, uint32_t addrx4[4 * 8], uint8_t *thash_buf)
{
#if 0
	uint8_t buf0[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t buf1[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t buf2[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t buf3[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
#endif
	uint8_t *buf0 = thash_buf;
	uint8_t *buf1 = buf0 + LC_THASHX4_BUFLEN;
	uint8_t *buf2 = buf1 + LC_THASHX4_BUFLEN;
	uint8_t *buf3 = buf2 + LC_THASHX4_BUFLEN;

	memcpy(buf0, ctx->pub_seed, LC_SPX_N);
	memcpy(buf1, ctx->pub_seed, LC_SPX_N);
	memcpy(buf2, ctx->pub_seed, LC_SPX_N);
	memcpy(buf3, ctx->pub_seed, LC_SPX_N);
	memcpy(buf0 + LC_SPX_N, addrx4 + 0 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf1 + LC_SPX_N, addrx4 + 1 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf2 + LC_SPX_N, addrx4 + 2 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf3 + LC_SPX_N, addrx4 + 3 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf0 + LC_SPX_N + LC_SPX_ADDR_BYTES, in0, inblocks * LC_SPX_N);
	memcpy(buf1 + LC_SPX_N + LC_SPX_ADDR_BYTES, in1, inblocks * LC_SPX_N);
	memcpy(buf2 + LC_SPX_N + LC_SPX_ADDR_BYTES, in2, inblocks * LC_SPX_N);
	memcpy(buf3 + LC_SPX_N + LC_SPX_ADDR_BYTES, in3, inblocks * LC_SPX_N);

	shake256x4(out0, out1, out2, out3, LC_SPX_N, buf0, buf1, buf2, buf3,
		   LC_SPX_N + LC_SPX_ADDR_BYTES + inblocks * LC_SPX_N);
}
