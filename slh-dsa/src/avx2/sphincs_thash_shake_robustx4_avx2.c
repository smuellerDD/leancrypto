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
		state[i] = _mm256_set1_epi64x(
			((int64_t *)ctx->pub_seed)[i]);
	}
#pragma GCC diagnostic pop

	for (i = 0; i < 4; i++) {
		state[LC_SPX_N / 8 + i] = _mm256_set_epi32(
			(int32_t)addrx4[3 * 8 + 1 + 2 * i],
			(int32_t)addrx4[3 * 8 + 2 * i],
			(int32_t)addrx4[2 * 8 + 1 + 2 * i],
			(int32_t)addrx4[2 * 8 + 2 * i],
			(int32_t)addrx4[8 + 1 + 2 * i],
			(int32_t)addrx4[8 + 2 * i],
			(int32_t)addrx4[1 + 2 * i],
			(int32_t)addrx4[2 * i]);
	}

	/* SHAKE domain separator and padding */
	state[LC_SPX_N / 8 + 4] = _mm256_set1_epi64x(0x1f);
	for (i = LC_SPX_N / 8 + 5; i < 16; i++) {
		state[i] = _mm256_set1_epi64x(0);
	}
	state[16] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

	for (i = 17; i < 25; i++) {
		state[i] = _mm256_set1_epi64x(0);
	}

	/* We will permutate state2 with f1600x4 to compute the bitmask,
	 * but first we'll copy it to state2 which will be used to compute
	 * the final output, as its input is alsmost identical. */
	__m256i state2[25];
	memcpy(state2, state, 800);

	KeccakF1600_StatePermute4x(&state[0]);

	/* By copying from state, state2 already contains the pub_seed
		* and addres.  We just need to copy in the input blocks xorred with
		* the bitmask we just computed. */
	for (i = 0; i < (LC_SPX_N / 8) * inblocks; i++) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		state2[LC_SPX_N / 8 + 4 + i] = _mm256_xor_si256(
			state[i], _mm256_set_epi64x(((int64_t *)in3)[i],
						    ((int64_t *)in2)[i],
						    ((int64_t *)in1)[i],
						    ((int64_t *)in0)[i]));
#pragma GCC diagnostic pop
	}

	/* Domain separator and start of padding.  Note that the quadwords
		* around are already zeroed for state from which we copied.
		* We do a XOR instead of a set as this might be the 16th quadword
		* when N=32 and inblocks=2, which already contains the end
		* of the padding. */
	state2[(LC_SPX_N / 8) * (1 + inblocks) + 4] = _mm256_xor_si256(
		state2[(LC_SPX_N / 8) * (1 + inblocks) + 4],
		_mm256_set1_epi64x(0x1f));

	KeccakF1600_StatePermute4x(&state2[0]);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0; i < LC_SPX_N / 8; i++) {
		((int64_t *)out0)[i] = _mm256_extract_epi64(state2[i], 0);
		((int64_t *)out1)[i] = _mm256_extract_epi64(state2[i], 1);
		((int64_t *)out2)[i] = _mm256_extract_epi64(state2[i], 2);
		((int64_t *)out3)[i] = _mm256_extract_epi64(state2[i], 3);
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
	unsigned int i;
#if 0
	uint8_t buf0[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t buf1[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t buf2[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t buf3[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t bitmask0[LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t bitmask1[LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t bitmask2[LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t bitmask3[LC_SPX_WOTS_LEN * LC_SPX_N];
#endif
	uint8_t *buf0 = thash_buf;
	uint8_t *buf1 = buf0 + LC_THASHX4_BUFLEN;
	uint8_t *buf2 = buf1 + LC_THASHX4_BUFLEN;
	uint8_t *buf3 = buf2 + LC_THASHX4_BUFLEN;
	uint8_t *bitmask0 = buf3 + LC_THASHX4_BUFLEN;
	uint8_t *bitmask1 = bitmask0 + LC_THASHX4_BITMASKLEN;
	uint8_t *bitmask2 = bitmask1 + LC_THASHX4_BITMASKLEN;
	uint8_t *bitmask3 = bitmask2 + LC_THASHX4_BITMASKLEN;

	memcpy(buf0, ctx->pub_seed, LC_SPX_N);
	memcpy(buf1, ctx->pub_seed, LC_SPX_N);
	memcpy(buf2, ctx->pub_seed, LC_SPX_N);
	memcpy(buf3, ctx->pub_seed, LC_SPX_N);
	memcpy(buf0 + LC_SPX_N, addrx4 + 0 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf1 + LC_SPX_N, addrx4 + 1 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf2 + LC_SPX_N, addrx4 + 2 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf3 + LC_SPX_N, addrx4 + 3 * 8, LC_SPX_ADDR_BYTES);

	shake256x4(bitmask0, bitmask1, bitmask2, bitmask3,
			inblocks * LC_SPX_N, buf0, buf1, buf2, buf3,
			LC_SPX_N + LC_SPX_ADDR_BYTES);

	for (i = 0; i < inblocks * LC_SPX_N; i++) {
		buf0[LC_SPX_N + LC_SPX_ADDR_BYTES + i] =
			in0[i] ^ bitmask0[i];
		buf1[LC_SPX_N + LC_SPX_ADDR_BYTES + i] =
			in1[i] ^ bitmask1[i];
		buf2[LC_SPX_N + LC_SPX_ADDR_BYTES + i] =
			in2[i] ^ bitmask2[i];
		buf3[LC_SPX_N + LC_SPX_ADDR_BYTES + i] =
			in3[i] ^ bitmask3[i];
	}

	shake256x4(out0, out1, out2, out3, LC_SPX_N, buf0, buf1, buf2,
			buf3,
			LC_SPX_N + LC_SPX_ADDR_BYTES + inblocks * LC_SPX_N);
}
