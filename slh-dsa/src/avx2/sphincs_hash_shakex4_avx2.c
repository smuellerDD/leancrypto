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

#include "alignment.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_hashx4_avx2.h"

#define KeccakF1600_StatePermute4x KeccakP1600times4_PermuteAll_24rounds
extern void KeccakF1600_StatePermute4x(__m256i *s);

/*
 * 4-way parallel version of prf_addr; takes 4x as much input and output
 */
void prf_addrx4(unsigned char *out0,
		unsigned char *out1,
		unsigned char *out2,
		unsigned char *out3,
		const spx_ctx *ctx,
		const uint32_t addrx4[4*8]) {
	/* As we write and read only a few quadwords, it is more efficient to
	 * build and extract from the fourway SHAKE256 state by hand. */
	__m256i state[25];
	unsigned int i;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0; i < LC_SPX_N/8; i++)
		state[i] = _mm256_set1_epi64x(((int64_t*)ctx->pub_seed)[i]);
#pragma GCC diagnostic pop

	for (i = 0; i < 4; i++) {
		state[LC_SPX_N/8+i] = _mm256_set_epi32(
			(int32_t)addrx4[3*8+1+2*i],
			(int32_t)addrx4[3*8+2*i],
			(int32_t)addrx4[2*8+1+2*i],
			(int32_t)addrx4[2*8+2*i],
			(int32_t)addrx4[8+1+2*i],
			(int32_t)addrx4[8+2*i],
			(int32_t)addrx4[1+2*i],
			(int32_t)addrx4[2*i]
		);
	}


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (i = 0; i < LC_SPX_N/8; i++) {
		state[LC_SPX_N/8+i+4] = _mm256_set1_epi64x(((int64_t*)ctx->sk_seed)[i]);
	}
#pragma GCC diagnostic pop

	/* SHAKE domain separator and padding. */
	state[LC_SPX_N/4+4] = _mm256_set1_epi64x(0x1f);
	for (i = LC_SPX_N/4+5; i < 16; i++) {
		state[i] = _mm256_set1_epi64x(0);
	}
	// shift unsigned and then cast to avoid UB
	state[16] = _mm256_set1_epi64x((long long)(0x80ULL << 56));

	for (i = 17; i < 25; i++) {
		state[i] = _mm256_set1_epi64x(0);
	}

	KeccakF1600_StatePermute4x(&state[0]);

	for (i = 0; i < LC_SPX_N/8; i++) {

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		((int64_t*)out0)[i] = _mm256_extract_epi64(state[i], 0);
		((int64_t*)out1)[i] = _mm256_extract_epi64(state[i], 1);
		((int64_t*)out2)[i] = _mm256_extract_epi64(state[i], 2);
		((int64_t*)out3)[i] = _mm256_extract_epi64(state[i], 3);
#pragma GCC diagnostic pop
	}
}
