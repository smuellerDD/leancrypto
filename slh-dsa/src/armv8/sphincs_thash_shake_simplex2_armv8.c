/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "bitshift.h"
#include "lc_memset_secure.h"
#include "shake_2x_armv8.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_thashx2_armv8.h"
#include "sphincs_utils.h"

#define f1600x2(s) keccak_f1600x2_armce((s), neon_KeccakF_RoundConstants)

/**
 * 2-way parallel version of thash; takes 2x as much input and output
 */
void thashx2_12(unsigned char *out0, unsigned char *out1,
		const unsigned char *in0, const unsigned char *in1,
		unsigned int inblocks, const spx_ctx *ctx,
		uint32_t addrx2[2 * 8])
{
	unsigned int i;

	/*
	 * As we write and read only a few quadwords, it is more efficient to
         * build and extract from the twoway SHAKE256 state by hand.
	 */
	union {
		v128 state128[25];
		uint64_t state[50];
	} s = { 0 };

	for (i = 0; i < LC_SPX_N / 8; i++) {
		uint64_t x = ptr_to_le64(ctx->pub_seed + 8 * i);
		s.state[2 * i] = x;
		s.state[2 * i + 1] = x;
	}
	for (i = 0; i < 4; i++) {
		s.state[2 * (LC_SPX_N / 8 + i)] =
			(((uint64_t)addrx2[1 + 2 * i]) << 32) |
			(uint64_t)addrx2[2 * i];
		s.state[2 * (LC_SPX_N / 8 + i) + 1] =
			(((uint64_t)addrx2[8 + 1 + 2 * i]) << 32) |
			(uint64_t)addrx2[8 + 2 * i];
	}

	for (i = 0; i < (LC_SPX_N / 8) * inblocks; i++) {
		s.state[2 * (LC_SPX_N / 8 + 4 + i)] = ptr_to_le64(in0 + 8 * i);
		s.state[2 * (LC_SPX_N / 8 + 4 + i) + 1] =
			ptr_to_le64(in1 + 8 * i);
	}

	/* Domain separator and padding. */
	s.state[2 * 16] = 0x80ULL << 56;
	s.state[2 * 16 + 1] = 0x80ULL << 56;

	s.state[2 * ((LC_SPX_N / 8) * (1 + inblocks) + 4)] ^= 0x1f;
	s.state[2 * ((LC_SPX_N / 8) * (1 + inblocks) + 4) + 1] ^= 0x1f;

	KeccakF1600_StatePermutex2(s.state128);
	//f1600x2(s.state);

	for (i = 0; i < LC_SPX_N / 8; i++) {
		le64_to_ptr(out0 + 8 * i, s.state[2 * i]);
		le64_to_ptr(out1 + 8 * i, s.state[2 * i + 1]);
	}

	lc_memset_secure(s.state, 0, sizeof(s.state));
}

void thashx2(unsigned char *out0, unsigned char *out1, const unsigned char *in0,
	     const unsigned char *in1, unsigned int inblocks,
	     const spx_ctx *ctx, uint32_t addrx2[2 * 8], uint8_t *thash_buf)
{
#if 0
#if (LC_SPX_FORS_TREES < LC_SPX_WOTS_LEN)
	uint8_t buf0[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t buf1[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
#endif
#endif
	uint8_t *buf0 = thash_buf;
	uint8_t *buf1 = buf0 + LC_THASHX4_BUFLEN;

	memcpy(buf0, ctx->pub_seed, LC_SPX_N);
	memcpy(buf1, ctx->pub_seed, LC_SPX_N);
	memcpy(buf0 + LC_SPX_N, addrx2 + 0 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf1 + LC_SPX_N, addrx2 + 1 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf0 + LC_SPX_N + LC_SPX_ADDR_BYTES, in0, inblocks * LC_SPX_N);
	memcpy(buf1 + LC_SPX_N + LC_SPX_ADDR_BYTES, in1, inblocks * LC_SPX_N);

	shake256x2_armv8(out0, out1, LC_SPX_N, buf0, buf1,
			 LC_SPX_N + LC_SPX_ADDR_BYTES + inblocks * LC_SPX_N);
}
