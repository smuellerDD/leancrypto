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

#include "shake_2x_armv8.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_thashx2_armv8.h"
#include "sphincs_utils.h"

#define f1600x2(s) keccak_f1600x2_armce((s), neon_KeccakF_RoundConstants)

//TODO use the ptr_to_...
static uint64_t load64(const unsigned char *x)
{
	unsigned long long r = 0, i;

	for (i = 0; i < 8; ++i) {
		r |= (unsigned long long)x[i] << 8 * i;
	}
	return r;
}

static void store64(uint8_t *x, uint64_t u)
{
	unsigned int i;

	for (i = 0; i < 8; ++i) {
		x[i] = (uint8_t)u;
		u >>= 8;
	}
}

/**
 * 2-way parallel version of thash; takes 2x as much input and output
 */
void thashx2_12(unsigned char *out0, unsigned char *out1,
		const unsigned char *in0, const unsigned char *in1,
		unsigned int inblocks, const spx_ctx *ctx,
		uint32_t addrx2[2 * 8])
{
	/* As we write and read only a few quadwords, it is more efficient to
         * build and extract from the twoway SHAKE256 state by hand. */
	uint64_t state[50] = { 0 };
	uint64_t state2[50];

	for (int i = 0; i < LC_SPX_N / 8; i++) {
		uint64_t x = load64(ctx->pub_seed + 8 * i);
		state[2 * i] = x;
		state[2 * i + 1] = x;
	}
	for (int i = 0; i < 4; i++) {
		state[2 * (LC_SPX_N / 8 + i)] =
			(((uint64_t)addrx2[1 + 2 * i]) << 32) |
			(uint64_t)addrx2[2 * i];
		state[2 * (LC_SPX_N / 8 + i) + 1] =
			(((uint64_t)addrx2[8 + 1 + 2 * i]) << 32) |
			(uint64_t)addrx2[8 + 2 * i];
	}

	/* Domain separator and padding. */
	state[2 * 16] = 0x80ULL << 56;
	state[2 * 16 + 1] = 0x80ULL << 56;

	state[2 * ((LC_SPX_N / 8) + 4)] ^= 0x1f;
	state[2 * ((LC_SPX_N / 8) + 4) + 1] ^= 0x1f;

	/* We will permutate state2 with f1600x2 to compute the bitmask,
	* but first we'll copy it to state2 which will be used to compute
	* the final output, as its input is almost identical. */
	memcpy(state2, state, 400);

	f1600x2(state);

	/* By copying from state, state2 already contains the pub_seed
	* and address.  We just need to copy in the input blocks xorred with
	* the bitmask we just computed. */
	for (unsigned int i = 0; i < (LC_SPX_N / 8) * inblocks; i++) {
		state2[2 * (LC_SPX_N / 8 + 4 + i)] =
			state[2 * i] ^ load64(in0 + 8 * i);
		state2[2 * (LC_SPX_N / 8 + 4 + i) + 1] =
			state[2 * i + 1] ^ load64(in1 + 8 * i);
	}

	/*
		* Domain separator and start of padding.  Note that the quadwords
		* around are already zeroed for state from which we copied.
		* We do a XOR instead of a set as this might be the 16th quadword
		* when N=32 and inblocks=2, which already contains the end
		* of the padding.
		*/
	state2[2 * ((LC_SPX_N / 8) * (1 + inblocks) + 4)] ^= 0x1f;
	state2[2 * ((LC_SPX_N / 8) * (1 + inblocks) + 4) + 1] ^= 0x1f;

	f1600x2(state2);

	for (int i = 0; i < LC_SPX_N / 8; i++) {
		store64(out0 + 8 * i, state2[2 * i]);
		store64(out1 + 8 * i, state2[2 * i + 1]);
	}
}

void thashx2(unsigned char *out0, unsigned char *out1, const unsigned char *in0,
	     const unsigned char *in1, unsigned int inblocks,
	     const spx_ctx *ctx, uint32_t addrx2[2 * 8], uint8_t *thash_buf)
{
#if 0
#if (LC_SPX_FORS_TREES < LC_SPX_WOTS_LEN)
	uint8_t buf0[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t buf1[LC_SPX_N + LC_SPX_ADDR_BYTES + LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t bitmask0[LC_SPX_WOTS_LEN * LC_SPX_N];
	uint8_t bitmask1[LC_SPX_WOTS_LEN * LC_SPX_N];
#endif
#endif
	uint8_t *buf0 = thash_buf;
	uint8_t *buf1 = buf0 + LC_THASHX4_BUFLEN;
	uint8_t *bitmask0 = buf1 + LC_THASHX4_BUFLEN;
	uint8_t *bitmask1 = bitmask0 + LC_THASHX4_BITMASKLEN;
	unsigned int i;

	memcpy(buf0, ctx->pub_seed, LC_SPX_N);
	memcpy(buf1, ctx->pub_seed, LC_SPX_N);
	memcpy(buf0 + LC_SPX_N, addrx2 + 0 * 8, LC_SPX_ADDR_BYTES);
	memcpy(buf1 + LC_SPX_N, addrx2 + 1 * 8, LC_SPX_ADDR_BYTES);

	shake256x2_armv8(bitmask0, bitmask1, inblocks * LC_SPX_N, buf0, buf1,
			 LC_SPX_N + LC_SPX_ADDR_BYTES);

	for (i = 0; i < inblocks * LC_SPX_N; i++) {
		buf0[LC_SPX_N + LC_SPX_ADDR_BYTES + i] = in0[i] ^ bitmask0[i];
		buf1[LC_SPX_N + LC_SPX_ADDR_BYTES + i] = in1[i] ^ bitmask1[i];
	}

	shake256x2_armv8(out0, out1, LC_SPX_N, buf0, buf1,
			 LC_SPX_N + LC_SPX_ADDR_BYTES + inblocks * LC_SPX_N);
}
