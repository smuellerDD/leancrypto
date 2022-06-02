/*
 * Copyright (C) 2021, Stephan Mueller <smueller@chronox.de>
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

#include <string.h>

#include "build_bug_on.h"
#include "bitshift_le.h"
#include "lc_sha3.h"
#include "memset_secure.h"
#include "visibility.h"

#define SHA3_STATE_WORDS	25
#define SHA3_STATE_SIZE		(SHA3_STATE_WORDS * sizeof(uint64_t))
struct lc_hash_state {
	uint8_t partial[LC_SHA3_MAX_SIZE_BLOCK];
	uint64_t state[SHA3_STATE_WORDS];
	size_t msg_len;
	size_t digestsize;
	unsigned int r;
	unsigned int rword;
	uint8_t padding;
	uint8_t squeeze_more:1;
};

static inline uint64_t rol(uint64_t x, int n)
{
	return ( (x << (n&(64-1))) | (x >> ((64-n)&(64-1))) );
}

/*********************************** Keccak ***********************************/
/* state[x + y*5] */
#define A(x, y) 	(x + 5 * y)
#define RHO_ROL(t)	(((t + 1) * (t + 2) / 2) % 64)

static inline void keccakp_theta_rho_pi(uint64_t s[25])
{
	uint64_t C[5], D[5], t;

	/* Steps 1 + 2 */
	C[0] = s[A(0, 0)] ^ s[A(0, 1)] ^ s[A(0, 2)] ^ s[A(0, 3)] ^ s[A(0, 4)];
	C[1] = s[A(1, 0)] ^ s[A(1, 1)] ^ s[A(1, 2)] ^ s[A(1, 3)] ^ s[A(1, 4)];
	C[2] = s[A(2, 0)] ^ s[A(2, 1)] ^ s[A(2, 2)] ^ s[A(2, 3)] ^ s[A(2, 4)];
	C[3] = s[A(3, 0)] ^ s[A(3, 1)] ^ s[A(3, 2)] ^ s[A(3, 3)] ^ s[A(3, 4)];
	C[4] = s[A(4, 0)] ^ s[A(4, 1)] ^ s[A(4, 2)] ^ s[A(4, 3)] ^ s[A(4, 4)];

	D[0] = C[4] ^ rol(C[1], 1);
	D[1] = C[0] ^ rol(C[2], 1);
	D[2] = C[1] ^ rol(C[3], 1);
	D[3] = C[2] ^ rol(C[4], 1);
	D[4] = C[3] ^ rol(C[0], 1);

	/* Step 3 theta and rho and pi */
	s[A(0, 0)] ^= D[0];
	t = rol(s[A(4, 4)] ^ D[4], RHO_ROL(11));
	s[A(4, 4)] = rol(s[A(1, 4)] ^ D[1], RHO_ROL(10));
	s[A(1, 4)] = rol(s[A(3, 1)] ^ D[3], RHO_ROL(9));
	s[A(3, 1)] = rol(s[A(1, 3)] ^ D[1], RHO_ROL(8));
	s[A(1, 3)] = rol(s[A(0, 1)] ^ D[0], RHO_ROL(7));
	s[A(0, 1)] = rol(s[A(3, 0)] ^ D[3], RHO_ROL(6));
	s[A(3, 0)] = rol(s[A(3, 3)] ^ D[3], RHO_ROL(5));
	s[A(3, 3)] = rol(s[A(2, 3)] ^ D[2], RHO_ROL(4));
	s[A(2, 3)] = rol(s[A(1, 2)] ^ D[1], RHO_ROL(3));
	s[A(1, 2)] = rol(s[A(2, 1)] ^ D[2], RHO_ROL(2));
	s[A(2, 1)] = rol(s[A(0, 2)] ^ D[0], RHO_ROL(1));
	s[A(0, 2)] = rol(s[A(1, 0)] ^ D[1], RHO_ROL(0));
	s[A(1, 0)] = rol(s[A(1, 1)] ^ D[1], RHO_ROL(23));
	s[A(1, 1)] = rol(s[A(4, 1)] ^ D[4], RHO_ROL(22));
	s[A(4, 1)] = rol(s[A(2, 4)] ^ D[2], RHO_ROL(21));
	s[A(2, 4)] = rol(s[A(4, 2)] ^ D[4], RHO_ROL(20));
	s[A(4, 2)] = rol(s[A(0, 4)] ^ D[0], RHO_ROL(19));
	s[A(0, 4)] = rol(s[A(2, 0)] ^ D[2], RHO_ROL(18));
	s[A(2, 0)] = rol(s[A(2, 2)] ^ D[2], RHO_ROL(17));
	s[A(2, 2)] = rol(s[A(3, 2)] ^ D[3], RHO_ROL(16));
	s[A(3, 2)] = rol(s[A(4, 3)] ^ D[4], RHO_ROL(15));
	s[A(4, 3)] = rol(s[A(3, 4)] ^ D[3], RHO_ROL(14));
	s[A(3, 4)] = rol(s[A(0, 3)] ^ D[0], RHO_ROL(13));
	s[A(0, 3)] = rol(s[A(4, 0)] ^ D[4], RHO_ROL(12));
	s[A(4, 0)] = t;
}

static const uint64_t keccakp_iota_vals[] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static inline void keccakp_chi_iota(uint64_t s[25], unsigned int round)
{
	uint64_t t0[5], t1[5];

	t0[0] = s[A(0, 0)];
	t0[1] = s[A(0, 1)];
	t0[2] = s[A(0, 2)];
	t0[3] = s[A(0, 3)];
	t0[4] = s[A(0, 4)];

	t1[0] = s[A(1, 0)];
	t1[1] = s[A(1, 1)];
	t1[2] = s[A(1, 2)];
	t1[3] = s[A(1, 3)];
	t1[4] = s[A(1, 4)];

	s[A(0, 0)] ^= ~s[A(1, 0)] & s[A(2, 0)];
	s[A(0, 0)] ^= keccakp_iota_vals[round];
	s[A(0, 1)] ^= ~s[A(1, 1)] & s[A(2, 1)];
	s[A(0, 2)] ^= ~s[A(1, 2)] & s[A(2, 2)];
	s[A(0, 3)] ^= ~s[A(1, 3)] & s[A(2, 3)];
	s[A(0, 4)] ^= ~s[A(1, 4)] & s[A(2, 4)];

	s[A(1, 0)] ^= ~s[A(2, 0)] & s[A(3, 0)];
	s[A(1, 1)] ^= ~s[A(2, 1)] & s[A(3, 1)];
	s[A(1, 2)] ^= ~s[A(2, 2)] & s[A(3, 2)];
	s[A(1, 3)] ^= ~s[A(2, 3)] & s[A(3, 3)];
	s[A(1, 4)] ^= ~s[A(2, 4)] & s[A(3, 4)];

	s[A(2, 0)] ^= ~s[A(3, 0)] & s[A(4, 0)];
	s[A(2, 1)] ^= ~s[A(3, 1)] & s[A(4, 1)];
	s[A(2, 2)] ^= ~s[A(3, 2)] & s[A(4, 2)];
	s[A(2, 3)] ^= ~s[A(3, 3)] & s[A(4, 3)];
	s[A(2, 4)] ^= ~s[A(3, 4)] & s[A(4, 4)];

	s[A(3, 0)] ^= ~s[A(4, 0)] & t0[0];
	s[A(3, 1)] ^= ~s[A(4, 1)] & t0[1];
	s[A(3, 2)] ^= ~s[A(4, 2)] & t0[2];
	s[A(3, 3)] ^= ~s[A(4, 3)] & t0[3];
	s[A(3, 4)] ^= ~s[A(4, 4)] & t0[4];

	s[A(4, 0)] ^= ~t0[0] & t1[0];
	s[A(4, 1)] ^= ~t0[1] & t1[1];
	s[A(4, 2)] ^= ~t0[2] & t1[2];
	s[A(4, 3)] ^= ~t0[3] & t1[3];
	s[A(4, 4)] ^= ~t0[4] & t1[4];
}

static inline void keccakp_1600(uint64_t s[25])
{
	unsigned int round;

	for (round = 0; round < 24; round++) {
		keccakp_theta_rho_pi(s);
		keccakp_chi_iota(s, round);
	}
}

/*********************************** SHA-3 ************************************/

static inline void sha3_init(struct lc_hash_state *ctx)
{
	unsigned int i;

	for (i = 0; i < 25; i++)
		ctx->state[i] = 0;
	ctx->msg_len = 0;
	ctx->squeeze_more = 0;
}

static void sha3_224_init(struct lc_hash_state *ctx)
{
	sha3_init(ctx);
	ctx->r = LC_SHA3_224_SIZE_BLOCK;
	ctx->rword = LC_SHA3_224_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = LC_SHA3_224_SIZE_DIGEST;
	ctx->padding = 0x06;
}

static size_t sha3_224_digestsize(struct lc_hash_state *ctx)
{
	(void)ctx;
	return LC_SHA3_224_SIZE_DIGEST;
}

static void sha3_256_init(struct lc_hash_state *ctx)
{
	sha3_init(ctx);
	ctx->r = LC_SHA3_256_SIZE_BLOCK;
	ctx->rword = LC_SHA3_256_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = LC_SHA3_256_SIZE_DIGEST;
	ctx->padding = 0x06;
}

static size_t sha3_256_digestsize(struct lc_hash_state *ctx)
{
	(void)ctx;
	return LC_SHA3_256_SIZE_DIGEST;
}

static void sha3_384_init(struct lc_hash_state *ctx)
{
	sha3_init(ctx);
	ctx->r = LC_SHA3_384_SIZE_BLOCK;
	ctx->rword = LC_SHA3_384_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = LC_SHA3_384_SIZE_DIGEST;
	ctx->padding = 0x06;
}

static size_t sha3_384_digestsize(struct lc_hash_state *ctx)
{
	(void)ctx;
	return LC_SHA3_384_SIZE_DIGEST;
}

static void sha3_512_init(struct lc_hash_state *ctx)
{
	sha3_init(ctx);
	ctx->r = LC_SHA3_512_SIZE_BLOCK;
	ctx->rword = LC_SHA3_512_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = LC_SHA3_512_SIZE_DIGEST;
	ctx->padding = 0x06;
}

static size_t sha3_512_digestsize(struct lc_hash_state *ctx)
{
	(void)ctx;
	return LC_SHA3_512_SIZE_DIGEST;
}

static void shake_256_init(struct lc_hash_state *ctx)
{
	sha3_init(ctx);
	ctx->r = LC_SHA3_256_SIZE_BLOCK;
	ctx->rword = LC_SHA3_256_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = 0;
	ctx->padding = 0x1f;
}

static void cshake_256_init(struct lc_hash_state *ctx)
{
	sha3_init(ctx);
	ctx->r = LC_SHA3_256_SIZE_BLOCK;
	ctx->rword = LC_SHA3_256_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = 0;
	ctx->padding = 0x04;
}

static inline void sha3_fill_state(struct lc_hash_state *ctx, const uint8_t *in)
{
	unsigned int i;

	for (i = 0; i < ctx->rword; i++) {
		ctx->state[i]  ^= ptr_to_le64(in);
		in += 8;
	}
}

static inline int sha3_aligned(const uint8_t *ptr, uint32_t alignmask)
{
        if ((uintptr_t)ptr & alignmask)
                return 0;
        return 1;
}

static inline void sha3_fill_state_aligned(struct lc_hash_state *ctx,
					   const uint64_t *in)
{
	unsigned int i;

	for (i = 0; i < ctx->rword; i++) {
		ctx->state[i]  ^= *in;
		in++;
	}
}

static void keccak_absorb(struct lc_hash_state *ctx,
			  const uint8_t *in, size_t inlen)
{
	size_t partial = ctx->msg_len % ctx->r;

	ctx->squeeze_more = 0;
	ctx->msg_len += inlen;

	/* Sponge absorbing phase */

	/* Check if we have a partial block stored */
	if (partial) {
		size_t todo = ctx->r - partial;

		/*
		 * If the provided data is small enough to fit in the partial
		 * buffer, copy it and leave it unprocessed.
		 */
		if (inlen < todo) {
			memcpy(ctx->partial + partial, in, inlen);
			return;
		}

		/*
		 * The input data is large enough to fill the entire partial
		 * block buffer. Thus, we fill it and transform it.
		 */
		memcpy(ctx->partial + partial, in, todo);
		inlen -= todo;
		in += todo;

		sha3_fill_state(ctx, ctx->partial);
		keccakp_1600(ctx->state);
	}

	/* Perform a transformation of full block-size messages */
	if (sha3_aligned(in, sizeof(uint64_t) - 1)) {
		for (; inlen >= ctx->r; inlen -= ctx->r, in += ctx->r) {
			/* 
			 * We can ignore the alignment warning as we checked
			 * for proper alignment.
			 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			sha3_fill_state_aligned(ctx, (uint64_t *)in);
#pragma GCC diagnostic pop
			keccakp_1600(ctx->state);
		}
	} else {
		for (; inlen >= ctx->r; inlen -= ctx->r, in += ctx->r) {
			sha3_fill_state(ctx, in);
			keccakp_1600(ctx->state);
		}
	}

	/* If we have data left, copy it into the partial block buffer */
	memcpy(ctx->partial, in, inlen);
}

static void keccak_squeeze(struct lc_hash_state *ctx, uint8_t *digest)
{
	size_t partial = ctx->msg_len % ctx->r;
	size_t i, digest_len = ctx->digestsize;
	uint32_t part;
	volatile uint32_t *part_p;

	if (!ctx->squeeze_more) {
		/* Final round in sponge absorbing phase */

		/* Fill the unused part of the partial buffer with zeros */
		memset(ctx->partial + partial, 0, ctx->r - partial);

		/* Add the padding bits and the 01 bits for the suffix. */
		ctx->partial[partial] = ctx->padding;
		ctx->partial[ctx->r - 1] |= 0x80;

		ctx->squeeze_more = 1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		sha3_fill_state_aligned(ctx, (uint64_t *)ctx->partial);
#pragma GCC diagnostic pop

	}

	while (digest_len) {
		size_t todo = digest_len > ctx->r ? ctx->r : digest_len;
		size_t todo_64 = todo >> 3;
		size_t todo_32 = (todo - (todo_64 << 3)) >> 2;

		digest_len -= todo;
		todo -= ((todo_64 << 3) + (todo_32 << 2));

		keccakp_1600(ctx->state);

		/* Sponge squeeze phase */
		for (i = 0; i < todo_64; i++, digest += 8)
			le64_to_ptr(digest, ctx->state[i]);

		if (todo_32) {
			le32_to_ptr(digest, (uint32_t)(ctx->state[i]));
			digest += 4;
			part = (uint32_t)(ctx->state[i] >> 32);
		} else {
			part = (uint32_t)(ctx->state[i]);
		}

		for (i = 0; i < todo << 3; i += 8, digest++)
			*digest = (uint8_t)(part >> i);
	}

	/* Zeroization */
	part_p = &part;
	*part_p = 0;
}

static void shake_set_digestsize(struct lc_hash_state *ctx, size_t digestsize)
{
	ctx->digestsize = digestsize;
}

static size_t shake_get_digestsize(struct lc_hash_state *ctx)
{
	return ctx->digestsize;
}

static const struct lc_hash _sha3_224 = {
	.init		= sha3_224_init,
	.update		= keccak_absorb,
	.final		= keccak_squeeze,
	.set_digestsize	= NULL,
	.get_digestsize	= sha3_224_digestsize,
	.blocksize	= LC_SHA3_224_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_hash_state),
};
DSO_PUBLIC const struct lc_hash *lc_sha3_224 = &_sha3_224;

static const struct lc_hash _sha3_256 = {
	.init		= sha3_256_init,
	.update		= keccak_absorb,
	.final		= keccak_squeeze,
	.set_digestsize	= NULL,
	.get_digestsize	= sha3_256_digestsize,
	.blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_hash_state),
};
DSO_PUBLIC const struct lc_hash *lc_sha3_256 = &_sha3_256;

static const struct lc_hash _sha3_384 = {
	.init		= sha3_384_init,
	.update		= keccak_absorb,
	.final		= keccak_squeeze,
	.set_digestsize	= NULL,
	.get_digestsize	= sha3_384_digestsize,
	.blocksize	= LC_SHA3_384_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_hash_state),
};
DSO_PUBLIC const struct lc_hash *lc_sha3_384 = &_sha3_384;

static const struct lc_hash _sha3_512 = {
	.init		= sha3_512_init,
	.update		= keccak_absorb,
	.final		= keccak_squeeze,
	.set_digestsize	= NULL,
	.get_digestsize	= sha3_512_digestsize,
	.blocksize	= LC_SHA3_512_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_hash_state),
};
DSO_PUBLIC const struct lc_hash *lc_sha3_512 = &_sha3_512;

static const struct lc_hash _shake256 = {
	.init		= shake_256_init,
	.update		= keccak_absorb,
	.final		= keccak_squeeze,
	.set_digestsize	= shake_set_digestsize,
	.get_digestsize	= shake_get_digestsize,
	.blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_hash_state),
};
DSO_PUBLIC const struct lc_hash *lc_shake256 = &_shake256;

static const struct lc_hash _cshake256 = {
	.init		= cshake_256_init,
	.update		= keccak_absorb,
	.final		= keccak_squeeze,
	.set_digestsize	= shake_set_digestsize,
	.get_digestsize	= shake_get_digestsize,
	.blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_hash_state),
};
DSO_PUBLIC const struct lc_hash *lc_cshake256 = &_cshake256;
