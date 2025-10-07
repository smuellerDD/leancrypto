/* Generic SHA-256 implementation
 *
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "bitshift_be.h"
#include "compare.h"
#include "ext_headers_internal.h"
#include "fips_mode.h"
#include "hash_common.h"
#include "lc_sha256.h"
#include "lc_memset_secure.h"
#include "lc_status.h"
#include "sha2_common.h"
#include "sha256_c.h"
#include "visibility.h"

LC_FIPS_RODATA_SECTION
static const uint32_t sha256_K[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_selftest(const struct lc_hash *sha256)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t msg_256[] = { FIPS140_MOD(0x06), 0x3A, 0x53 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_256[] = { 0x8b, 0x05, 0x65, 0x59, 0x60, 0x71,
					   0xc7, 0x6e, 0x35, 0xe1, 0xea, 0x54,
					   0x48, 0x39, 0xe6, 0x47, 0x27, 0xdf,
					   0x89, 0xb4, 0xde, 0x27, 0x74, 0x44,
					   0xa7, 0x7f, 0x77, 0xcb, 0x97, 0x89,
					   0x6f, 0xf4 };
	uint8_t act[LC_SHA256_SIZE_DIGEST];

	LC_SELFTEST_RUN(lc_sha256_c->algorithm_type);

	lc_hash_nocheck(sha256, msg_256, sizeof(msg_256), act);
	lc_compare_selftest(lc_sha256_c->algorithm_type, act, exp_256,
			    LC_SHA256_SIZE_DIGEST, "SHA-256");
}

int sha256_init_nocheck(void *_state)
{
	struct lc_sha256_state *ctx = _state;

	if (!ctx)
		return -EINVAL;

	ctx->H[0] = 0x6a09e667;
	ctx->H[1] = 0xbb67ae85;
	ctx->H[2] = 0x3c6ef372;
	ctx->H[3] = 0xa54ff53a;
	ctx->H[4] = 0x510e527f;
	ctx->H[5] = 0x9b05688c;
	ctx->H[6] = 0x1f83d9ab;
	ctx->H[7] = 0x5be0cd19;

	ctx->msg_len = 0;

	return 0;
}

int sha256_init(void *_state)
{
	sha256_selftest(lc_sha256);
	LC_SELFTEST_COMPLETED(lc_sha256_c->algorithm_type);

	return sha256_init_nocheck(_state);
}

static inline uint32_t ror(uint32_t x, int n)
{
	return ((x >> (n & (32 - 1))) | (x << ((32 - n) & (32 - 1))));
}

#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (ror(x, 2) ^ ror(x, 13) ^ ror(x, 22))
#define S1(x) (ror(x, 6) ^ ror(x, 11) ^ ror(x, 25))
#define s0(x) (ror(x, 7) ^ ror(x, 18) ^ (x >> 3))
#define s1(x) (ror(x, 17) ^ ror(x, 19) ^ (x >> 10))

static inline void sha256_transform(struct lc_sha256_state *ctx,
				    const uint8_t *in)
{
	uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
	unsigned int i;

	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];
	f = ctx->H[5];
	g = ctx->H[6];
	h = ctx->H[7];

	for (i = 0; i < 64; i++) {
		if (i < 16) {
			W[i] = ptr_to_be32(in);
			in += 4;
		} else {
			W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) +
			       W[i - 16];

			/* Zeroization */
			W[i - 16] = 0;
		}
		T1 = h + S1(e) + CH(e, f, g) + sha256_K[i] + W[i];
		T2 = S0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + T1;
		d = c;
		c = b;
		b = a;
		a = T1 + T2;
	}

	ctx->H[0] += a;
	ctx->H[1] += b;
	ctx->H[2] += c;
	ctx->H[3] += d;
	ctx->H[4] += e;
	ctx->H[5] += f;
	ctx->H[6] += g;
	ctx->H[7] += h;

	/* Zeroize intermediate values - register are not zeroized */
	for (i = 48; i < 64; i++)
		W[i] = 0;
}

static inline void sha256_transform_block_c(struct lc_sha256_state *ctx,
					    const uint8_t *in, size_t blocks)
{
	size_t i;

	for (i = 0; i < blocks; i++, in += LC_SHA256_SIZE_BLOCK)
		sha256_transform(ctx, in);
}

void sha256_update(struct lc_sha256_state *ctx, const uint8_t *in, size_t inlen,
		   void (*sha256_transform_block)(struct lc_sha256_state *ctx,
						  const uint8_t *in,
						  size_t blocks))
{
	size_t blocks;
	unsigned int partial;

	if (!ctx)
		return;

	partial = ctx->msg_len % LC_SHA256_SIZE_BLOCK;
	ctx->msg_len += inlen;

	/* Check if we have a partial block stored */
	if (partial) {
		unsigned int todo = LC_SHA256_SIZE_BLOCK - partial;

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

		sha256_transform_block(ctx, ctx->partial, 1);
	}

	/* Perform a transformation of full block-size messages */
	blocks = inlen / LC_SHA256_SIZE_BLOCK;
	if (blocks) {
		sha256_transform_block(ctx, in, blocks);

		/* Update length / data pointer for consumed data */
		blocks *= LC_SHA256_SIZE_BLOCK;
		inlen -= blocks;
		in += blocks;
	}

	/* If we have data left, copy it into the partial block buffer */
	memcpy(ctx->partial, in, inlen);
}

static void sha256_update_c(void *_state, const uint8_t *in, size_t inlen)
{
	struct lc_sha256_state *ctx = _state;

	sha256_update(ctx, in, inlen, sha256_transform_block_c);
}

void sha256_final(struct lc_sha256_state *ctx, uint8_t *digest,
		  void (*sha256_transform_block)(struct lc_sha256_state *ctx,
						 const uint8_t *in,
						 size_t blocks))
{
	unsigned int i, partial;

	if (!ctx || !digest)
		return;

	partial = ctx->msg_len % LC_SHA256_SIZE_BLOCK;

	/*
	 * We know a-priori that we have at least one byte free in the partial
	 * buffer.
	 */
	ctx->partial[partial] = 0x80;
	partial++;

	/*
	 * If our partial buffer is filled too much now and we have no way to
	 * store the final 16 bytes that is supposed to hold the message length
	 * in bits, transform it.
	 */
	if (partial > (LC_SHA256_SIZE_BLOCK - (2 * sizeof(uint32_t)))) {
		memset(ctx->partial + partial, 0,
		       LC_SHA256_SIZE_BLOCK - partial);
		partial = 0;
		sha256_transform_block(ctx, ctx->partial, 1);
	}

	/* Fill the unused part of the partial buffer with zeros */
	memset(ctx->partial + partial, 0, LC_SHA256_SIZE_BLOCK - partial);

	/* Add the message length in bits at the end of the partial buffer */
	ctx->msg_len <<= 3;
	be64_to_ptr(ctx->partial + (LC_SHA256_SIZE_BLOCK - 8), ctx->msg_len);

	/* Final transformation */
	sha256_transform_block(ctx, ctx->partial, 1);

	lc_memset_secure(ctx->partial, 0, LC_SHA256_SIZE_BLOCK);

	/* Output digest */
	for (i = 0; i < 8; i++, digest += 4) {
		be32_to_ptr(digest, ctx->H[i]);

		/* Zeroization */
		ctx->H[i] = 0;
	}
}

static void sha256_final_c(void *_state, uint8_t *digest)
{
	struct lc_sha256_state *ctx = _state;

	sha256_final(ctx, digest, sha256_transform_block_c);
}

size_t sha256_get_digestsize(void *_state)
{
	(void)_state;
	return LC_SHA256_SIZE_DIGEST;
}

static const struct lc_hash _sha256_c = {
	.init = sha256_init,
	.init_nocheck = sha256_init_nocheck,
	.update = sha256_update_c,
	.final = sha256_final_c,
	.set_digestsize = NULL,
	.get_digestsize = sha256_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = NULL,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha256_state),
	.algorithm_type = LC_ALG_STATUS_SHA256
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha256_c) = &_sha256_c;

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha256) = &_sha256_c;
