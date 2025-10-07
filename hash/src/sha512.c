/* Generic SHA-512 implementation
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

#include "bitshift.h"
#include "compare.h"
#include "ext_headers_internal.h"
#include "fips_mode.h"
#include "hash_common.h"
#include "lc_sha512.h"
#include "lc_memset_secure.h"
#include "lc_status.h"
#include "sha2_common.h"
#include "sha512_c.h"
#include "sponge_common.h"
#include "visibility.h"

LC_FIPS_RODATA_SECTION
static const uint64_t sha512_K[] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
	0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
	0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
	0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
	0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
	0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
	0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
	0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
	0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
	0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
	0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
	0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
	0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
	0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
	0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
	0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
	0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
	0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
	0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
	0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
	0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

static void sha512_selftest(const struct lc_hash *sha512, const char *impl)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t msg_512[] = { FIPS140_MOD(0x7F), 0xAD, 0x12 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_512[] = {
		0x53, 0x35, 0x98, 0xe5, 0x29, 0x49, 0x18, 0xa0, 0xaf, 0x4b,
		0x3a, 0x62, 0x31, 0xcb, 0xd7, 0x19, 0x21, 0xdb, 0x80, 0xe1,
		0x00, 0xa0, 0x74, 0x95, 0xb4, 0x44, 0xc4, 0x7a, 0xdb, 0xbc,
		0x9a, 0x64, 0x76, 0xbb, 0xc8, 0xdb, 0x8e, 0xe3, 0x0c, 0x87,
		0x2f, 0x11, 0x35, 0xf1, 0x64, 0x65, 0x9c, 0x52, 0xce, 0xc7,
		0x7c, 0xcf, 0xb8, 0xc7, 0xd8, 0x57, 0x63, 0xda, 0xee, 0x07,
		0x9f, 0x60, 0x0c, 0x79
	};
	uint8_t act[LC_SHA512_SIZE_DIGEST];

	LC_SELFTEST_RUN(lc_sha512_c->algorithm_type);

	lc_hash_nocheck(sha512, msg_512, sizeof(msg_512), act);
	lc_compare_selftest(lc_sha512_c->algorithm_type, act, exp_512,
			    LC_SHA512_SIZE_DIGEST, impl);
}

int sha384_init_nocheck(void *_state)
{
	struct lc_sha512_state *ctx = _state;

	if (!ctx)
		return -EINVAL;

	ctx->H[0] = 0xcbbb9d5dc1059ed8ULL;
	ctx->H[1] = 0x629a292a367cd507ULL;
	ctx->H[2] = 0x9159015a3070dd17ULL;
	ctx->H[3] = 0x152fecd8f70e5939ULL;
	ctx->H[4] = 0x67332667ffc00b31ULL;
	ctx->H[5] = 0x8eb44a8768581511ULL;
	ctx->H[6] = 0xdb0c2e0d64f98fa7ULL;
	ctx->H[7] = 0x47b5481dbefa4fa4ULL;

	ctx->msg_len = 0;

	return 0;
}

int sha384_init(void *_state)
{
	sha512_selftest(lc_sha512, "SHA-384");
	LC_SELFTEST_COMPLETED(lc_sha512_c->algorithm_type);

	return sha384_init_nocheck(_state);
}

int sha512_init_nocheck(void *_state)
{
	struct lc_sha512_state *ctx = _state;

	if (!ctx)
		return -EINVAL;

	ctx->H[0] = 0x6a09e667f3bcc908ULL;
	ctx->H[1] = 0xbb67ae8584caa73bULL;
	ctx->H[2] = 0x3c6ef372fe94f82bULL;
	ctx->H[3] = 0xa54ff53a5f1d36f1ULL;
	ctx->H[4] = 0x510e527fade682d1ULL;
	ctx->H[5] = 0x9b05688c2b3e6c1fULL;
	ctx->H[6] = 0x1f83d9abfb41bd6bULL;
	ctx->H[7] = 0x5be0cd19137e2179ULL;

	ctx->msg_len = 0;

	return 0;
}

int sha512_init(void *_state)
{
	sha512_selftest(lc_sha512, "SHA-512");
	LC_SELFTEST_COMPLETED(lc_sha512_c->algorithm_type);

	return sha512_init_nocheck(_state);
}

static inline uint64_t ror(uint64_t x, int n)
{
	return ((x >> (n & (64 - 1))) | (x << ((64 - n) & (64 - 1))));
}

#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (ror(x, 28) ^ ror(x, 34) ^ ror(x, 39))
#define S1(x) (ror(x, 14) ^ ror(x, 18) ^ ror(x, 41))
#define s0(x) (ror(x, 1) ^ ror(x, 8) ^ (x >> 7))
#define s1(x) (ror(x, 19) ^ ror(x, 61) ^ (x >> 6))

static inline void sha512_transform(struct lc_sha512_state *ctx,
				    const uint8_t *in)
{
	uint64_t W[80], a, b, c, d, e, f, g, h, T1, T2;
	unsigned int i;

	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];
	f = ctx->H[5];
	g = ctx->H[6];
	h = ctx->H[7];

	for (i = 0; i < 80; i++) {
		if (i < 16) {
			W[i] = ptr_to_be64(in);
			in += 8;
		} else {
			W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) +
			       W[i - 16];

			/* Zeroization */
			W[i - 16] = 0;
		}
		T1 = h + S1(e) + CH(e, f, g) + sha512_K[i] + W[i];
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
	for (i = 64; i < 80; i++)
		W[i] = 0;
}

static inline void sha512_transform_block_c(struct lc_sha512_state *ctx,
					    const uint8_t *in, size_t blocks)
{
	size_t i;

	for (i = 0; i < blocks; i++, in += LC_SHA512_SIZE_BLOCK)
		sha512_transform(ctx, in);
}

void sha512_update(struct lc_sha512_state *ctx, const uint8_t *in, size_t inlen,
		   void (*sha512_transform_block)(struct lc_sha512_state *ctx,
						  const uint8_t *in,
						  size_t blocks))
{
	size_t blocks;
	unsigned int partial;

	if (!ctx)
		return;

	partial = ctx->msg_len % LC_SHA512_SIZE_BLOCK;
	ctx->msg_len += inlen;

	/* Check if we have a partial block stored */
	if (partial) {
		unsigned int todo = LC_SHA512_SIZE_BLOCK - partial;

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

		sha512_transform_block(ctx, ctx->partial, 1);
	}

	/* Perform a transformation of full block-size messages */
	blocks = inlen / LC_SHA512_SIZE_BLOCK;
	if (blocks) {
		sha512_transform_block(ctx, in, blocks);

		/* Update length / data pointer for consumed data */
		blocks *= LC_SHA512_SIZE_BLOCK;
		inlen -= blocks;
		in += blocks;
	}

	/* If we have data left, copy it into the partial block buffer */
	memcpy(ctx->partial, in, inlen);
}

static void sha512_update_c(void *_state, const uint8_t *in, size_t inlen)
{
	struct lc_sha512_state *ctx = _state;

	sha512_update(ctx, in, inlen, sha512_transform_block_c);
}

void sha512_final(struct lc_sha512_state *ctx, uint8_t *digest,
		  void (*sha512_transform_block)(struct lc_sha512_state *ctx,
						 const uint8_t *in,
						 size_t blocks))
{
	unsigned int i, partial;

	if (!ctx || !digest)
		return;

	partial = ctx->msg_len % LC_SHA512_SIZE_BLOCK;

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
	if (partial > (LC_SHA512_SIZE_BLOCK - (2 * sizeof(uint64_t)))) {
		memset(ctx->partial + partial, 0,
		       LC_SHA512_SIZE_BLOCK - partial);
		partial = 0;
		sha512_transform_block(ctx, ctx->partial, 1);
	}

	/* Fill the unused part of the partial buffer with zeros */
	memset(ctx->partial + partial, 0, LC_SHA512_SIZE_BLOCK - partial);

	/* Add the message length in bits at the end of the partial buffer */
	ctx->msg_len <<= 3;
	be64_to_ptr(ctx->partial + (LC_SHA512_SIZE_BLOCK - 8), ctx->msg_len);

	/* Final transformation */
	sha512_transform_block(ctx, ctx->partial, 1);

	lc_memset_secure(ctx->partial, 0, LC_SHA512_SIZE_BLOCK);

	/* Output digest */
	for (i = 0; i < 8; i++, digest += 8) {
		be64_to_ptr(digest, ctx->H[i]);

		/* Zeroization */
		ctx->H[i] = 0;
	}
}

static void sha384_final_c(void *_state, uint8_t *digest)
{
	struct lc_sha512_state *ctx = _state;

	sha512_final(ctx, digest, sha512_transform_block_c);
}

static void sha512_final_c(void *_state, uint8_t *digest)
{
	struct lc_sha512_state *ctx = _state;

	sha512_final(ctx, digest, sha512_transform_block_c);
}

void sha512_extract_bytes(const void *state, uint8_t *data, size_t offset,
			  size_t length)
{
	sponge_extract_bytes(state, data, offset, length, LC_SHA512_STATE_WORDS,
			     be_bswap64, be_bswap32, be64_to_ptr, be32_to_ptr);
}

size_t sha384_get_digestsize(void *_state)
{
	(void)_state;
	return LC_SHA384_SIZE_DIGEST;
}

size_t sha512_get_digestsize(void *_state)
{
	(void)_state;
	return LC_SHA512_SIZE_DIGEST;
}

static const struct lc_hash _sha384_c = {
	.init = sha384_init,
	.init_nocheck = sha384_init_nocheck,
	.update = sha512_update_c,
	.final = sha384_final_c,
	.set_digestsize = NULL,
	.get_digestsize = sha384_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = sha512_extract_bytes,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha512_state),
	.algorithm_type = LC_ALG_STATUS_SHA512
};

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha384_c) = &_sha384_c;

static const struct lc_hash _sha512_c = {
	.init = sha512_init,
	.init_nocheck = sha512_init_nocheck,
	.update = sha512_update_c,
	.final = sha512_final_c,
	.set_digestsize = NULL,
	.get_digestsize = sha512_get_digestsize,
	.sponge_permutation = NULL,
	.sponge_add_bytes = NULL,
	.sponge_extract_bytes = sha512_extract_bytes,
	.sponge_newstate = NULL,
	.sponge_rate = LC_SHA512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha512_state),
	.algorithm_type = LC_ALG_STATUS_SHA512
};

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha512_c) = &_sha512_c;

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha384) = &_sha384_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha512) = &_sha512_c;
