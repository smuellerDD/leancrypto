/* Generic SHA-512 implementation
 *
 * Copyright (C) 2020, Stephan Mueller <smueller@chronox.de>
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

#include "bitshift_be.h"
#include "lc_sha512.h"
#include "memset_secure.h"
#include "visibility.h"

struct lc_hash_state {
	uint64_t H[8];
	size_t msg_len;
	uint8_t partial[LC_SHA512_SIZE_BLOCK];
};

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

static void sha512_init(struct lc_hash_state *ctx)
{
	ctx->H[0] = 0x6a09e667f3bcc908ULL;
	ctx->H[1] = 0xbb67ae8584caa73bULL;
	ctx->H[2] = 0x3c6ef372fe94f82bULL;
	ctx->H[3] = 0xa54ff53a5f1d36f1ULL;
	ctx->H[4] = 0x510e527fade682d1ULL;
	ctx->H[5] = 0x9b05688c2b3e6c1fULL;
	ctx->H[6] = 0x1f83d9abfb41bd6bULL;
	ctx->H[7] = 0x5be0cd19137e2179ULL;

	ctx->msg_len = 0;
}

static inline uint64_t ror(uint64_t x, int n)
{
	return ( (x >> (n&(64-1))) | (x << ((64-n)&(64-1))) );
}

#define CH(x, y, z)	((x & y) ^ (~x & z))
#define MAJ(x, y, z)	((x & y) ^ (x & z) ^ (y & z))
#define S0(x)		(ror(x, 28) ^ ror(x, 34) ^ ror(x, 39))
#define S1(x)		(ror(x, 14) ^ ror(x, 18) ^ ror(x, 41))
#define s0(x)		(ror(x, 1) ^ ror(x, 8) ^ (x >> 7))
#define s1(x)		(ror(x, 19) ^ ror(x, 61) ^ (x >> 6))

static inline void sha512_transform(struct lc_hash_state *ctx, const uint8_t *in)
{
	uint64_t W[80], a, b, c, d, e, f, g, h, T1, T2;
	unsigned int i;

	a = ctx->H[0]; b = ctx->H[1]; c = ctx->H[2]; d = ctx->H[3];
	e = ctx->H[4]; f = ctx->H[5]; g = ctx->H[6]; h = ctx->H[7];

	for (i = 0; i < 80; i++) {
		if (i < 16) {
			W[i] = ptr_to_be64(in);
			in += 8;
		} else {
			W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];

			/* Zeroization */
			W[i - 16] = 0;
		}
		T1 = h + S1(e) + CH(e, f, g) + sha512_K[i] + W[i];
		T2 = S0(a) + MAJ(a, b, c);
		h = g; g = f; f = e; e = d + T1;
		d = c; c = b; b = a; a = T1 + T2;
	}

	ctx->H[0] += a; ctx->H[1] += b; ctx->H[2] += c; ctx->H[3] += d;
	ctx->H[4] += e; ctx->H[5] += f; ctx->H[6] += g; ctx->H[7] += h;

	/* Zeroize intermediate values - register are not zeroized */
	for (i = 64; i < 80; i++)
		W[i] = 0;
}

static void sha512_update(struct lc_hash_state *ctx, const uint8_t *in, size_t inlen)
{
	unsigned int partial = ctx->msg_len % LC_SHA512_SIZE_BLOCK;

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

		sha512_transform(ctx, ctx->partial);
	}

	/* Perform a transformation of full block-size messages */
	for (; inlen >= LC_SHA512_SIZE_BLOCK;
	     inlen -= LC_SHA512_SIZE_BLOCK, in += LC_SHA512_SIZE_BLOCK)
		sha512_transform(ctx, in);

	/* If we have data left, copy it into the partial block buffer */
	memcpy(ctx->partial, in, inlen);
}

static void sha512_final(struct lc_hash_state *ctx, uint8_t *digest)
{
	unsigned int i, partial = ctx->msg_len % LC_SHA512_SIZE_BLOCK;

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
		sha512_transform(ctx, ctx->partial);
	}

	/* Fill the unused part of the partial buffer with zeros */
	memset(ctx->partial + partial, 0, LC_SHA512_SIZE_BLOCK - partial);

	/* Add the message length in bits at the end of the partial buffer */
	ctx->msg_len <<= 3;
	be64_to_ptr(ctx->partial + (LC_SHA512_SIZE_BLOCK - 8), ctx->msg_len);

	/* Final transformation */
	sha512_transform(ctx, ctx->partial);

	memset_secure(ctx->partial, 0, LC_SHA512_SIZE_BLOCK);

	/* Output digest */
	for (i = 0; i < 8; i++, digest += 8) {
		be64_to_ptr(digest, ctx->H[i]);

		/* Zeroization */
		ctx->H[i] = 0;
	}
}

static size_t sha512_get_digestsize(struct lc_hash_state *ctx)
{
	(void)ctx;
	return LC_SHA512_SIZE_DIGEST;
}

static const struct lc_hash _sha512 = {
	.init		= sha512_init,
	.update		= sha512_update,
	.final		= sha512_final,
	.set_digestsize	= NULL,
	.get_digestsize = sha512_get_digestsize,
	.blocksize	= LC_SHA512_SIZE_BLOCK,
	.statesize	= sizeof(struct lc_hash_state),
};

DSO_PUBLIC const struct lc_hash *lc_sha512 = &_sha512;
