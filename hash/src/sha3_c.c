/*
 * Copyright (C) 2021 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "build_bug_on.h"
#include "bitshift.h"
#include "conv_be_le.h"
#include "ext_headers.h"
#include "lc_sha3.h"
#include "lc_memset_secure.h"
#include "math_helper.h"
#include "sha3_c.h"
#include "sha3_common.h"
#include "sha3_selftest.h"
#include "visibility.h"
#include "xor.h"

static inline uint64_t rol(uint64_t x, int n)
{
	return ((x << (n & (64 - 1))) | (x >> ((64 - n) & (64 - 1))));
}

/*********************************** Keccak ***********************************/
/* state[x + y*5] */
#define A(x, y) (x + 5 * y)
#define RHO_ROL(t) (((t + 1) * (t + 2) / 2) % 64)

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

static inline void sha3_ctx_init(void *_state)
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_224_state *ctx = _state;
	unsigned int i;

	/*
	 * Zeroize the actual state which is required by some implementations
	 * like ARM-CE.
	 */
	for (i = 0; i < LC_SHA3_STATE_WORDS; i++)
		ctx->state[i] = 0;

	ctx->msg_len = 0;
	ctx->squeeze_more = 0;
	ctx->offset = 0;
}

void sha3_224_init_common(void *_state)
{
	struct lc_sha3_224_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHA3_224_SIZE_BLOCK;
	ctx->rword = LC_SHA3_224_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = LC_SHA3_224_SIZE_DIGEST;
	ctx->padding = 0x06;
}

static void sha3_224_init(void *_state)
{
	struct lc_sha3_224_state *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	sha3_224_selftest_common(lc_sha3_224_c, &tested, "SHA3-224 C");
	sha3_224_init_common(_state);
	sha3_state_init(ctx->state);
}

size_t sha3_224_digestsize(void *_state)
{
	(void)_state;
	return LC_SHA3_224_SIZE_DIGEST;
}

void sha3_256_init_common(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHA3_256_SIZE_BLOCK;
	ctx->rword = LC_SHA3_256_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = LC_SHA3_256_SIZE_DIGEST;
	ctx->padding = 0x06;
}

static void sha3_256_init(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	sha3_256_selftest_common(lc_sha3_256_c, &tested, "SHA3-256 C");
	sha3_256_init_common(_state);
	sha3_state_init(ctx->state);
}

size_t sha3_256_digestsize(void *_state)
{
	(void)_state;
	return LC_SHA3_256_SIZE_DIGEST;
}

void sha3_384_init_common(void *_state)
{
	struct lc_sha3_384_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHA3_384_SIZE_BLOCK;
	ctx->rword = LC_SHA3_384_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = LC_SHA3_384_SIZE_DIGEST;
	ctx->padding = 0x06;
}

static void sha3_384_init(void *_state)
{
	struct lc_sha3_384_state *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	sha3_384_selftest_common(lc_sha3_384_c, &tested, "SHA3-384 C");
	sha3_384_init_common(_state);
	sha3_state_init(ctx->state);
}

size_t sha3_384_digestsize(void *_state)
{
	(void)_state;
	return LC_SHA3_384_SIZE_DIGEST;
}

void sha3_512_init_common(void *_state)
{
	struct lc_sha3_512_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHA3_512_SIZE_BLOCK;
	ctx->rword = LC_SHA3_512_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = LC_SHA3_512_SIZE_DIGEST;
	ctx->padding = 0x06;
}

static void sha3_512_init(void *_state)
{
	struct lc_sha3_512_state *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	sha3_512_selftest_common(lc_sha3_512_c, &tested, "SHA3-512 C");
	sha3_512_init_common(_state);
	sha3_state_init(ctx->state);
}

size_t sha3_512_digestsize(void *_state)
{
	(void)_state;
	return LC_SHA3_512_SIZE_DIGEST;
}

void shake_128_init_common(void *_state)
{
	struct lc_shake_128_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHAKE_128_SIZE_BLOCK;
	ctx->rword = LC_SHAKE_128_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = 0;
	ctx->padding = 0x1f;
}

static void shake_128_init(void *_state)
{
	struct lc_shake_128_state *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	shake128_selftest_common(lc_shake128_c, &tested, "SHAKE128 C");
	shake_128_init_common(_state);
	sha3_state_init(ctx->state);
}

void shake_256_init_common(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHA3_256_SIZE_BLOCK;
	ctx->rword = LC_SHA3_256_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = 0;
	ctx->padding = 0x1f;
}

static void shake_256_init(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	shake256_selftest_common(lc_shake256_c, &tested, "SHAKE256 C");
	shake_256_init_common(_state);
	sha3_state_init(ctx->state);
}

void cshake_256_init_common(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHA3_256_SIZE_BLOCK;
	ctx->rword = LC_SHA3_256_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = 0;
	ctx->padding = 0x04;
}

static void cshake_256_init(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	cshake256_selftest_common(lc_cshake256_c, &tested, "cSHAKE256 C");
	cshake_256_init_common(_state);
	sha3_state_init(ctx->state);
}

void cshake_128_init_common(void *_state)
{
	struct lc_shake_128_state *ctx = _state;

	if (!ctx)
		return;

	sha3_ctx_init(_state);
	ctx->r = LC_SHAKE_128_SIZE_BLOCK;
	ctx->rword = LC_SHAKE_128_SIZE_BLOCK / sizeof(uint64_t);
	ctx->digestsize = 0;
	ctx->padding = 0x04;
}

static void cshake_128_init(void *_state)
{
	struct lc_shake_128_state *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	cshake128_selftest_common(lc_cshake128_c, &tested, "cSHAKE128 C");
	cshake_128_init_common(_state);
	sha3_state_init(ctx->state);
}

/*
 * All lc_sha3_*_state are equal except for the last entry, thus we use
 * the largest state.
 */
static inline void sha3_fill_state(struct lc_sha3_224_state *ctx,
				   const uint8_t *in)
{
	unsigned int i;

	for (i = 0; i < ctx->rword; i++) {
		ctx->state[i] ^= ptr_to_le64(in);
		in += 8;
	}
}

static inline int sha3_aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

static inline void sha3_fill_state_aligned(struct lc_sha3_224_state *ctx,
					   const uint64_t *in)
{
	unsigned int i;

	for (i = 0; i < ctx->rword; i++) {
		ctx->state[i] ^= le_bswap64(*in);
		in++;
	}
}

#if defined(LC_BIG_ENDIAN) || defined(__BIG_ENDIAN)

/*
 * This function works on both endianesses, but since it has more code than
 * the little endian code base, there is a special case for little endian.
 */
static inline void sha3_fill_state_bytes(uint64_t state[LC_SHA3_STATE_WORDS],
					 const uint8_t *in, size_t byte_offset,
					 size_t inlen)
{
	unsigned int i;
	union {
		uint64_t dw;
		uint8_t b[sizeof(uint64_t)];
	} tmp;

	state += byte_offset / sizeof(state[0]);

	i = byte_offset & (sizeof(tmp) - 1);

	tmp.dw = 0;

	/*
	 * This loop simply XORs the data in *in with the state starting from
	 * byte_offset. The complication is that the simple XOR of the *in bytes
	 * with the respective bytes in the state only works on little endian
	 * systems. For big endian systems, we must apply a byte swap! This
	 * loop therefore concatenates the *in bytes in chunks of uint64_t
	 * and then XORs the byte swapped value into the state.
	 */
	while (inlen) {
		uint8_t ctr;

		for (ctr = 0; i < sizeof(tmp) && (size_t)ctr < inlen;
		     i++, in++, ctr++)
			tmp.b[i] = *in;

		*state ^= le_bswap64(tmp.dw);
		state++;
		inlen -= ctr;
		i = 0;

		/* This line also implies zeroization of the data */
		tmp.dw = 0;
	}
}

#elif defined(LC_LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN)

static inline void sha3_fill_state_bytes(uint64_t state[LC_SHA3_STATE_WORDS],
					 const uint8_t *in, size_t byte_offset,
					 size_t inlen)
{
	uint8_t *_state = (uint8_t *)state;

	xor_64(_state + byte_offset, in, inlen);
}

#else
#error "Endianess not defined"
#endif

static void keccak_absorb(void *_state, const uint8_t *in, size_t inlen)
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_224_state *ctx = _state;
	size_t partial;

	if (!ctx)
		return;

	partial = ctx->msg_len % ctx->r;
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
			sha3_fill_state_bytes(ctx->state, in, partial, inlen);
			return;
		}

		/*
		 * The input data is large enough to fill the entire partial
		 * block buffer. Thus, we fill it and transform it.
		 */
		sha3_fill_state_bytes(ctx->state, in, partial, todo);
		inlen -= todo;
		in += todo;

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
	sha3_fill_state_bytes(ctx->state, in, 0, inlen);
}

static void keccak_squeeze(void *_state, uint8_t *digest)
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_224_state *ctx = _state;
	size_t i, digest_len;
	uint32_t part;
	volatile uint32_t *part_p;

	if (!ctx || !digest)
		return;

	digest_len = ctx->digestsize;

	if (!ctx->squeeze_more) {
		size_t partial = ctx->msg_len % ctx->r;
		static const uint8_t terminator = 0x80;

		/* Final round in sponge absorbing phase */

		/* Add the padding bits and the 01 bits for the suffix. */
		sha3_fill_state_bytes(ctx->state, &ctx->padding, partial, 1);

		if ((ctx->padding >= 0x80) && (partial == (size_t)(ctx->r - 1)))
			keccakp_1600(ctx->state);
		sha3_fill_state_bytes(ctx->state, &terminator, ctx->r - 1, 1);

		ctx->squeeze_more = 1;
	}

	while (digest_len) {
		unsigned int j;
		uint8_t todo_64, todo_32;

		/* How much data can we squeeze considering current state? */
		uint8_t todo = ctx->r - ctx->offset;

		/* Limit the data to be squeezed by the requested amount. */
		todo = (uint8_t)((digest_len > todo) ? todo : digest_len);

		digest_len -= todo;

		if (ctx->offset) {
			/*
			 * Access requests when squeezing more data that
			 * happens to be not aligned with the block size of
			 * the used SHAKE algorithm are processed byte-wise.
			 */
			size_t word, byte;

			for (i = ctx->offset; i < todo + ctx->offset;
			     i++, digest++) {
				word = i / sizeof(ctx->state[0]);
				byte = (i % sizeof(ctx->state[0])) << 3;

				*digest = (uint8_t)(ctx->state[word] >> byte);
			}

			/* Advance the offset */
			ctx->offset += todo;
			/* Wrap the offset at block size */
			ctx->offset %= ctx->r;
			continue;
		}

		/*
		 * Access to obtain blocks without offset are implemented
		 * with streamlined memory access.
		 */

		/* Generate new keccak block */
		keccakp_1600(ctx->state);

		/* Advance the offset */
		ctx->offset += todo;
		/* Wrap the offset at block size */
		ctx->offset %= ctx->r;

		/* How much 64-bit aligned data can we obtain? */
		todo_64 = todo >> 3;

		/* How much 32-bit aligned data can we obtain? */
		todo_32 = (uint8_t)((todo - (todo_64 << 3)) >> 2);

		/* How much non-aligned do we have to obtain? */
		todo -= (uint8_t)(((todo_64 << 3) + (todo_32 << 2)));

		/* Sponge squeeze phase */

		/* 64-bit aligned request */
		for (i = 0; i < todo_64; i++, digest += 8)
			le64_to_ptr(digest, ctx->state[i]);

		if (todo_32) {
			/* 32-bit aligned request */
			le32_to_ptr(digest, (uint32_t)(ctx->state[i]));
			digest += 4;
			part = (uint32_t)(ctx->state[i] >> 32);
		} else {
			/* non-aligned request */
			part = (uint32_t)(ctx->state[i]);
		}

		for (j = 0; j < (unsigned int)(todo << 3); j += 8, digest++)
			*digest = (uint8_t)(part >> j);
	}

	/* Zeroization */
	part_p = &part;
	*part_p = 0;
}

static void keccak_c_permutation(void *state)
{
	keccakp_1600((uint64_t *)state);
}

static void keccak_c_add_bytes(void *state, const uint8_t *data,
			       unsigned int offset, unsigned int length)
{
	sha3_fill_state_bytes((uint64_t *)state, data, offset, length);
}

static void keccak_c_extract_bytes(const void *state, uint8_t *data,
				   size_t offset, size_t length)
{
	size_t i;
	const uint64_t *s = state;

	if (offset) {
		/*
		 * Access requests when squeezing more data that happens to be
		 * not aligned with the block size of the used SHAKE algorithm
		 * are processed byte-wise.
		 */
		size_t word, byte;

		for (i = offset; i < length + offset; i++, data++) {
			word = i / sizeof(*s);
			byte = (i % sizeof(*s)) << 3;

			*data = (uint8_t)(s[word] >> byte);
		}
	} else {
		union {
			uint64_t dw;
			uint32_t w[2];
		} val;
		uint32_t part;
		unsigned int j;
		uint8_t todo_64, todo_32, todo;

		/* How much 64-bit aligned data can we obtain? */
		todo_64 = (uint8_t)(length >> 3);

		/* How much 32-bit aligned data can we obtain? */
		todo_32 = (uint8_t)((length - (uint8_t)(todo_64 << 3)) >> 2);

		/* How much non-aligned do we have to obtain? */
		todo = (uint8_t)(length -
				 (uint8_t)((todo_64 << 3) + (todo_32 << 2)));

		/* Sponge squeeze phase */

		/* 64-bit aligned request */
		for (i = 0; i < todo_64; i++, data += 8)
			le64_to_ptr(data, s[i]);

		if (i < LC_SHA3_STATE_WORDS)
			val.dw = le_bswap64(s[i]);
		else
			val.dw = 0;

		if (todo_32) {
			/* 32-bit aligned request */
			le32_to_ptr(data, val.w[0]);
			data += 4;
			part = le_bswap32(val.w[1]);
		} else {
			/* non-aligned request */
			part = le_bswap32(val.w[0]);
		}

		for (j = 0; j < (unsigned int)(todo << 3); j += 8, data++)
			*data = (uint8_t)(part >> j);
	}
}

static void keccak_c_newstate(void *state, const uint8_t *data, size_t offset,
			      size_t length)
{
	uint64_t *s = state;
	unsigned int i;
	union {
		uint64_t dw;
		uint8_t b[sizeof(uint64_t)];
	} tmp;

	s += offset / sizeof(s[0]);

	i = offset & (sizeof(tmp) - 1);

	/*
	 * This loop simply copy the data in *data with the state starting from
	 * byte_offset. The complication is that the simple copy of the *data
	 * bytes with the respective bytes in the state only works on little
	 * endian systems. For big endian systems, we must apply a byte swap!
	 * This loop therefore concatenates the *data bytes in chunks of
	 * uint64_t and then copies the byte swapped value into the state.
	 */
	while (length) {
		uint8_t ctr;

		/* Copy the current state data into tmp */
		tmp.dw = *s;

		/* Overwrite the existing tmp data with new data */
		for (ctr = 0; i < sizeof(tmp) && (size_t)ctr < length;
		     i++, data++, ctr++)
			tmp.b[i] = *data;

		*s = le_bswap64(tmp.dw);
		s++;
		length -= ctr;
		i = 0;

		/* This line also implies zeroization of the data */
		tmp.dw = 0;
	}
}

void shake_set_digestsize(void *_state, size_t digestsize)
{
	struct lc_sha3_256_state *ctx = _state;

	ctx->digestsize = digestsize;
}

size_t shake_get_digestsize(void *_state)
{
	struct lc_sha3_256_state *ctx = _state;

	return ctx->digestsize;
}

static const struct lc_hash _sha3_224_c = {
	.init = sha3_224_init,
	.update = keccak_absorb,
	.final = keccak_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_224_digestsize,
	.keccak_permutation = keccak_c_permutation,
	.keccak_add_bytes = keccak_c_add_bytes,
	.keccak_extract_bytes = keccak_c_extract_bytes,
	.keccak_newstate = keccak_c_newstate,
	.rate = LC_SHA3_224_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_224_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_224_c) = &_sha3_224_c;

static const struct lc_hash _sha3_256_c = {
	.init = sha3_256_init,
	.update = keccak_absorb,
	.final = keccak_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_256_digestsize,
	.keccak_permutation = keccak_c_permutation,
	.keccak_add_bytes = keccak_c_add_bytes,
	.keccak_extract_bytes = keccak_c_extract_bytes,
	.keccak_newstate = keccak_c_newstate,
	.rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_256_c) = &_sha3_256_c;

static const struct lc_hash _sha3_384_c = {
	.init = sha3_384_init,
	.update = keccak_absorb,
	.final = keccak_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_384_digestsize,
	.keccak_permutation = keccak_c_permutation,
	.keccak_add_bytes = keccak_c_add_bytes,
	.keccak_extract_bytes = keccak_c_extract_bytes,
	.keccak_newstate = keccak_c_newstate,
	.rate = LC_SHA3_384_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_384_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_384_c) = &_sha3_384_c;

static const struct lc_hash _sha3_512_c = {
	.init = sha3_512_init,
	.update = keccak_absorb,
	.final = keccak_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = sha3_512_digestsize,
	.keccak_permutation = keccak_c_permutation,
	.keccak_add_bytes = keccak_c_add_bytes,
	.keccak_extract_bytes = keccak_c_extract_bytes,
	.keccak_newstate = keccak_c_newstate,
	.rate = LC_SHA3_512_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_512_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_512_c) = &_sha3_512_c;

static const struct lc_hash _shake128_c = {
	.init = shake_128_init,
	.update = keccak_absorb,
	.final = keccak_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.keccak_permutation = keccak_c_permutation,
	.keccak_add_bytes = keccak_c_add_bytes,
	.keccak_extract_bytes = keccak_c_extract_bytes,
	.keccak_newstate = keccak_c_newstate,
	.rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_shake128_c) = &_shake128_c;

static const struct lc_hash _shake256_c = {
	.init = shake_256_init,
	.update = keccak_absorb,
	.final = keccak_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.keccak_permutation = keccak_c_permutation,
	.keccak_add_bytes = keccak_c_add_bytes,
	.keccak_extract_bytes = keccak_c_extract_bytes,
	.keccak_newstate = keccak_c_newstate,
	.rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_shake256_c) = &_shake256_c;

static const struct lc_hash _cshake256_c = {
	.init = cshake_256_init,
	.update = keccak_absorb,
	.final = keccak_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.keccak_permutation = keccak_c_permutation,
	.keccak_add_bytes = keccak_c_add_bytes,
	.keccak_extract_bytes = keccak_c_extract_bytes,
	.keccak_newstate = keccak_c_newstate,
	.rate = LC_SHA3_256_SIZE_BLOCK,
	.statesize = sizeof(struct lc_sha3_256_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_cshake256_c) = &_cshake256_c;

static const struct lc_hash _cshake128_c = {
	.init = cshake_128_init,
	.update = keccak_absorb,
	.final = keccak_squeeze,
	.set_digestsize = shake_set_digestsize,
	.get_digestsize = shake_get_digestsize,
	.keccak_permutation = keccak_c_permutation,
	.keccak_add_bytes = keccak_c_add_bytes,
	.keccak_extract_bytes = keccak_c_extract_bytes,
	.rate = LC_SHAKE_128_SIZE_BLOCK,
	.statesize = sizeof(struct lc_shake_128_state),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_cshake128_c) = &_cshake128_c;

LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_224) = &_sha3_224_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_256) = &_sha3_256_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_384) = &_sha3_384_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_sha3_512) = &_sha3_512_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_shake128) = &_shake128_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_shake256) = &_shake256_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_cshake128) = &_cshake128_c;
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_cshake256) = &_cshake256_c;
