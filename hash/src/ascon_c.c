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

#include "ascon_selftest.h"
#include "bitshift.h"
#include "conv_be_le.h"
#include "lc_ascon_hash.h"
#include "rotate.h"
#include "sponge_common.h"
#include "visibility.h"


/***************************** Ascon Permutation ******************************/

#if 0
/* This code may be suitable for bit-slicing code */
static inline void ascon_permutation_ps(uint64_t s[LC_ASCON_HASH_STATE_WORDS],
					uint64_t constant)
{
	uint64_t t[5];

	s[2] ^= constant;

	// clang-format off
	s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1];
	t[0]  = s[0]; t[1]  = s[1]; t[2]  = s[2]; t[3]  = s[3]; t[4]  = s[4];
	t[0] =~ t[0]; t[1] =~ t[1]; t[2] =~ t[2]; t[3] =~ t[3]; t[4] =~ t[4];
	t[0] &= s[1]; t[1] &= s[2]; t[2] &= s[3]; t[3] &= s[4]; t[4] &= s[0];
	s[0] ^= t[1]; s[1] ^= t[2]; s[2] ^= t[3]; s[3] ^= t[4]; s[4] ^= t[0];
	s[1] ^= s[0]; s[0] ^= s[4]; s[3] ^= s[2]; s[2] =~ s[2];
	// clang-format on
}

static inline void ascon_permutation_pl(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	// clang-format off
	s[0] ^= ror64(s[0], 19) ^ ror64(s[0], 28);
	s[1] ^= ror64(s[1], 61) ^ ror64(s[1], 39);
	s[2] ^= ror64(s[2],  1) ^ ror64(s[2],  6);
	s[3] ^= ror64(s[3], 10) ^ ror64(s[3], 17);
	s[4] ^= ror64(s[4],  7) ^ ror64(s[4], 41);
	// clang-format on
}
static inline void ascon_permutation_ps_pl(
	uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	ascon_permutation_ps(s);
	ascon_permutation_pl(s);
}

#else
static inline void ascon_permutation_one(
	uint64_t s[LC_ASCON_HASH_STATE_WORDS], uint8_t constant)
{
	uint64_t t[5];

	/* addition of constants */
	s[2] ^= constant;

	/* substitution layer */
	s[0] ^= s[4];
	s[4] ^= s[3];
	s[2] ^= s[1];
	t[0] = s[0] ^ (~s[1] & s[2]);
	t[1] = s[1] ^ (~s[2] & s[3]);
	t[2] = s[2] ^ (~s[3] & s[4]);
	t[3] = s[3] ^ (~s[4] & s[0]);
	t[4] = s[4] ^ (~s[0] & s[1]);

	t[1] ^= t[0];
	t[0] ^= t[4];
	t[3] ^= t[2];
	t[2] = ~t[2];

	/* linear diffusion layer */
	s[0] = t[0] ^ ror64(t[0], 19) ^ ror64(t[0], 28);
	s[1] = t[1] ^ ror64(t[1], 61) ^ ror64(t[1], 39);
	s[2] = t[2] ^ ror64(t[2], 1) ^ ror64(t[2], 6);
	s[3] = t[3] ^ ror64(t[3], 10) ^ ror64(t[3], 17);
	s[4] = t[4] ^ ror64(t[4], 7) ^ ror64(t[4], 41);
}
#endif

static inline void ascon_permutation_6(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	ascon_permutation_one(s, 0x96);
	ascon_permutation_one(s, 0x87);
	ascon_permutation_one(s, 0x78);
	ascon_permutation_one(s, 0x69);
	ascon_permutation_one(s, 0x5a);
	ascon_permutation_one(s, 0x4b);
}

static inline void ascon_permutation_8(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	ascon_permutation_one(s, 0xb4);
	ascon_permutation_one(s, 0xa5);
	ascon_permutation_one(s, 0x96);
	ascon_permutation_one(s, 0x87);
	ascon_permutation_one(s, 0x78);
	ascon_permutation_one(s, 0x69);
	ascon_permutation_one(s, 0x5a);
	ascon_permutation_one(s, 0x4b);
}

static inline void ascon_permutation_12(uint64_t s[LC_ASCON_HASH_STATE_WORDS])
{
	ascon_permutation_one(s, 0xf0);
	ascon_permutation_one(s, 0xe1);
	ascon_permutation_one(s, 0xd2);
	ascon_permutation_one(s, 0xc3);
	ascon_permutation_one(s, 0xb4);
	ascon_permutation_one(s, 0xa5);
	ascon_permutation_one(s, 0x96);
	ascon_permutation_one(s, 0x87);
	ascon_permutation_one(s, 0x78);
	ascon_permutation_one(s, 0x69);
	ascon_permutation_one(s, 0x5a);
	ascon_permutation_one(s, 0x4b);
}

static void ascon_c_permutation(void *state, unsigned int rounds)
{
	switch (rounds) {
	case 12:
		ascon_permutation_12((uint64_t *)state);
		break;
	case 8:
		ascon_permutation_8((uint64_t *)state);
		break;
	case 6:
		ascon_permutation_6((uint64_t *)state);
		break;
	default:
		break;
	}
}

/************************ Raw Ascon Sponge Operations *************************/

#if defined(LC_LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN)

/*
 * This function works on both endianesses, but since it has more code than
 * the little endian code base, there is a special case for little endian.
 */
static inline void ascon_fill_state_bytes(uint64_t *state, const uint8_t *in,
					  size_t byte_offset, size_t inlen)
{
	sponge_fill_state_bytes(state, in, byte_offset, inlen, be_bswap64);
}

#elif defined(LC_BIG_ENDIAN) || defined(__BIG_ENDIAN)

static inline void ascon_fill_state_bytes(uint64_t *state, const uint8_t *in,
					  size_t byte_offset, size_t inlen)
{
	uint8_t *_state = (uint8_t *)state;

	xor_64(_state + byte_offset, in, inlen);
}

#else
#error "Endianess not defined"
#endif

static void ascon_c_add_bytes(void *state, const uint8_t *data,
			      unsigned int offset, unsigned int length)
{
	ascon_fill_state_bytes((uint64_t *)state, data, offset, length);
}

static void ascon_c_extract_bytes(const void *state, uint8_t *data,
				  size_t offset, size_t length)
{
	sponge_extract_bytes(state, data, offset, length,
			     LC_ASCON_HASH_STATE_WORDS, be_bswap64, be_bswap32,
			     be64_to_ptr, be32_to_ptr);
}

static void ascon_c_newstate(void *state, const uint8_t *data, size_t offset,
			      size_t length)
{
	sponge_newstate(state, data, offset, length, be_bswap64);
}

/********************************* Ascon Hash *********************************/

static inline void ascon_ctx_init(struct lc_ascon_hash *ctx)
{
	ctx->msg_len = 0;
	ctx->squeeze_more = 0;
	ctx->offset = 0;
}

static void ascon_128_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 12;
	ctx->digestsize = LC_ASCON_HASH_DIGESTSIZE;

	ctx->state[0] = 0xee9398aadb67f03d;
	ctx->state[1] = 0x8bb21831c60f1002;
	ctx->state[2] = 0xb48a92db98d5da62;
	ctx->state[3] = 0x43189921b8f8e3e8;
	ctx->state[4] = 0x348fa5c9d525e140;
}

static void ascon_128_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	ascon_128_selftest_common(lc_ascon_128, &tested, "Ascon 128 C");
	ascon_128_init_common(ctx);
}

static void ascon_128a_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 8;
	ctx->digestsize = LC_ASCON_HASH_DIGESTSIZE;

	ctx->state[0] = 0x01470194fc6528a6;
	ctx->state[1] = 0x738ec38ac0adffa7;
	ctx->state[2] = 0x2ec8e3296c76384c;
	ctx->state[3] = 0xd6f6a54d7f52377d;
	ctx->state[4] = 0xa13c42a223be8d87;
}

static void ascon_128a_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	ascon_128a_selftest_common(lc_ascon_128a, &tested, "Ascon 128a C");
	ascon_128a_init_common(ctx);
}

static void ascon_xof_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 12;
	ctx->digestsize = 0;

	ctx->state[0] = 0xb57e273b814cd416;
	ctx->state[1] = 0x2b51042562ae2420;
	ctx->state[2] = 0x66a3a7768ddf2218;
	ctx->state[3] = 0x5aad0a7a8153650c;
	ctx->state[4] = 0x4f3e0e32539493b6;
}

static void ascon_xof_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	ascon_xof_selftest_common(lc_ascon_xof, &tested, "Ascon XOF C");
	ascon_xof_init_common(ctx);
}

static void ascon_xofa_init_common(struct lc_ascon_hash *ctx)
{
	if (!ctx)
		return;

	ascon_ctx_init(ctx);
	ctx->roundb = 8;
	ctx->digestsize = 0;

	ctx->state[0] = 0x44906568b77b9832;
	ctx->state[1] = 0xcd8d6cae53455532;
	ctx->state[2] = 0xf7b5212756422129;
	ctx->state[3] = 0x246885e1de0d225b;
	ctx->state[4] = 0xa8cb5ce33449973f;
}

static void ascon_xofa_init(void *_state)
{
	struct lc_ascon_hash *ctx = _state;
	static int tested = 0;

	if (!ctx)
		return;

	ascon_xofa_selftest_common(lc_ascon_xofa, &tested, "Ascon XOFa C");
	ascon_xofa_init_common(ctx);
}
static size_t ascon_digestsize(void *_state)
{
	(void)_state;
	return LC_ASCON_HASH_DIGESTSIZE;
}

static void ascon_xof_set_digestsize(void *_state, size_t digestsize)
{
	struct lc_ascon_hash *ctx = _state;

	ctx->digestsize = digestsize;
}

static size_t ascon_xof_get_digestsize(void *_state)
{
	struct lc_ascon_hash *ctx = _state;

	return ctx->digestsize;
}

static inline void ascon_fill_state_aligned(struct lc_ascon_hash *ctx,
					    const uint64_t *in)
{
	unsigned int i;

	for (i = 0; i < LC_ASCON_HASH_RATE_WORDS; i++) {
		ctx->state[i] ^= be_bswap64(*in);
		in++;
	}
}

static inline void ascon_fill_state(struct lc_ascon_hash *ctx,
				    const uint8_t *in)
{
	unsigned int i;

	for (i = 0; i < LC_ASCON_HASH_RATE_WORDS; i++) {
		ctx->state[i] ^= ptr_to_be64(in);
		in += 8;
	}
}

static void ascon_absorb(void *_state, const uint8_t *in, size_t inlen)
{
	struct lc_ascon_hash *ctx = _state;
	size_t partial;

	if (!ctx)
		return;

	partial = ctx->msg_len % LC_ASCON_HASH_RATE;
	ctx->squeeze_more = 0;
	ctx->msg_len += inlen;

	/* Sponge absorbing phase */

	/* Check if we have a partial block stored */
	if (partial) {
		size_t todo = LC_ASCON_HASH_RATE - partial;

		/*
		 * If the provided data is small enough to fit in the partial
		 * buffer, copy it and leave it unprocessed.
		 */
		if (inlen < todo) {
			ascon_fill_state_bytes(ctx->state, in, partial, inlen);
			return;
		}

		/*
		 * The input data is large enough to fill the entire partial
		 * block buffer. Thus, we fill it and transform it.
		 */
		ascon_fill_state_bytes(ctx->state, in, partial, todo);
		inlen -= todo;
		in += todo;
	}

	if (partial && inlen)
		ascon_c_permutation(ctx->state, ctx->roundb);

	/* Perform a transformation of full block-size messages */
	if (mem_aligned(in, sizeof(uint64_t) - 1)) {
		for (; inlen >= LC_ASCON_HASH_RATE;
		       inlen -= LC_ASCON_HASH_RATE, in += LC_ASCON_HASH_RATE) {
			/*
			 * We can ignore the alignment warning as we checked
			 * for proper alignment.
			 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			ascon_fill_state_aligned(ctx, (uint64_t *)in);
#pragma GCC diagnostic pop
			if (inlen)
				ascon_c_permutation(ctx->state, ctx->roundb);
		}
	} else {
		for (; inlen >= LC_ASCON_HASH_RATE;
		       inlen -= LC_ASCON_HASH_RATE, in += LC_ASCON_HASH_RATE) {
			ascon_fill_state(ctx, in);
			if (inlen)
				ascon_c_permutation(ctx->state, ctx->roundb);
		}
	}

	/* If we have data left, copy it into the partial block buffer */
	ascon_fill_state_bytes(ctx->state, in, 0, inlen);
}

static void ascon_squeeze(void *_state, uint8_t *digest)
{
	struct lc_ascon_hash *ctx = _state;
	size_t digest_len;

	if (!ctx || !digest)
		return;

	digest_len = ctx->digestsize;

	if (!ctx->squeeze_more) {
		uint8_t partial = ctx->msg_len % LC_ASCON_HASH_RATE;
		static const uint8_t pad_data = 0x80;

		/* Add the padding bits and the 01 bits for the suffix. */
		ascon_fill_state_bytes(ctx->state, &pad_data, partial, 1);

		/* Final round in sponge absorbing phase */
		ascon_permutation_12(ctx->state);

		ctx->squeeze_more = 1;
	}

	while (digest_len) {
		/* How much data can we squeeze considering current state? */
		uint8_t todo = LC_ASCON_HASH_RATE - ctx->offset;

		/* Limit the data to be squeezed by the requested amount. */
		todo = (uint8_t)((digest_len > todo) ? todo : digest_len);

		sponge_extract_bytes(ctx->state, digest, ctx->offset, todo,
				     LC_ASCON_HASH_STATE_WORDS, be_bswap64,
				     be_bswap32, be64_to_ptr, be32_to_ptr);

		digest += todo;
		digest_len -= todo;

		/* Advance the offset */
		ctx->offset += todo;
		/* Wrap the offset at block size */
		ctx->offset %= LC_ASCON_HASH_RATE;

		if (!ctx->offset)
			ascon_c_permutation(ctx->state, ctx->roundb);
	}
}

static const struct lc_hash _ascon_128_c = {
	.init = ascon_128_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = ascon_digestsize,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_128) = &_ascon_128_c;


static const struct lc_hash _ascon_128a_c = {
	.init = ascon_128a_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = NULL,
	.get_digestsize = ascon_digestsize,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 128 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_128a) = &_ascon_128a_c;

static const struct lc_hash _ascon_xof_c = {
	.init = ascon_xof_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = ascon_xof_set_digestsize,
	.get_digestsize = ascon_xof_get_digestsize,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_xof) = &_ascon_xof_c;


static const struct lc_hash _ascon_xofa_c = {
	.init = ascon_xofa_init,
	.update = ascon_absorb,
	.final = ascon_squeeze,
	.set_digestsize = ascon_xof_set_digestsize,
	.get_digestsize = ascon_xof_get_digestsize,
	.sponge_permutation = ascon_c_permutation,
	.sponge_add_bytes = ascon_c_add_bytes,
	.sponge_extract_bytes = ascon_c_extract_bytes,
	.sponge_newstate = ascon_c_newstate,
	.sponge_rate = 64 / 8,
	.statesize = sizeof(struct lc_ascon_hash),
};
LC_INTERFACE_SYMBOL(const struct lc_hash *, lc_ascon_xofa) = &_ascon_xofa_c;
