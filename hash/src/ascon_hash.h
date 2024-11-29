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

#ifndef ASCON_HASH_H
#define ASCON_HASH_H

#include "bitshift.h"
#include "conv_be_le.h"
#include "lc_ascon_hash.h"
#include "sponge_common.h"
#include "xor.h"

#ifdef __cplusplus
extern "C" {
#endif

/************************ Raw Ascon Sponge Operations *************************/

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__

/*
 * This function works on both endianesses, but since it has more code than
 * the little endian code base, there is a special case for big endian.
 */
static inline void ascon_fill_state_bytes(uint64_t *state, const uint8_t *in,
					  size_t byte_offset, size_t inlen)
{
	sponge_fill_state_bytes(state, in, byte_offset, inlen, le_bswap64);
}

#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__

static inline void ascon_fill_state_bytes(uint64_t *state, const uint8_t *in,
					  size_t byte_offset, size_t inlen)
{
	uint8_t *_state = (uint8_t *)state;

	xor_64(_state + byte_offset, in, inlen);
}

#else
#error "Endianess not defined"
#endif

static void ascon_c_add_bytes(void *state, const uint8_t *data, size_t offset,
			      size_t length)
{
	ascon_fill_state_bytes((uint64_t *)state, data, offset, length);
}

static void ascon_c_extract_bytes(const void *state, uint8_t *data,
				  size_t offset, size_t length)
{
	sponge_extract_bytes(state, data, offset, length,
			     LC_ASCON_HASH_STATE_WORDS, le_bswap64, le_bswap32,
			     le64_to_ptr, le32_to_ptr);
}

static void ascon_c_newstate(void *state, const uint8_t *data, size_t offset,
			     size_t length)
{
	sponge_newstate(state, data, offset, length, le_bswap64);
}

/********************************* Ascon Hash *********************************/

static inline void ascon_fill_state_aligned(struct lc_ascon_hash *ctx,
					    const uint64_t *in)
{
	unsigned int i;

	for (i = 0; i < LC_ASCON_HASH_RATE_WORDS; i++) {
		ctx->state[i] ^= le_bswap64(*in);
		in++;
	}
}

static inline void ascon_fill_state(struct lc_ascon_hash *ctx,
				    const uint8_t *in)
{
	unsigned int i;

	for (i = 0; i < LC_ASCON_HASH_RATE_WORDS; i++) {
		ctx->state[i] ^= ptr_to_le64(in);
		in += 8;
	}
}

static inline void
ascon_absorb_common(void *_state, const uint8_t *in, size_t inlen,
		    void (*permutation)(void *state, unsigned int rounds))
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
		permutation(ctx->state, ctx->roundb);

	/* Perform a transformation of full block-size messages */
	if (lc_mem_aligned(in, sizeof(uint64_t) - 1)) {
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
				permutation(ctx->state, ctx->roundb);
		}
	} else {
		for (; inlen >= LC_ASCON_HASH_RATE;
		     inlen -= LC_ASCON_HASH_RATE, in += LC_ASCON_HASH_RATE) {
			ascon_fill_state(ctx, in);
			if (inlen)
				permutation(ctx->state, ctx->roundb);
		}
	}

	/* If we have data left, copy it into the partial block buffer */
	ascon_fill_state_bytes(ctx->state, in, 0, inlen);
}

static inline void ascon_squeeze_common(
	void *_state, uint8_t *digest,
	void (*permutation12)(uint64_t s[LC_ASCON_HASH_STATE_WORDS]),
	void (*permutation)(void *state, unsigned int rounds))
{
	struct lc_ascon_hash *ctx = _state;
	size_t digest_len;

	if (!ctx || !digest)
		return;

	digest_len = ctx->digestsize;

	if (!ctx->squeeze_more) {
		uint8_t partial = ctx->msg_len % LC_ASCON_HASH_RATE;
		/*
		 * Based on the specification in SP800-232 section 2.1, this
		 * padding byte would be 0x80.
		 *
		 * However the bitstring is indexed from LSB to MSB, i.e.,
		 * appending byte 0x01 appends the abstract bitstring
		 * 1,0,0,0,0,0,0,0. Thus, the specification does in fact change
		 * not only the byte ordering (as expected for little endian),
		 * but also the bit indexing (and thus the bit ordering in the
		 * abstract bitstring notation used to define the mode).
		 */
		static const uint8_t pad_data = 0x01;

		/* Add the padding bits and the 01 bits for the suffix. */
		ascon_fill_state_bytes(ctx->state, &pad_data, partial, 1);

		/* Final round in sponge absorbing phase */
		permutation12(ctx->state);

		ctx->squeeze_more = 1;
	}

	while (digest_len) {
		/* How much data can we squeeze considering current state? */
		uint8_t todo = LC_ASCON_HASH_RATE - ctx->offset;

		/* Limit the data to be squeezed by the requested amount. */
		todo = (uint8_t)((digest_len > todo) ? todo : digest_len);

		sponge_extract_bytes(ctx->state, digest, ctx->offset, todo,
				     LC_ASCON_HASH_STATE_WORDS, le_bswap64,
				     le_bswap32, le64_to_ptr, le32_to_ptr);

		digest += todo;
		digest_len -= todo;

		/* Advance the offset */
		ctx->offset += todo;
		/* Wrap the offset at block size */
		ctx->offset %= LC_ASCON_HASH_RATE;

		if (!ctx->offset)
			permutation(ctx->state, ctx->roundb);
	}
}

#ifdef __cplusplus
}
#endif

#endif /* ASCON_HASH_H */
