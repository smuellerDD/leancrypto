/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef KECCAKP_1600_ARMV8A_CE_H
#define KECCAKP_1600_ARMV8A_CE_H

#include "ext_headers.h"
#include "ext_headers_arm.h"
#include "lc_sha3.h"
#include "math_helper.h"

#ifdef __cplusplus
extern "C"
{
#endif

size_t lc_keccak_absorb_arm_ce(uint64_t A[25], const unsigned char *inp,
			       size_t len, size_t r);
void lc_keccak_squeeze_arm_ce(uint64_t A[25], unsigned char *out, size_t len,
			      size_t r);
void lc_keccakf1600_arm_ce(uint64_t A[25]);

size_t lc_keccak_absorb_arm_asm(uint64_t A[25], const unsigned char *inp,
				size_t len, size_t r);
void lc_keccak_squeeze_arm_asm(uint64_t A[25], unsigned char *out, size_t len,
			       size_t r);
void lc_keccakf1600_arm_asm(uint64_t A[25]);

static inline void
keccak_arm_asm_absorb_internal(void *_state, const uint8_t *in, size_t inlen,
			       size_t (*absorb)(uint64_t A[25],
						const unsigned char *inp,
						size_t len, size_t r))
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_224_state *ctx = _state;
	size_t partial, blocksize;

	if (!ctx)
		return;

	blocksize = ctx->r;
	partial = ctx->msg_len % blocksize;
	ctx->squeeze_more = 0;
	ctx->msg_len += inlen;

	/* Sponge absorbing phase */

	/* Check if we have a partial block stored */
	if (partial) {
		size_t todo = blocksize - partial;

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

		LC_NEON_ENABLE;
		absorb(ctx->state, ctx->partial, blocksize, blocksize);
		LC_NEON_DISABLE;
	}

	/* Perform a transformation of full block-size messages */
	if (inlen >= blocksize) {
		size_t inlen2 = inlen;

		inlen = absorb(ctx->state, in, inlen, blocksize);
		in += inlen2 - inlen;

	}

	/* If we have data left, copy it into the partial block buffer */
	memcpy(ctx->partial, in, inlen);
}

static inline void
keccak_arm_asm_squeeze_internal(void *_state, uint8_t *digest,
				size_t (*absorb)(uint64_t A[25],
						 const unsigned char *inp,
						 size_t len, size_t r),
				void (*squeeze)(uint64_t A[25],
						unsigned char *out,
						size_t len, size_t r),
				void (*keccakf1600)(uint64_t A[25]))
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_224_state *ctx = _state;
	size_t digest_len, blocksize;
	unsigned int squeeze_more = ctx->squeeze_more;

	if (!ctx || !digest)
		return;

	digest_len = ctx->digestsize;
	blocksize = ctx->r;

	if (!ctx->squeeze_more) {
		size_t partial = ctx->msg_len % blocksize;

		/* Final round in sponge absorbing phase */

		/* Fill the unused part of the partial buffer with zeros */
		memset(ctx->partial + partial, 0, blocksize - partial);

		/* Add the padding bits and the 01 bits for the suffix. */
		ctx->partial[partial] = ctx->padding;
		ctx->partial[blocksize - 1] |= 0x80;

		ctx->squeeze_more = 1;

		LC_NEON_ENABLE;
		absorb(ctx->state, ctx->partial, blocksize, blocksize);
		LC_NEON_DISABLE;
	}

	if (ctx->offset) {
		/*
		 * Access requests when squeezing more data that
		 * happens to be not aligned with the block size of
		 * the used SHAKE algorithm are processed byte-wise.
		 */
		size_t word, byte, i;

		/* How much data can we squeeze considering current state? */
		size_t todo = blocksize - ctx->offset;

		/* Limit the data to be squeezed by the requested amount. */
		todo = min_size(digest_len, todo);

		digest_len -= todo;

		for (i = ctx->offset;
		     i < todo + ctx->offset;
		     i++, digest++) {
			word = i / sizeof(ctx->state[0]);
			byte = (i % sizeof(ctx->state[0])) << 3;

			*digest = (uint8_t)(ctx->state[word] >> byte);
		}

		/* Advance the offset */
		ctx->offset += todo;
		/* Wrap the offset at block size */
		ctx->offset %= blocksize;

		/* If entire request is satisfied here, no need to continue. */
		if (!digest_len)
			return;

		/*
		 * All bytes from the Keccak state are now consumed and
		 * we did not yet satisfy the entire request, the
		 * remaining request is processed with the squeeze function
		 * below. We must perform a permutation operation now, because
		 * the sqeeze implementation first outputs the state followed
		 * by a permutation.
		 */
		LC_NEON_ENABLE;
		keccakf1600(ctx->state);
		LC_NEON_DISABLE;

	} else if (squeeze_more) {
		/*
		 * If there was a previous squeeze operation and there was no
		 * offset left in that previous round, we must perform a
		 * permutation operation, because the sqeeze implementation
		 * first outputs the state followed by a permutation.
		 */
		LC_NEON_ENABLE;
		keccakf1600(ctx->state);
		LC_NEON_DISABLE;
	}

	LC_NEON_ENABLE;
	squeeze(ctx->state, digest, digest_len, blocksize);
	LC_NEON_DISABLE;

	/* Advance the offset */
	ctx->offset += digest_len;
	/* Wrap the offset at block size */
	ctx->offset %= blocksize;
}


#ifdef __cplusplus
}
#endif

#endif /* KECCAKP_1600_ARMV8A_CE_H */
