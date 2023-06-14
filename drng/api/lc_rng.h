/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_RNG_H
#define LC_RNG_H

#include "lc_memory_support.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_rng {
	int (*generate)(void *state,
			const uint8_t *addtl_input, size_t addtl_input_len,
			uint8_t *out, size_t outlen);
	int (*seed)(void *state,
		    const uint8_t *seed, size_t seedlen,
		    const uint8_t *persbuf, size_t perslen);
	void (*zero)(void *state);
};

struct lc_rng_ctx {
	const struct lc_rng *rng;
	void *rng_state;
};

#define LC_RNG_CTX(name, cb)						       \
	name->rng = cb;							       \
	name->rng_state = (uint8_t *)(name) + sizeof(struct lc_rng_ctx)

/**
 * Seeded DRNG
 *
 * One common instance of a seeded DRNG. The caller does not need to consider
 * the seeding and reseeding - it is automatically and transparently handled.
 * Thus, this structure can be directly used for the lc_rng API by a caller
 * and have a properly seeded DRNG.
 *
 * NOTE: The caller must ensure that a lock is applied around the use of this
 * variable if there is the potential of concurrent use.
 */
extern struct lc_rng_ctx *lc_seeded_rng;

/**
 * Concept of RNGs in leancrypto
 *
 * All RNGs can be used with the API calls documented below. However,
 * the allocation part is RNG-specific. Thus, perform the following steps
 *
 * 1. Allocation: Use the stack or heap allocation functions documented in
 *    lc_cshake256_drng.h, lc_kmac256_drng.h, lc_hash_drbg*.h.
 *
 * 2. Use the returned cipher handle with the API calls below.
 */

/**
 * @brief Zeroize RNG context
 *
 * @param [in] ctx RNG context to be zeroized
 */
static inline void lc_rng_zero(struct lc_rng_ctx *ctx)
{
	const struct lc_rng *rng;
	void *rng_state;

	if (!ctx)
		return;

	rng = ctx->rng;
	rng_state = ctx->rng_state;

	rng->zero(rng_state);
}

/**
 * @brief Zeroize and free RNG context
 *
 * @param [in] ctx RNG context to be zeroized and freed
 */
static inline void lc_rng_zero_free(struct lc_rng_ctx *ctx)
{
	if (!ctx)
		return;

	lc_rng_zero(ctx);
	lc_free(ctx);
}

/**
 * @brief Obtain random numbers
 *
 * @param [in] ctx allocated RNG cipher handle
 * @param [in] addtl_input Additional input to diversify state
 * @param [in] addtl_input_len Length of additional input buffer
 * @param [out] outbuf allocated buffer that is to be filled with random numbers
 * @param [in] outbuflen length of outbuf indicating the size of the random
 *			 number byte string to be generated
 *
 * Generate random numbers and fill the buffer provided by the caller.
 *
 * @return 0 upon success; < 0 on error
 */
static inline int
lc_rng_generate(struct lc_rng_ctx *ctx,
		const uint8_t *addtl_input, size_t addtl_input_len,
		uint8_t *out, size_t outlen)
{
	const struct lc_rng *rng;
	void *rng_state;

	if (!ctx)
		return -EINVAL;

	rng = ctx->rng;
	rng_state = ctx->rng_state;

	return rng->generate(rng_state, addtl_input, addtl_input_len,
			     out, outlen);
}

/**
 * @brief (Re)Seed the RNG
 *
 * @param [in] ctx allocated RNG cipher handle
 * @param [in] seed buffer with the seed data
 * @param [in] seedlen length of seed
 * @param [in] persbuf Personalization / additional information buffer - may be
 *		       NULL
 * @param [in] perslen Length of personalization / additional information buffer
 *
 * When calling the function, the DRNG is seeded or reseeded. If it is reseeded,
 * the old state information is mixed into the new state.
 *
 * @return 0 upon success; < 0 on error
 */
static inline int
lc_rng_seed(struct lc_rng_ctx *ctx,
	    const uint8_t *seed, size_t seedlen,
	    const uint8_t *persbuf, size_t perslen)
{
	const struct lc_rng *rng;
	void *rng_state;

	if (!ctx)
		return -EINVAL;

	rng = ctx->rng;
	rng_state = ctx->rng_state;

	return rng->seed(rng_state, seed, seedlen, persbuf, perslen);
}

#ifdef __cplusplus
}
#endif

#endif /* LC_RNG_H */
