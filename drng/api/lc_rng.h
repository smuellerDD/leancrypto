/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>

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
 * @param state [in] RNG context to be zeroized
 */
static inline void lc_rng_zero(struct lc_rng_ctx *ctx)
{
	const struct lc_rng *rng = ctx->rng;
	void *rng_state = ctx->rng_state;

	rng->zero(rng_state);
}

/**
 * @brief Zeroize and free RNG context
 *
 * @param state [in] RNG context to be zeroized and freed
 */
static inline void lc_rng_zero_free(struct lc_rng_ctx *ctx)
{
	if (!ctx)
		return;

	lc_rng_zero(ctx);
	free(ctx);
}

/**
 * @brief Obtain random numbers
 *
 * @param ctx [in] allocated RNG cipher handle
 * @param addtl_input [in] Additional input to diversify state
 * @param addtl_input_len [in] Length of additional input buffer
 * @param outbuf [out] allocated buffer that is to be filled with random numbers
 * @param outbuflen [in] length of outbuf indicating the size of the random
 *			 number byte string to be generated
 *
 * Generate random numbers and fill the buffer provided by the caller.
 *
 * The generation operation updates the KMAC DRNG state at the same time
 * the random bit stream is generated to achieve backtracking resistance.
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
 * @param ctx [in] allocated RNG cipher handle
 * @param seed [in] buffer with the seed data
 * @param seedlen [in] length of seed
 * @param persbuf [in] Personalization / additional information buffer - may be
 *		       NULL
 * @param perslen [in] Length of personalization / additional information buffer
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
	const struct lc_rng *rng = ctx->rng;
	void *rng_state = ctx->rng_state;

	return rng->seed(rng_state, seed, seedlen, persbuf, perslen);
}

#ifdef __cplusplus
}
#endif

#endif /* LC_RNG_H */
