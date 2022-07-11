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

#ifndef LC_KMAC256_DRNG_H
#define LC_KMAC256_DRNG_H

#include "lc_kmac.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_kmac256_drng_state {
	uint8_t *key;
};

#define LC_KMAC256_DRNG_KEYSIZE		64
#define LC_KMAC256_DRNG_MAX_CHUNK	(LC_SHA3_256_SIZE_BLOCK * 100)
#define LC_KMAC256_DRNG_STATE_SIZE	(LC_KMAC256_DRNG_KEYSIZE)
#define LC_KMAC256_DRNG_CTX_SIZE	(sizeof(struct lc_kmac256_drng_state) +\
					 LC_KMAC256_DRNG_STATE_SIZE)

#define _LC_KMAC256_DRNG_SET_CTX(name, ctx, offset)			       \
	name->key = (uint8_t *)(uint8_t *)ctx + offset

#define LC_KMAC256_DRNG_SET_CTX(name) _LC_KMAC256_DRNG_SET_CTX(name, name,     \
					 sizeof(struct lc_kmac256_drng_state))

/**
 * @brief Zeroize KMAC DRBG context allocated with either
 *	  LC_KMAC256_DRNG_CTX_ON_STACK or lc_kmac256_drng_alloc
 *
 * @param hash_state [in] Hash context to be zeroized
 */
static inline void lc_kmac256_drng_zero(struct lc_kmac256_drng_state *state)
{
	memset_secure((uint8_t *)state + sizeof(struct lc_kmac256_drng_state),
		      0, LC_KMAC256_DRNG_STATE_SIZE);
}

/**
 * @brief Allocate stack memory for the KMAC256 DRNG context
 *
 * @param name [in] Name of the stack variable
 */
#define LC_KMAC256_DRNG_CTX_ON_STACK(name)				       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_KMAC256_DRNG_CTX_SIZE,uint64_t);\
	struct lc_kmac256_drng_state *name =				       \
		(struct lc_kmac256_drng_state *)name ## _ctx_buf;  	       \
	LC_KMAC256_DRNG_SET_CTX(name);					       \
	lc_kmac256_drng_zero(name)

/**
 * @brief Allocation of a KMAC DRNG context
 *
 * @param state [out] KMAC DRNG context allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * You need to seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_kmac256_drng_alloc(struct lc_kmac256_drng_state **state);

/**
 * @brief Zeroize and free KMAC DRNG context
 *
 * @param state [in] KMAC DRNG context to be zeroized and freed
 */
void lc_kmac256_drng_zero_free(struct lc_kmac256_drng_state *state);

/**
 * @brief Obtain random numbers
 *
 * @param state [in] allocated KMAC DRNG cipher handle
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
void
lc_kmac256_drng_generate(struct lc_kmac256_drng_state *state,
			 const uint8_t *addtl_input, size_t addtl_input_len,
			 uint8_t *out, size_t outlen);

/**
 * @brief (Re)Seed the KMAC DRNG
 *
 * @param state [in] allocated ChaCha20 cipher handle
 * @param seed [in] buffer with the seed data
 * @param seedlen [in] length of seed
 * @param persbuf [in] Personalization / additional information buffer - may be
 *		      NULL
 * @param perslen [in] Length of personalization / additional information buffer
 *
 * When calling the function, the DRNG is seeded or reseeded. If it is reseeded,
 * the old state information is mixed into the new state.
 *
 * @return 0 upon succes; < 0 on error
 */
void lc_kmac256_drng_seed(struct lc_kmac256_drng_state *state,
		          const uint8_t *seed, size_t seedlen,
			  const uint8_t *persbuf, size_t perslen);

#ifdef __cplusplus
}
#endif

#endif /* LC_KMAC256_DRNG_H */
