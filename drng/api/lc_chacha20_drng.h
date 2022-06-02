/*
 * Copyright (C) 2016 - 2017, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#ifndef _LC_CHACHA20_DRNG_H
#define _LC_CHACHA20_DRNG_H

#include <stdint.h>

#include "lc_chacha20.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_chacha20_drng_ctx {
	struct lc_sym_ctx cc20;
};

#define LC_CC20_DRNG_STATE_SIZE		(LC_SYM_STATE_SIZE(lc_chacha20))
#define LC_CC20_DRNG_CTX_SIZE		(LC_CC20_DRNG_STATE_SIZE +	       \
					 sizeof(struct lc_chacha20_drng_ctx))

#define _LC_CC20_DRNG_SET_CTX(name, ctx, offset)			       \
	_LC_SYM_SET_CTX((&name->cc20), lc_chacha20, ctx, offset)

#define LC_CC20_DRNG_SET_CTX(name)	_LC_CC20_DRNG_SET_CTX(name, name,      \
					sizeof(struct lc_chacha20_drng_ctx))

/**
 * @brief Zeroize Hash context allocated with either LC_HASH_CTX_ON_STACK or
 *	  lc_hmac_alloc
 *
 * @param hash_state [in] Hash context to be zeroized
 */
static inline void lc_cc20_drng_zero(struct lc_chacha20_drng_ctx *cc20_ctx)
{
	struct lc_sym_ctx *sym_ctx = &cc20_ctx->cc20;

	memset_secure((uint8_t *)cc20_ctx + sizeof(struct lc_chacha20_drng_ctx),
		      0, LC_CC20_DRNG_STATE_SIZE);
	lc_sym_init(sym_ctx);
}

/**
 * @brief Allocate stack memory for the Hash DRBG context
 *
 * @param name [in] Name of the stack variable
 */
#define LC_CC20_DRNG_CTX_ON_STACK(name)			      		       \
	LC_ALIGNED_SYM_BUFFER(name ## _ctx_buf, lc_chacha20,		       \
			      LC_CC20_DRNG_CTX_SIZE, uint64_t);		       \
	struct lc_chacha20_drng_ctx *name =				       \
			(struct lc_chacha20_drng_ctx *) name ## _ctx_buf;      \
	LC_CC20_DRNG_SET_CTX(name);					       \
	lc_cc20_drng_zero(name)

/**
 * @brief Allocation of a ChaCha20 DRNG context
 *
 * @param cc20_ctx [out] ChaCha20 DRNG context allocated by the function
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * You need to seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_cc20_drng_alloc(struct lc_chacha20_drng_ctx **cc20_ctx);

/**
 * @brief Zeroize and ChaCha20 DRNG context
 *
 * @param cc20_ctx [in] ChaCha20 DRNG context to be zeroized and freed
 */
void lc_cc20_drng_zero_free(struct lc_chacha20_drng_ctx *cc20_ctx);

/**
 * @brief Obtain random numbers
 *
 * @param cc20_ctx [in] allocated ChaCha20 cipher handle
 * @param outbuf [out] allocated buffer that is to be filled with random numbers
 * @param outbuflen [in] length of outbuf indicating the size of the random
 *	number byte string to be generated
 *
 * Generate random numbers and fill the buffer provided by the caller.
 *
 * Before each request of random numbers, a high-resolution time stamp is
 * mixed into the random number generator state.
 *
 * If the last (re)seeding operation is longer than 600 seconds ago or
 * more than 1GB of random numbers were generated, an automated
 * reseed is performed.
 *
 * After the generation of random numbers, the internal state of the ChaCha20
 * DRNG is completely re-created using ChaCha20 to provide enhanced backtracking
 * resistance. I.e. if the state of the DRNG becomes known after generation
 * of random numbers, an attacker cannot deduce the already generated
 * random numbers.
 *
 * @return 0 upon success; < 0 on error
 */
void lc_cc20_drng_generate(struct lc_chacha20_drng_ctx *cc20_ctx,
			   uint8_t *outbuf, size_t outbuflen);

/**
 * @brief Reseed the ChaCha20 DRNG
 *
 * @param cc20_ctx [in] allocated ChaCha20 cipher handle
 * @param inbuf [in] buffer with the seed data
 * @param inbuflen [in] length of inbuf
 *
 * When calling the function, the DRNG is first seeded from its internal
 * noise sources. This is followed by seeding the DRNG with the caller-provided
 * data.
 *
 * @return 0 upon succes; < 0 on error
 */
void lc_cc20_drng_seed(struct lc_chacha20_drng_ctx *cc20_ctx,
		       const uint8_t *inbuf, size_t inbuflen);

#ifdef __cplusplus
}
#endif

#endif /* _LC_CHACHA20_DRNG_H */
