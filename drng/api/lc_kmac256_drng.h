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

/*
 * The memory of both key and random member variable MUST be a linear buffer
 * as both values are filled with one KECCAK operation.
 */
struct lc_kmac256_drng_state {
	uint8_t *key;		/* KMAC DRNG key */
	uint8_t *random;	/* Random bit stream data from first KECCAK */
};

#define LC_KMAC256_DRNG_KEYSIZE		64
#define LC_KMAC256_DRNG_MAX_CHUNK	(LC_SHA3_256_SIZE_BLOCK * 100)
#define LC_KMAC256_DRNG_STATE_SIZE	(LC_SHA3_256_SIZE_BLOCK)
#define LC_KMAC256_DRBG_RND_SIZE	(LC_KMAC256_DRNG_STATE_SIZE -	       \
					 LC_KMAC256_DRNG_KEYSIZE)
#define LC_KMAC256_DRNG_CTX_SIZE	(sizeof(struct lc_kmac256_drng_state) +\
					 LC_KMAC256_DRNG_STATE_SIZE)

#define _LC_KMAC256_DRNG_SET_CTX(name, ctx, offset)			       \
	name->key = (uint8_t *)(uint8_t *)ctx + offset;			       \
	name->random = (uint8_t *)(uint8_t *)ctx + offset +		       \
			LC_KMAC256_DRNG_KEYSIZE

#define LC_KMAC256_DRNG_SET_CTX(name) _LC_KMAC256_DRNG_SET_CTX(name, name,     \
					 sizeof(struct lc_kmac256_drng_state))

/**
 * @brief Zeroize Hash context allocated with either LC_HASH_CTX_ON_STACK or
 *	  lc_hmac_alloc
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

void
lc_kmac256_drng_generate(struct lc_kmac256_drng_state *state,
			 const uint8_t *addtl_input, size_t addtl_input_len,
			 uint8_t *out, size_t outlen);

void lc_kmac256_drng_seed(struct lc_kmac256_drng_state *state,
		          const uint8_t *key, size_t keylen);

void lc_kmac256_drng_zero_free(struct lc_kmac256_drng_state *state);

int lc_kmac256_drng_alloc(struct lc_kmac256_drng_state **lc_kmac_drng_state);

#ifdef __cplusplus
}
#endif

#endif /* LC_KMAC256_DRNG_H */
