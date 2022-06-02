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

#ifndef LC_HASH_DRBG_H
#define LC_HASH_DRBG_H

#include "lc_drbg.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if !defined(LC_DRBG_HASH_STATELEN) ||					       \
    !defined(LC_DRBG_HASH_BLOCKLEN) ||					       \
    !defined(LC_DRBG_HASH_CORE)
# error "Do not include this header file directly! Use lc_hash_drbg_<hashtype>.h"
#endif

struct lc_drbg_hash_state {
	struct lc_drbg_state drbg;
	struct lc_hash_ctx hash_ctx; /* Cipher handle - HASH_MAX_STATE_SIZE */
	uint8_t *V;	/* internal state 10.1.1.1 1a) - DRBG_STATELEN */
	uint8_t *C;	/* static value 10.1.1.1 1b) - DRBG_STATELEN */
	uint8_t *scratchpad;	/* working mem DRBG_STATELEN + DRBG_BLOCKLEN */

	/* Number of RNG requests since last reseed -- 10.1.1.1 1c) */
	size_t reseed_ctr;
};

#define LC_DRBG_HASH_STATE_SIZE(x)	(3 * LC_DRBG_HASH_STATELEN +	       \
					 LC_DRBG_HASH_BLOCKLEN +	       \
					 LC_HASH_STATE_SIZE(x))
#define LC_DRBG_HASH_CTX_SIZE(x)	(LC_DRBG_HASH_STATE_SIZE(x) +	       \
					 sizeof(struct lc_drbg_hash_state))

void lc_drbg_hash_seed(struct lc_drbg_state *drbg, struct lc_drbg_string *seed);
size_t lc_drbg_hash_generate(struct lc_drbg_state *drbg,
			     uint8_t *buf, size_t buflen,
			     struct lc_drbg_string *addtl);
void lc_drbg_hash_zero(struct lc_drbg_state *drbg);

#define _LC_DRBG_HASH_SET_CTX(name, ctx, offset)			       \
	_LC_DRBG_SET_CTX((&name->drbg), lc_drbg_hash_seed,		       \
			 lc_drbg_hash_generate, lc_drbg_hash_zero);	       \
	_LC_HASH_SET_CTX((&name->hash_ctx), LC_DRBG_HASH_CORE, ctx, offset);   \
	name->V = (uint8_t *)((uint8_t *)ctx + offset +			       \
			      LC_HASH_STATE_SIZE(LC_DRBG_HASH_CORE));	       \
        name->C = (uint8_t *)((uint8_t *)ctx + offset +			       \
		  LC_HASH_STATE_SIZE(LC_DRBG_HASH_CORE) +		       \
		  LC_DRBG_HASH_STATELEN);				       \
	name->scratchpad = (uint8_t *)((uint8_t *)ctx +	offset +	       \
			   LC_HASH_STATE_SIZE(LC_DRBG_HASH_CORE) +	       \
			   2 * LC_DRBG_HASH_STATELEN);			       \
	name->reseed_ctr = 0

#define LC_DRBG_HASH_SET_CTX(name) _LC_DRBG_HASH_SET_CTX(name, name,	       \
					 sizeof(struct lc_drbg_hash_state))

/**
 * @brief Allocate stack memory for the Hash DRBG context
 *
 * @param name [in] Name of the stack variable
 */
#define LC_DRBG_HASH_CTX_ON_STACK(name)			      		       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf,				       \
			  LC_DRBG_HASH_CTX_SIZE(LC_DRBG_HASH_CORE), uint64_t); \
	struct lc_drbg_hash_state *name ## _hash =			       \
				(struct lc_drbg_hash_state *) name ## _ctx_buf;\
	LC_DRBG_HASH_SET_CTX(name ## _hash);				       \
	struct lc_drbg_state *name = (struct lc_drbg_state *)name ## _hash;    \
	lc_drbg_hash_zero(name)

/**
 * @brief Allocate Hash DRBG context on heap
 *
 * @param drbg [out] Allocated Hash DRBG context
 *
 * @return: 0 on success, < 0 on error
 */
int lc_drbg_hash_alloc(struct lc_drbg_state **drbg);


#ifdef __cplusplus
}
#endif

#endif /* LC_HASH_DRBG_H */
