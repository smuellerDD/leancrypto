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

#ifndef LC_HMAC_DRBG_H
#define LC_HMAC_DRBG_H

#include "lc_drbg.h"
#include "lc_hmac.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if !defined(LC_DRBG_HMAC_STATELEN) || !defined(LC_DRBG_HMAC_BLOCKLEN) || !defined(LC_DRBG_HMAC_CORE)
# error "Do not include this header file directly! Use hash_drbg_<hashtype>.h"
#endif

struct lc_drbg_hmac_state {
	struct lc_drbg_state drbg;
	struct lc_hmac_ctx hmac_ctx; /* Cipher handle - HMAC_MAX_STATE_SIZE */
	uint8_t *V;	/* internal state 10.1.1.1 1a) - DRBG_STATELEN */
	uint8_t *C;	/* static value 10.1.1.1 1b) - DRBG_STATELEN */
};

#define LC_DRBG_HMAC_STATE_SIZE(x)	(2 * LC_DRBG_HMAC_STATELEN +	       \
					 LC_HMAC_STATE_SIZE(x))
#define LC_DRBG_HMAC_CTX_SIZE(x)	(LC_DRBG_HMAC_STATE_SIZE(x) +	       \
					 sizeof(struct lc_drbg_hmac_state))

void lc_drbg_hmac_seed(struct lc_drbg_state *drbg, struct lc_drbg_string *seed);
size_t lc_drbg_hmac_generate(struct lc_drbg_state *drbg,
			     uint8_t *buf, size_t buflen,
			     struct lc_drbg_string *addtl);
void lc_drbg_hmac_zero(struct lc_drbg_state *drbg);

#define _LC_DRBG_HMAC_SET_CTX(name, ctx, offset)			       \
	_LC_DRBG_SET_CTX((&name->drbg), lc_drbg_hmac_seed,		       \
			 lc_drbg_hmac_generate, lc_drbg_hmac_zero);	       \
	_LC_HMAC_SET_CTX((&name->hmac_ctx), LC_DRBG_HMAC_CORE, ctx, offset);   \
	name->V = (uint8_t *)((uint8_t *)ctx + offset +			       \
			      LC_HMAC_STATE_SIZE(LC_DRBG_HMAC_CORE));	       \
	name->C = (uint8_t *)((uint8_t *)ctx + offset +			       \
		  LC_HMAC_STATE_SIZE(LC_DRBG_HMAC_CORE) + LC_DRBG_HMAC_STATELEN)

#define LC_DRBG_HMAC_SET_CTX(name) _LC_DRBG_HMAC_SET_CTX(name, name,	       \
					sizeof(struct lc_drbg_hmac_state))


/**
 * @brief Allocate stack memory for the Hash DRBG context
 *
 * @param name [in] Name of the stack variable
 */
#define LC_DRBG_HMAC_CTX_ON_STACK(name)			      		       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf,				       \
			  LC_DRBG_HMAC_CTX_SIZE(LC_DRBG_HMAC_CORE), uint64_t); \
	struct lc_drbg_hmac_state *name ## _hmac =			       \
				(struct lc_drbg_hmac_state *) name ## _ctx_buf;\
	LC_DRBG_HMAC_SET_CTX(name ## _hmac);				       \
	struct lc_drbg_state *name = (struct lc_drbg_state *)name ## _hmac;    \
	lc_drbg_hmac_zero(name)

/**
 * @brief Allocate HMAC DRBG context on heap
 *
 * @param drbg [out] Allocated HMAC DRBG context
 *
 * @return: 0 on success, < 0 on error
 */
int lc_drbg_hmac_alloc(struct lc_drbg_state **drbg);

#ifdef __cplusplus
}
#endif

#endif /* LC_HMAC_DRBG_H */
