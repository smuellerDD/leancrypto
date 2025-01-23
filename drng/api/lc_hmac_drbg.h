/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(LC_DRBG_HMAC_STATELEN) || !defined(LC_DRBG_HMAC_BLOCKLEN) ||      \
	!defined(LC_DRBG_HMAC_CORE)
#error "Do not include this header file directly! Use lc_hmac_drbg_<hashtype>.h"
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_drbg_hmac_state {
	struct lc_hmac_ctx hmac_ctx; /* Cipher handle - HMAC_MAX_STATE_SIZE */
	uint8_t *V; /* internal state 10.1.1.1 1a) - DRBG_STATELEN */
	uint8_t *C; /* static value 10.1.1.1 1b) - DRBG_STATELEN */
	unsigned int seeded : 1;
};

#define LC_DRBG_HMAC_STATE_SIZE(x)                                             \
	(2 * LC_DRBG_HMAC_STATELEN + LC_HMAC_STATE_SIZE(x))
#define LC_DRBG_HMAC_CTX_SIZE(x)                                               \
	(LC_DRBG_HMAC_STATE_SIZE(x) + sizeof(struct lc_drbg_hmac_state) +      \
	 sizeof(struct lc_rng))

#define _LC_DRBG_HMAC_SET_CTX(name, ctx, offset)                               \
	_LC_HMAC_SET_CTX((&(name)->hmac_ctx), LC_DRBG_HMAC_CORE, ctx, offset); \
	(name)->V = (uint8_t *)((uint8_t *)ctx + offset +                      \
				LC_HMAC_STATE_SIZE(LC_DRBG_HMAC_CORE));        \
	(name)->C = (uint8_t *)((uint8_t *)ctx + offset +                      \
				LC_HMAC_STATE_SIZE(LC_DRBG_HMAC_CORE) +        \
				LC_DRBG_HMAC_STATELEN);                        \
	(name)->seeded = 0

#define LC_DRBG_HMAC_SET_CTX(name)                                             \
	_LC_DRBG_HMAC_SET_CTX(name, name, sizeof(struct lc_drbg_hmac_state))

extern const struct lc_rng *lc_hmac_drbg;

#define LC_DRBG_HMAC_RNG_CTX(name)                                             \
	LC_RNG_CTX(name, lc_hmac_drbg);                                        \
	LC_DRBG_HMAC_SET_CTX((struct lc_drbg_hmac_state *)name->rng_state);    \
	lc_hmac_drbg->zero(name->rng_state)
/// \endcond

/**
 * @brief Allocate stack memory for the Hash DRBG context
 *
 * @param [in] name Name of the stack variable
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_DRBG_HMAC_CTX_ON_STACK(name)                                             \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(                                          \
				name##_ctx_buf,                                     \
				LC_DRBG_HMAC_CTX_SIZE(LC_DRBG_HMAC_CORE),           \
				LC_HASH_COMMON_ALIGNMENT);                          \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;              \
	LC_DRBG_HMAC_RNG_CTX(name);                                                 \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocate HMAC DRBG context on heap
 *
 * @param [out] drbg Allocated HMAC DRBG context
 *
 * \warning You MUST seed the DRNG!
 *
 * @return: 0 on success, < 0 on error
 */
int lc_drbg_hmac_alloc(struct lc_rng_ctx **drbg);

/**
 * @brief Tests as defined in 11.3.2 in addition to the cipher tests: testing
 *	  of the error handling.
 *
 * @param [in] drbg DRBG state handle that is used solely for the testing. It
 *		    shall not be a production handle unless you call drbg_seed
 *		    on that handle afterwards.
 *
 * Note: testing of failing seed source as defined in 11.3.2 must be handled
 * by the caller.
 *
 * Note 2: There is no sensible way of testing the reseed counter
 * enforcement, so skip it.
 *
 * @return: 0 on success, < 0 on error
 */
int lc_drbg_hmac_healthcheck_sanity(struct lc_rng_ctx *drbg);

#ifdef __cplusplus
}
#endif

#endif /* LC_HMAC_DRBG_H */
