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

#ifndef LC_HASH_DRBG_H
#define LC_HASH_DRBG_H

#include "lc_drbg.h"
#include "lc_rng.h"
#include "lc_sha512.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
#define LC_DRBG_HASH_STATELEN 111
#define LC_DRBG_HASH_BLOCKLEN 64

struct lc_drbg_hash_state {
	struct lc_hash_ctx hash_ctx; /* Cipher handle */
	uint8_t hash_state[LC_SHA512_STATE_SIZE + LC_HASH_COMMON_ALIGNMENT];
	uint8_t V[LC_DRBG_HASH_STATELEN]; /* internal state 10.1.1.1 1a) */
	uint8_t C[LC_DRBG_HASH_STATELEN]; /* static value 10.1.1.1 1b) */
	uint8_t scratchpad[LC_DRBG_HASH_STATELEN + LC_DRBG_HASH_BLOCKLEN];
	/* working mem */

	/* Number of RNG requests since last reseed -- 10.1.1.1 1c) */
	size_t reseed_ctr;
	unsigned int seeded : 1;
};

#define LC_DRBG_HASH_STATE_SIZE (sizeof(struct lc_drbg_hash_state))
#define LC_DRBG_HASH_CTX_SIZE                                                  \
	((unsigned long)(LC_DRBG_HASH_STATE_SIZE + sizeof(struct lc_rng)))

#define _LC_DRBG_HASH_SET_CTX(name, ctx, offset)                               \
	LC_SHA512_CTX((&(name)->hash_ctx));                                    \
	(name)->reseed_ctr = 0;                                                \
	(name)->seeded = 0

#define LC_DRBG_HASH_SET_CTX(name)                                             \
	_LC_DRBG_HASH_SET_CTX(name, name, sizeof(struct lc_drbg_hash_state))

extern const struct lc_rng *lc_hash_drbg;

#define LC_DRBG_HASH_RNG_CTX(name)                                             \
	LC_RNG_CTX((name), lc_hash_drbg);                                      \
	LC_DRBG_HASH_SET_CTX((struct lc_drbg_hash_state *)name->rng_state);    \
	lc_rng_zero(name)
/// \endcond

/**
 * @brief Allocate stack memory for the Hash DRBG context
 *
 * @param [in] name Name of the stack variable
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_DRBG_HASH_CTX_ON_STACK(name)                                        \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf, LC_DRBG_HASH_CTX_SIZE,       \
				  LC_HASH_COMMON_ALIGNMENT);                   \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;         \
	LC_DRBG_HASH_RNG_CTX(name);                                            \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocate Hash DRBG context on heap
 *
 * @param [out] drbg Allocated Hash DRBG context
 *
 * \warning You MUST seed the DRNG!
 *
 * @return: 0 on success, < 0 on error
 */
int lc_drbg_hash_alloc(struct lc_rng_ctx **drbg);

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
int lc_drbg_hash_healthcheck_sanity(struct lc_rng_ctx *drbg);

#ifdef __cplusplus
}
#endif

#endif /* LC_HASH_DRBG_H */
