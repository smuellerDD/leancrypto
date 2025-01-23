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

#ifndef LC_HASH_CRYPT_H
#define LC_HASH_CRYPT_H

#include "lc_aead.h"
/*
 * This is the hash crypt cipher operation using the Hash DRBG with SHA-512
 * core as input.
 */
#include "lc_hash_drbg.h"
#include "lc_hmac.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
/*
 * The block size of the algorithm for generating the key stream. The min DRBG
 * generate size is larger. This implies that there is no DRBG update operation
 * while the key stream for one block is generated.
 */
#define LC_HC_KEYSTREAM_BLOCK 64

struct lc_hc_cryptor {
	struct lc_rng_ctx drbg;
	uint8_t drbg_state[LC_DRBG_HASH_STATE_SIZE];
	struct lc_hmac_ctx auth_ctx;
	size_t keystream_ptr;
	uint8_t keystream[LC_HC_KEYSTREAM_BLOCK];
};

#define LC_HC_CTX_SIZE(x)                                                      \
	(sizeof(struct lc_aead) + sizeof(struct lc_hc_cryptor) +               \
	 LC_HMAC_STATE_SIZE(x))

/* Hash-based AEAD-algorithm */
extern const struct lc_aead *lc_hash_aead;

#define _LC_HC_SET_CTX(name, hashname)                                         \
	LC_DRBG_HASH_RNG_CTX((&name->drbg));                                   \
	_LC_HMAC_SET_CTX((&name->auth_ctx), hashname, name,                    \
			 (sizeof(struct lc_hc_cryptor)))

#define LC_HC_SET_CTX(name, hashname)                                          \
	LC_AEAD_CTX(name, lc_hash_aead);                                       \
	_LC_HC_SET_CTX(((struct lc_hc_cryptor *)name->aead_state), hashname)
/// \endcond

/**
 * @brief Return maximum size of authentication tag
 *
 * @param [in] hc Hash cryptor context handle
 *
 * @return size of tag
 */
static inline size_t lc_hc_get_tagsize(struct lc_hc_cryptor *hc)
{
	struct lc_hmac_ctx *auth_ctx = &hc->auth_ctx;

	return lc_hmac_macsize(auth_ctx);
}

/**
 * @brief Allocate Hash cryptor context on heap
 *
 * @param [in] hash Hash implementation of type struct hash used for the HMAC
 *		    authentication
 * @param [out] ctx Allocated hash cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_hc_alloc(const struct lc_hash *hash, struct lc_aead_ctx **ctx);

/**
 * @brief Allocate stack memory for the hash cryptor context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hash Hash implementation of type struct hash used for the HMAC
 *		    authentication
 */
#define LC_HC_CTX_ON_STACK(name, hash)                                              \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_HC_CTX_SIZE(hash),                     \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_aead_ctx *name = (struct lc_aead_ctx *)name##_ctx_buf;            \
	LC_HC_SET_CTX(name, hash);                                                  \
	lc_aead_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_HASH_CRYPT_H */
