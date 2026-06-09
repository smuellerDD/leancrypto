/*
 * Copyright (C) 2020 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_HMAC_H
#define LC_HMAC_H

#include "lc_hash.h"
#include "lc_sha3.h"
#include "lc_status.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
#if LC_SHA3_MAX_SIZE_BLOCK
#define LC_SHA_MAX_SIZE_BLOCK LC_SHA3_MAX_SIZE_BLOCK
#define LC_HMAC_STATE_SIZE_HASH LC_SHA3_224_STATE_SIZE
#elif LC_SHA512_SIZE_BLOCK
#define LC_SHA_MAX_SIZE_BLOCK LC_SHA512_SIZE_BLOCK
#define LC_HMAC_STATE_SIZE_HASH LC_SHA512_STATE_SIZE
#elif LC_SHA256_SIZE_BLOCK
#define LC_SHA_MAX_SIZE_BLOCK LC_SHA256_SIZE_BLOCK
#define LC_HMAC_STATE_SIZE_HASH LC_SHA256_STATE_SIZE
#else
#error "No known maximum block size defined - include sha3.h, sha512.h or sha256.h before hmac.h"
#endif

struct lc_hmac_key {
	uint8_t k_opad[LC_SHA_MAX_SIZE_BLOCK];
	uint8_t k_ipad[LC_SHA_MAX_SIZE_BLOCK];
};

struct lc_hmac_ctx {
	struct lc_hash_ctx hash_ctx;
	const struct lc_hmac_key *key;
};

#define LC_HMAC_KEY_SIZE (sizeof(struct lc_hmac_key))

#define LC_HMAC_STATE_SIZE (sizeof(struct lc_hmac_ctx) + LC_HMAC_KEY_SIZE)
#define LC_HMAC_CTX_SIZE (LC_HMAC_STATE_SIZE)

#define _LC_HMAC_SET_CTX(name, hashname, ctx, offset)                          \
	_LC_HASH_SET_CTX((&name->hash_ctx), hashname);                         \
	name->key = (struct lc_hmac_key *)((uint8_t *)ctx + offset)

#define LC_HMAC_SET_CTX(name, hashname)                                        \
	_LC_HMAC_SET_CTX(name, hashname, name, sizeof(struct lc_hmac_ctx))
/// \endcond

/**
 * @defgroup HMAC HMAC Keyed Message Digest
 */

/**
 * @ingroup HMAC
 * @brief Initialize HMAC context
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param [in] key MAC key of arbitrary size
 * @param [in] keylen Size of the MAC key
 *
 * The caller must provide an allocated hmac_ctx. This can be achieved by
 * using HMAC_CTX_ON_STACK or by using hmac_alloc.
 *
 * @return 0 on success; < 0 on error
 */
int lc_hmac_init(struct lc_hmac_ctx *hmac_ctx, const uint8_t *key,
		 size_t keylen);

/**
 * @ingroup HMAC
 * @brief Re-initialize HMAC context after a hmac_final operation
 *
 * This operation allows the HMAC context to be used again with the same key
 * set during hmac_init.
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 */
void lc_hmac_reinit(struct lc_hmac_ctx *hmac_ctx);

/**
 * @ingroup HMAC
 * @brief Initialize HMAC key context
 *
 * This key context takes in the key and processes them to make them usable
 * as HMAC keys. Yet, the caller can keep the \p hmac_key structure a const
 * after this call.
 *
 * @param [out] hmac_key Structure to fill with the processed key
 * @param [in] hash Hash type
 * @param [in] key MAC key of arbitrary size
 * @param [in] keylen Size of the MAC key
 *
 * @return 0 on success; < 0 on error
 */
int lc_hmac_setkey(struct lc_hmac_key *hmac_key, const struct lc_hash *hash,
		   const uint8_t *key, size_t keylen);

/**
 * @ingroup HMAC
 * @brief Initialize HMAC context with preprocessed key
 *
 * The \p hmac_key structure must be initialized with \p lc_hmac_setkey. The
 * caller must keep the \p hmac_key accessible for the duration of \p hmac_ctx.
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param [in] hmac_key Pre-processed HMAC key
 *
 * The caller must provide an allocated hmac_ctx. This can be achieved by
 * using HMAC_CTX_ON_STACK or by using hmac_alloc.
 *
 * @return 0 on success; < 0 on error
 */
int lc_hmac_init_with_hmac_key(struct lc_hmac_ctx *hmac_ctx,
			       const struct lc_hmac_key *hmac_key);

/**
 * @ingroup HMAC
 * @brief Update HMAC
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 */
void lc_hmac_update(struct lc_hmac_ctx *hmac_ctx, const uint8_t *in,
		    size_t inlen);

/**
 * @ingroup HMAC
 * @brief Calculate HMAC mac
 *
 * If the cipher handle shall be used for a new HMAC operation with the same
 * key after this call, you MUST re-initialize the handle with hmac_reinit.
 *
 * @param [in] hmac_ctx Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param [out] mac Buffer with at least the size of the message digest that
 *		    is returned by hmac_macsize.
 */
void lc_hmac_final(struct lc_hmac_ctx *hmac_ctx, uint8_t *mac);

/**
 * @ingroup HMAC
 * @brief Allocate HMAC context on heap
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    HMAC calculation with.
 * @param [out] hmac_ctx Allocated HMAC context
 *
 * @return 0 on success, < 0 on error
 */
int lc_hmac_alloc(const struct lc_hash *hash, struct lc_hmac_ctx **hmac_ctx);

/**
 * @ingroup HMAC
 * @brief Zeroize and free HMAC context
 *
 * \warning If a caller used \p lc_hmac_init_with_hmac_key to provide a separate
 * storage for the key, the zeroization does NOT clear the key buffer to allow
 * it to be reused. The caller is responsible to clear it.
 *
 * @param [in] hmac_ctx HMAC context to be zeroized and freed
 */
void lc_hmac_zero_free(struct lc_hmac_ctx *hmac_ctx);

/**
 * @ingroup HMAC
 * @brief Zeroize HMAC context allocated with either HMAC_CTX_ON_STACK or
 *	  hmac_alloc
 *
 * \warning If a caller used \p lc_hmac_init_with_hmac_key to provide a separate
 * storage for the key, the zeroization does NOT clear the key buffer to allow
 * it to be reused. The caller is responsible to clear it.
 *
 * @param [in] hmac_ctx HMAC context to be zeroized
 */
void lc_hmac_zero(struct lc_hmac_ctx *hmac_ctx);

/**
 * @ingroup HMAC
 * @brief Obtain algorithm status
 *
 * @param [in] hash Hash algorithm instance
 *
 * @return algorithm status
 */
enum lc_alg_status_val lc_hmac_alg_status(const struct lc_hash *hash);

/**
 * @ingroup HMAC
 * @brief Obtain algorithm status
 *
 * @param [in] ctx Hash context handle
 *
 * @return algorithm status
 */
enum lc_alg_status_val lc_hmac_ctx_alg_status(const struct lc_hash_ctx *ctx);

/**
 * @ingroup HMAC
 * @brief Allocate stack memory for the HMAC context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hashname Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_HMAC_CTX_ON_STACK(name, hashname)                                   \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		_Pragma("GCC diagnostic ignored \"-Wcast-align\"")             \
			LC_ALIGNED_BUFFER(name##_ctx_buf, LC_HMAC_CTX_SIZE,    \
					  LC_HASH_COMMON_ALIGNMENT);           \
	struct lc_hmac_ctx *name = (struct lc_hmac_ctx *)name##_ctx_buf;       \
	LC_HMAC_SET_CTX(name, hashname);                                       \
	lc_hmac_zero(name);                                                    \
	_Pragma("GCC diagnostic pop")

/**
 * @ingroup HMAC
 * @brief Return the MAC size
 *
 * @param [in] hmac_ctx HMAC context to be zeroized
 *
 * @return MAC size
 */
size_t lc_hmac_macsize(struct lc_hmac_ctx *hmac_ctx);

/**
 * @ingroup HMAC
 * @brief Calculate HMAC - one-shot
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    HMAC calculation with.
 * @param [in] key MAC key of arbitrary size
 * @param [in] keylen Size of the MAC key
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 * @param [out] mac Buffer with at least the size of the message digest.
 *
 * The HMAC calculation operates entirely on the stack.
 *
 * @return 0 on success; < 0 on error
 */
int lc_hmac(const struct lc_hash *hash, const uint8_t *key, size_t keylen,
	    const uint8_t *in, size_t inlen, uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif /* LC_HMAC_H */
