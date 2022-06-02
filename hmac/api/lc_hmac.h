/*
 * Copyright (C) 2020 - 2021, Stephan Mueller <smueller@chronox.de>
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
#include "memset_secure.h"

#ifdef __cplusplus
extern "C"
{
#endif

#if LC_SHA3_MAX_SIZE_BLOCK
# define LC_SHA_MAX_SIZE_BLOCK	LC_SHA3_MAX_SIZE_BLOCK
#elif LC_SHA512_SIZE_BLOCK
# define LC_SHA_MAX_SIZE_BLOCK	LC_SHA512_SIZE_BLOCK
#elif LC_SHA256_SIZE_BLOCK
# define LC_SHA_MAX_SIZE_BLOCK	LC_SHA256_SIZE_BLOCK
#else
# error "No known maximum block size defined - include sha3.h, sha512.h or sha256.h before hmac.h"
#endif

struct lc_hmac_ctx {
	uint8_t *k_opad;
	uint8_t *k_ipad;
	struct lc_hash_ctx hash_ctx;
};

#define LC_HMAC_STATE_SIZE(x)		(LC_HASH_STATE_SIZE(x) +	       \
					 2 * LC_SHA_MAX_SIZE_BLOCK)
#define LC_HMAC_CTX_SIZE(x)		(LC_HMAC_STATE_SIZE(x) +	       \
					 sizeof(struct lc_hmac_ctx))

#define _LC_HMAC_SET_CTX(name, hashname, ctx, offset)			       \
	_LC_HASH_SET_CTX((&name->hash_ctx), hashname, ctx, offset);	       \
        name->k_opad = (uint8_t *)((uint8_t *)ctx + offset +		       \
				   LC_HASH_STATE_SIZE(hashname));	       \
	name->k_ipad = (uint8_t *)((uint8_t *)ctx + offset +		       \
				   LC_HASH_STATE_SIZE(hashname) +	       \
				   LC_SHA_MAX_SIZE_BLOCK)


#define LC_HMAC_SET_CTX(name, hashname)					       \
	_LC_HMAC_SET_CTX(name, hashname, name, sizeof(struct lc_hmac_ctx))

/**
 * @brief Initialize HMAC context
 *
 * @param hmac_ctx [in] Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param key [in] MAC key of arbitrary size
 * @param keylen [in] Size of the MAC key
 *
 * The caller must provide an allocated hmac_ctx. This can be achieved by
 * using HMAC_CTX_ON_STACK or by using hmac_alloc.
 */
void lc_hmac_init(struct lc_hmac_ctx *hmac_ctx,
		  const uint8_t *key, size_t keylen);

/**
 * @brief Re-initialize HMAC context after a hmac_final operation
 *
 * This operation allows the HMAC context to be used again with the same key
 * set during hmac_init.
 *
 * @param hmac_ctx [in] Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 */
void lc_hmac_reinit(struct lc_hmac_ctx *hmac_ctx);

/**
 * @brief Update HMAC
 *
 * @param hmac_ctx [in] Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param in [in] Buffer holding the data whose MAC shall be calculated
 * @param inlen [in] Length of the input buffer
 */
void lc_hmac_update(struct lc_hmac_ctx *hmac_ctx,
		    const uint8_t *in, size_t inlen);

/**
 * @brief Calculate HMAC mac
 *
 * If the cipher handle shall be used for a new HMAC operation with the same
 * key after this call, you MUST re-initialize the handle with hmac_reinit.
 *
 * @param hmac_ctx [in] Reference to hmac context implementation to be used to
 *			perform HMAC calculation with.
 * @param mac [out] Buffer with at least the size of the message digest that
 *		    is returned by hmac_macsize.
 */
void lc_hmac_final(struct lc_hmac_ctx *hmac_ctx, uint8_t *mac);

/**
 * @brief Allocate HMAC context on heap
 *
 * @param hash [in] Reference to hash implementation to be used to perform
 *		    HMAC calculation with.
 * @param hmac_ctx [out] Allocated HMAC context
 *
 * @return 0 on success, < 0 on error
 */
int lc_hmac_alloc(const struct lc_hash *hash, struct lc_hmac_ctx **hmac_ctx);

/**
 * @brief Zeroize and free HMAC context
 *
 * @param hmac_ctx [in] HMAC context to be zeroized and freed
 */
void lc_hmac_zero_free(struct lc_hmac_ctx *hmac_ctx);

/**
 * @brief Zeroize HMAC context allocated with either HMAC_CTX_ON_STACK or
 *	  hmac_alloc
 *
 * @param hmac_ctx [in] HMAC context to be zeroized
 */
static inline void lc_hmac_zero(struct lc_hmac_ctx *hmac_ctx)
{
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	const struct lc_hash *hash = hash_ctx->hash;

	memset_secure((uint8_t *)hmac_ctx + sizeof(struct lc_hmac_ctx), 0,
		      LC_HMAC_STATE_SIZE(hash));
}

/**
 * @brief Allocate stack memory for the HMAC context
 *
 * @param name [in] Name of the stack variable
 * @param hashname [in] Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_HMAC_CTX_ON_STACK(name, hashname)				       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_HMAC_CTX_SIZE(hashname),	       \
			  uint64_t);					       \
	struct lc_hmac_ctx *name = (struct lc_hmac_ctx *)name ## _ctx_buf;     \
	LC_HMAC_SET_CTX(name, hashname);				       \
	lc_hmac_zero(name)

/**
 * @brief Return the MAC size
 *
 * @param hmac_ctx [in] HMAC context to be zeroized
 *
 * @return MAC size
 */
static inline size_t lc_hmac_macsize(struct lc_hmac_ctx *hmac_ctx)
{
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;

	return lc_hash_digestsize(hash_ctx);
}

/**
 * @brief Calculate HMAC - one-shot
 *
 * @param hash [in] Reference to hash implementation to be used to perform
 *		    HMAC calculation with.
 * @param key [in] MAC key of arbitrary size
 * @param keylen [in] Size of the MAC key
 * @param in [in] Buffer holding the data whose MAC shall be calculated
 * @param inlen [in] Length of the input buffer
 * @param mac [out] Buffer with at least the size of the message digest.
 *
 * The HMAC calculation operates entirely on the stack.
 */
static inline void lc_hmac(const struct lc_hash *hash,
			   const uint8_t *key, size_t keylen,
			   const uint8_t *in, size_t inlen,
			   uint8_t *mac)
{
	   LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);

	   lc_hmac_init(hmac_ctx, key, keylen);
	   lc_hmac_update(hmac_ctx, in, inlen);
	   lc_hmac_final(hmac_ctx, mac);

	   lc_hmac_zero(hmac_ctx);
}

#ifdef __cplusplus
}
#endif

#endif /* LC_HMAC_H */
