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

#ifndef LC_KMAC_H
#define LC_KMAC_H

#include "lc_hash.h"
#include "lc_sha3.h"
#include "memset_secure.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_kmac_ctx {
	uint8_t *shadow_ctx;
	struct lc_hash_ctx hash_ctx;
};

#define LC_KMAC_STATE_SIZE(x)		(LC_HASH_STATE_SIZE(x))
#define LC_KMAC_STATE_SIZE_REINIT(x)	(2 * LC_HASH_STATE_SIZE(x))
#define LC_KMAC_CTX_SIZE(x)		(LC_KMAC_STATE_SIZE(x) + 	       \
					 sizeof(struct lc_kmac_ctx))
#define LC_KMAC_CTX_SIZE_REINIT(x)	(LC_KMAC_STATE_SIZE_REINIT(x) +	       \
					 sizeof(struct lc_kmac_ctx))

#define _LC_KMAC_SET_CTX(name, hashname, ctx, offset)			       \
	_LC_HASH_SET_CTX((&name->hash_ctx), hashname, ctx, offset);	       \
        name->shadow_ctx = NULL

#define LC_KMAC_SET_CTX(name, hashname)					       \
	_LC_KMAC_SET_CTX(name, hashname, name, sizeof(struct lc_kmac_ctx))

#define _LC_KMAC_SET_CTX_REINIT(name, hashname, ctx, offset)		       \
	_LC_HASH_SET_CTX((&name->hash_ctx), hashname, name, offset);	       \
        name->shadow_ctx = (uint8_t *)((uint8_t *)ctx + offset +	       \
				       LC_HASH_STATE_SIZE(hashname))

#define LC_KMAC_SET_CTX_REINIT(name, hashname)				       \
	_LC_KMAC_SET_CTX_REINIT(name, hashname, name,			       \
				sizeof(struct lc_kmac_ctx))

/**
 * @brief Initialize KMAC context
 *
 * @param kmac_ctx [in] Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param key [in] MAC key of arbitrary size
 * @param klen [in] Size of the MAC key
 * @param s [in] Optional customization string - if not needed, use NULL
 * @param slen [in] Size of s
 *
 * The caller must provide an allocated kmac_ctx. This can be achieved by
 * using KMAC_CTX_ON_STACK or by using kmac_alloc.
 */
void lc_kmac_init(struct lc_kmac_ctx *kmac_ctx,
		  const uint8_t *key, size_t klen,
		  const uint8_t *s, size_t slen);

/**
 * @brief Re-initialize KMAC context after a kmac_final operation
 *
 * This operation allows the KMAC context to be used again with the same key
 * set during kmac_init.
 *
 * @param kmac_ctx [in] Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 */
void lc_kmac_reinit(struct lc_kmac_ctx *kmac_ctx);

/**
 * @brief Update KMAC
 *
 * @param kmac_ctx [in] Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param in [in] Buffer holding the data whose MAC shall be calculated
 * @param inlen [in] Length of the input buffer
 */
void lc_kmac_update(struct lc_kmac_ctx *kmac_ctx,
		    const uint8_t *in, size_t inlen);

/**
 * @brief Calculate KMAC MAC
 *
 * If the cipher handle shall be used for a new KMAC operation with the same
 * key after this call, you MUST re-initialize the handle with kmac_reinit.
 *
 * @param kmac_ctx [in] Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param mac [out] Buffer with at least the size of the message digest that
 *		    is returned by kmac_macsize.
 * @param maclen [in] Size of the requested MAC
 */
void lc_kmac_final(struct lc_kmac_ctx *kmac_ctx, uint8_t *mac, size_t maclen);

/**
 * @brief Calculate KMAC MAC in XOF mode
 *
 * If the cipher handle shall be used for a new KMAC operation with the same
 * key after this call, you MUST re-initialize the handle with kmac_reinit.
 *
 * @param kmac_ctx [in] Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param mac [out] Buffer to hold the message digest
 * @param maclen [in] Size of the requested MAC
 */
void lc_kmac_final_xof(struct lc_kmac_ctx *kmac_ctx,
		       uint8_t *mac, size_t maclen);

/**
 * @brief Get more message digest from the KMAC operation
 *
 * This call is intended to be invoked after the lc_kmac_final_xof. It generates
 * more message digest.
 *
 * E.g. the following calls are equal:
 *
 * size_t maclen = LC_SHA3_256_SIZE_BLOCK * 3 + 5;
 *
 * `lc_kmac_final_xof(ctx, mac, maclen);`
 *
 * and
 *
 * ```
 * lc_kmac_final_xof(ctx, mac, LC_SHA3_256_SIZE_BLOCK + 1);
 * lc_kmac_final_xof_more(ctx, mac + LC_SHA3_256_SIZE_BLOCK + 1,
 *			  2 * LC_SHA3_256_SIZE_BLOCK + 1);
 * lc_kmac_final_xof_more(ctx, mac + 3 * LC_SHA3_256_SIZE_BLOCK + 2, 3);
 * ```
 *
 * @param kmac_ctx [in] Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param mac [out] Buffer to hold the message digest
 * @param maclen [in] Size of the requested MAC
 */
void lc_kmac_final_xof_more(struct lc_kmac_ctx *kmac_ctx, uint8_t *mac,
			    size_t maclen);

/**
 * @brief Allocate KMAC context on heap
 *
 * NOTE: This is defined for cshake256 as of now.
 *
 * @param hash [in] Reference to hash implementation to be used to perform
 *		    KMAC calculation with. Use cshake256!
 * @param kmac_ctx [out] Allocated KMAC context
 * @param flags [in] Zero or more of the flags defined below
 *
 * @return 0 on success, < 0 on error
 */
int lc_kmac_alloc(const struct lc_hash *hash, struct lc_kmac_ctx **kmac_ctx,
		  uint32_t flags);

/*
 * Support re-initialization of state. You set a key during kmac_init,
 * perform a full KMAC operation. After a kmac_final, the re-initialization
 * support allows you to call kmac_reinit and reuse the state for a new
 * operation without providing the keys again. If in doubt, initialize
 * the context with re-init support. The difference is that more memory is
 * allocated to retain the initialized state.
 */
#define LC_KMAC_FLAGS_SUPPORT_REINIT	(1 << 0)

/**
 * @brief Zeroize and free KMAC context
 *
 * @param kmac_ctx [in] KMAC context to be zeroized and freed
 */
void lc_kmac_zero_free(struct lc_kmac_ctx *kmac_ctx);

/**
 * @brief Zeroize KMAC context allocated with either LC_KMAC_CTX_ON_STACK or
 *	  lc_kmac_alloc
 *
 * @param kmac_ctx [in] KMAC context to be zeroized
 */
static inline void lc_kmac_zero(struct lc_kmac_ctx *kmac_ctx)
{
	struct lc_hash_ctx *hash_ctx = &kmac_ctx->hash_ctx;
	const struct lc_hash *hash = hash_ctx->hash;

	memset_secure((uint8_t *)kmac_ctx + sizeof(struct lc_kmac_ctx), 0,
		      kmac_ctx->shadow_ctx ? LC_KMAC_STATE_SIZE_REINIT(hash) :
					     LC_KMAC_STATE_SIZE(hash));
}

/**
 * @brief Allocate stack memory for the KMAC context
 *
 * This allocates the memory without re-initialization support
 *
 * NOTE: This is defined for lc_cshake256 as of now.
 *
 * @param name [in] Name of the stack variable - use cshake256!
 * @param hashname [in] Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_KMAC_CTX_ON_STACK(name, hashname)				       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_KMAC_CTX_SIZE(hashname),	       \
			  uint64_t);					       \
	struct lc_kmac_ctx *name = (struct lc_kmac_ctx *)name ## _ctx_buf;     \
	LC_KMAC_SET_CTX(name, hashname);				       \
	lc_kmac_zero(name)

/**
 * @brief Allocate stack memory for the KMAC context
 *
 * This allocates the memory with re-initialization support.
 * See KMAC_FLAGS_SUPPORT_REINIT for the explanation about re-initialization.
 *
 * NOTE: This is defined for cshake256 as of now.
 *
 * @param name [in] Name of the stack variable - use cshake256!
 * @param hashname [in] Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_KMAC_CTX_ON_STACK_REINIT(name, hashname)			       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_KMAC_CTX_SIZE_REINIT(hashname), \
			  uint64_t);					       \
	struct lc_kmac_ctx *name = (struct lc_kmac_ctx *)name ## _ctx_buf;     \
	LC_KMAC_SET_CTX_REINIT(name, hashname);				       \
	lc_kmac_zero(name)

/**
 * @brief Return the MAC size
 *
 * @param kmac_ctx [in] KMAC context to be zeroized
 *
 * @return MAC size
 */
static inline size_t lc_kmac_macsize(struct lc_kmac_ctx *kmac_ctx)
{
	struct lc_hash_ctx *hash_ctx = &kmac_ctx->hash_ctx;

	return lc_hash_digestsize(hash_ctx);
}

/**
 * @brief Calculate KMAC - one-shot
 *
 * NOTE: This is defined for cshake256 as of now.
 *
 * @param hash [in] Reference to hash implementation to be used to perform
 *		    KMAC calculation with. Use cshake256!
 * @param key [in] MAC key of arbitrary size
 * @param keylen [in] Size of the MAC key
 * @param in [in] Buffer holding the data whose MAC shall be calculated
 * @param inlen [in] Length of the input buffer
 * @param s [in] Optional customization string - if not needed, use NULL
 * @param slen [in] Size of s
 * @param mac [out] Buffer with at least the size of the message digest.
 * @param maclen [in] Size of the requested MAC
 *
 * The KMAC calculation operates entirely on the stack.
 */
static inline void lc_kmac(const struct lc_hash *hash,
			   const uint8_t *key, size_t keylen,
			   const uint8_t *s, size_t slen,
			   const uint8_t *in, size_t inlen,
			   uint8_t *mac, size_t maclen)
{
	   LC_KMAC_CTX_ON_STACK(kmac_ctx, hash);

	   lc_kmac_init(kmac_ctx, key, keylen, s, slen);
	   lc_kmac_update(kmac_ctx, in, inlen);
	   lc_kmac_final(kmac_ctx, mac, maclen);

	   lc_kmac_zero(kmac_ctx);
}

/**
 * @brief Calculate KMAC in XOF mode - one-shot
 *
 * NOTE: This is defined for cshake256 as of now.
 *
 * @param hash [in] Reference to hash implementation to be used to perform
 *		    KMAC calculation with. Use cshake256!
 * @param key [in] MAC key of arbitrary size
 * @param keylen [in] Size of the MAC key
 * @param in [in] Buffer holding the data whose MAC shall be calculated
 * @param inlen [in] Length of the input buffer
 * @param s [in] Optional customization string - if not needed, use NULL
 * @param slen [in] Size of s
 * @param mac [out] Buffer with at least the size of the message digest.
 * @param maclen [in] Size of the requested MAC
 *
 * The KMAC calculation operates entirely on the stack.
 */
static inline void lc_kmac_xof(const struct lc_hash *hash,
			       const uint8_t *key, size_t keylen,
			       const uint8_t *s, size_t slen,
			       const uint8_t *in, size_t inlen,
			       uint8_t *mac, size_t maclen)
{
	   LC_KMAC_CTX_ON_STACK(kmac_ctx, hash);

	   lc_kmac_init(kmac_ctx, key, keylen, s, slen);
	   lc_kmac_update(kmac_ctx, in, inlen);
	   lc_kmac_final_xof(kmac_ctx, mac, maclen);

	   lc_kmac_zero(kmac_ctx);
}


#ifdef __cplusplus
}
#endif

#endif /* LC_KMAC_H */
