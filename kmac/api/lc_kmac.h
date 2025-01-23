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

#ifndef LC_KMAC_H
#define LC_KMAC_H

#include "lc_hash.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_kmac_ctx {
	uint8_t final_called : 1;
	uint8_t rng_initialized : 1;
	uint8_t *shadow_ctx;
	struct lc_hash_ctx hash_ctx;
};

#define LC_KMAC_STATE_SIZE(x) (LC_HASH_STATE_SIZE(x))
#define LC_KMAC_STATE_SIZE_REINIT(x) (2 * LC_HASH_STATE_SIZE(x))
#define LC_KMAC_CTX_SIZE(x) (LC_KMAC_STATE_SIZE(x) + sizeof(struct lc_kmac_ctx))
#define LC_KMAC_CTX_SIZE_REINIT(x)                                             \
	(LC_KMAC_STATE_SIZE_REINIT(x) + sizeof(struct lc_kmac_ctx))

#define _LC_KMAC_SET_CTX(name, hashname, ctx, offset)                          \
	_LC_HASH_SET_CTX((&name->hash_ctx), hashname, ctx, offset);            \
	name->shadow_ctx = NULL

#define LC_KMAC_SET_CTX(name, hashname)                                        \
	_LC_KMAC_SET_CTX(name, hashname, name, sizeof(struct lc_kmac_ctx))

#define _LC_KMAC_SET_CTX_REINIT(name, hashname, ctx, offset)                   \
	_LC_HASH_SET_CTX((&name->hash_ctx), hashname, ctx, offset);            \
	name->shadow_ctx = (uint8_t *)((uint8_t *)ctx + offset +               \
				       LC_HASH_STATE_SIZE(hashname))

#define LC_KMAC_SET_CTX_REINIT(name, hashname)                                 \
	_LC_KMAC_SET_CTX_REINIT(name, hashname, name,                          \
				sizeof(struct lc_kmac_ctx))
/// \endcond

/**
 * @brief Initialize KMAC context
 *
 * @param [in] kmac_ctx Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param [in] key MAC key of arbitrary size
 * @param [in] klen Size of the MAC key
 * @param [in] s Optional customization string - if not needed, use NULL
 * @param [in] slen Size of s
 *
 * The caller must provide an allocated kmac_ctx. This can be achieved by
 * using KMAC_CTX_ON_STACK or by using kmac_alloc.
 */
void lc_kmac_init(struct lc_kmac_ctx *kmac_ctx, const uint8_t *key, size_t klen,
		  const uint8_t *s, size_t slen);

/**
 * @brief Re-initialize KMAC context after a kmac_final operation
 *
 * This operation allows the KMAC context to be used again with the same key
 * set during kmac_init.
 *
 * @param [in] kmac_ctx Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 */
void lc_kmac_reinit(struct lc_kmac_ctx *kmac_ctx);

/**
 * @brief Update KMAC
 *
 * @param [in] kmac_ctx Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 */
void lc_kmac_update(struct lc_kmac_ctx *kmac_ctx, const uint8_t *in,
		    size_t inlen);

/**
 * @brief Calculate KMAC MAC
 *
 * If the cipher handle shall be used for a new KMAC operation with the same
 * key after this call, you MUST re-initialize the handle with kmac_reinit.
 *
 * @param [in] kmac_ctx Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param [out] mac Buffer with at least the size of the message digest that
 *		    is returned by kmac_macsize.
 * @param [in] maclen Size of the requested MAC
 */
void lc_kmac_final(struct lc_kmac_ctx *kmac_ctx, uint8_t *mac, size_t maclen);

/**
 * @brief Calculate KMAC MAC in XOF mode
 *
 * If the cipher handle shall be used for a new KMAC operation with the same
 * key after this call, you MUST re-initialize the handle with kmac_reinit.
 *
 * This call is can be to be invoked multiple times It generates more message
 * digest.
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
 * lc_kmac_final_xof(ctx, mac + LC_SHA3_256_SIZE_BLOCK + 1,
 *			  2 * LC_SHA3_256_SIZE_BLOCK + 1);
 * lc_kmac_final_xof(ctx, mac + 3 * LC_SHA3_256_SIZE_BLOCK + 2, 3);
 * ```
 *
 * @param [in] kmac_ctx Reference to kmac context implementation to be used to
 *			perform KMAC calculation with.
 * @param [out] mac Buffer to hold the message digest
 * @param [in] maclen Size of the requested MAC
 */
void lc_kmac_final_xof(struct lc_kmac_ctx *kmac_ctx, uint8_t *mac,
		       size_t maclen);

/**
 * @brief Allocate KMAC context on heap
 *
 * NOTE: This is defined for cshake256 as of now.
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    KMAC calculation with. Use cshake256!
 * @param [out] kmac_ctx Allocated KMAC context
 * @param [in] flags Zero or more of the flags defined below
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
#define LC_KMAC_FLAGS_SUPPORT_REINIT (1 << 0)

/**
 * @brief Zeroize and free KMAC context
 *
 * @param [in] kmac_ctx KMAC context to be zeroized and freed
 */
void lc_kmac_zero_free(struct lc_kmac_ctx *kmac_ctx);

/**
 * @brief Zeroize KMAC context allocated with either LC_KMAC_CTX_ON_STACK or
 *	  lc_kmac_alloc
 *
 * @param [in] kmac_ctx KMAC context to be zeroized
 */
void lc_kmac_zero(struct lc_kmac_ctx *kmac_ctx);

/**
 * @brief Allocate stack memory for the KMAC context
 *
 * This allocates the memory without re-initialization support
 *
 * @param [in] name Name of the stack variable - use lc_cshake256 or
 *		    lc_cshake128
 * @param [in] hashname Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_KMAC_CTX_ON_STACK(name, hashname)                                        \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_KMAC_CTX_SIZE(hashname),               \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_kmac_ctx *name = (struct lc_kmac_ctx *)name##_ctx_buf;            \
	LC_KMAC_SET_CTX(name, hashname);                                            \
	lc_kmac_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocate stack memory for the KMAC context
 *
 * This allocates the memory with re-initialization support.
 * See KMAC_FLAGS_SUPPORT_REINIT for the explanation about re-initialization.
 *
 * @param [in] name Name of the stack variable - use lc_cshake256 or
 *		    lc_cshake128
 * @param [in] hashname Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_KMAC_CTX_ON_STACK_REINIT(name, hashname)                                 \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_KMAC_CTX_SIZE_REINIT(hashname),        \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_kmac_ctx *name = (struct lc_kmac_ctx *)name##_ctx_buf;            \
	LC_KMAC_SET_CTX_REINIT(name, hashname);                                     \
	lc_kmac_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Return the MAC size
 *
 * @param [in] kmac_ctx KMAC context
 *
 * @return MAC size
 */
size_t lc_kmac_macsize(struct lc_kmac_ctx *kmac_ctx);

/**
 * @brief Calculate KMAC - one-shot
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    KMAC calculation with. Use lc_cshake256 or lc_cshake128.
 * @param [in] key MAC key of arbitrary size
 * @param [in] keylen Size of the MAC key
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 * @param [in] s Optional customization string - if not needed, use NULL
 * @param [in] slen Size of s
 * @param [out] mac Buffer with at least the size of the message digest.
 * @param [in] maclen Size of the requested MAC
 *
 * The KMAC calculation operates entirely on the stack.
 */
void lc_kmac(const struct lc_hash *hash, const uint8_t *key, size_t keylen,
	     const uint8_t *s, size_t slen, const uint8_t *in, size_t inlen,
	     uint8_t *mac, size_t maclen);

/**
 * @brief Calculate KMAC in XOF mode - one-shot
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    KMAC calculation with. Use lc_cshake256 or lc_cshake128.
 * @param [in] key MAC key of arbitrary size
 * @param [in] keylen Size of the MAC key
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 * @param [in] s Optional customization string - if not needed, use NULL
 * @param [in] slen Size of s
 * @param [out] mac Buffer with at least the size of the message digest.
 * @param [in] maclen Size of the requested MAC
 *
 * The KMAC calculation operates entirely on the stack.
 */
void lc_kmac_xof(const struct lc_hash *hash, const uint8_t *key, size_t keylen,
		 const uint8_t *s, size_t slen, const uint8_t *in, size_t inlen,
		 uint8_t *mac, size_t maclen);

/******************************** KMAC as RNG *********************************/

/*
 * The KMAC can be used as an RNG context for aggregated algorithms like
 * Kyber or Dilithium. The idea is that KMAC acts as a key derivation function
 * whose state can be initialized from an input data to deterministically derive
 * the values required for the algorithms the RNG context is used with.
 *
 * This RNG state is NOT intended to serve as a general-purpose deterministic
 * random number generator. For using KMAC as a such general-purpose DRNG, see
 * the API provided with lc_kmac256_drng.h.
 */

/* KMAC DRNG implementation */
extern const struct lc_rng *lc_kmac_rng;

#define LC_KMAC_KDF_DRNG_CTX_SIZE(hashname)                                    \
	(sizeof(struct lc_rng_ctx) + LC_KMAC_CTX_SIZE(hashname))

#define LC_KMAC_KDF_DRNG_SET_CTX(name, hashname) LC_KMAC_SET_CTX(name, hashname)

#define LC_KMAC_KDF_RNG_CTX(name, hashname)                                    \
	LC_RNG_CTX(name, lc_kmac_rng);                                         \
	LC_KMAC_KDF_DRNG_SET_CTX(((struct lc_kmac_ctx *)(name->rng_state)),    \
				 hashname);                                    \
	lc_rng_zero(name)

/**
 * @brief Allocate stack memory for the KMAC DRNG context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hashname Reference to lc_hash implementation - use lc_cshake256
 *			or lc_cshake128.
 */
#define LC_KMAC_KDF_DRNG_CTX_ON_STACK(name, hashname)                               \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_KMAC_KDF_DRNG_CTX_SIZE(hashname),      \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;              \
	LC_KMAC_KDF_RNG_CTX(name, hashname);                                        \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocation of a KMAC DRNG context
 *
 * @param [out] state KMAC DRNG context allocated by the function
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    RNG operation with. Use lc_cshake256 or lc_cshake128.
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * You need to seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_kmac_rng_alloc(struct lc_rng_ctx **state, const struct lc_hash *hash);

#ifdef __cplusplus
}
#endif

#endif /* LC_KMAC_H */
