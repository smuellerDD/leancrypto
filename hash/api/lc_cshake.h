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

#ifndef LC_CSHAKE_H
#define LC_CSHAKE_H

#include "lc_hash.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the hash state following the cSHAKE specification
 *
 * To invoke cSHAKE, perform the following steps:
 *
 * lc_cshake_init
 * lc_hash_set_digestsize
 * lc_hash_update
 * ...
 * lc_hash_update
 * lc_hash_final
 *
 * Or use the helper lc_cshake_final:
 *
 * lc_cshake_init
 * lc_hash_update
 * ...
 * lc_hash_update
 * lc_cshake_final
 *
 * @param [in] ctx Initialized hash context
 * @param [in] n N is a function-name bit string, used by NIST to define
 *		 functions based on cSHAKE. When no function other than cSHAKE
 *		 is desired, N is set to the empty string.
 * @param [in] nlen Length of n
 * @param [in] s S is a customization bit string. The user selects this string
 *		 to define a variant of the function. When no customization is
 *		 desired, S is set to the empty string.
 * @param [in] slen Length of s
 */
void lc_cshake_init(struct lc_hash_ctx *ctx, const uint8_t *n, size_t nlen,
		    const uint8_t *s, size_t slen);

/**
 * @brief Generate a cSHAKE message digest from a given state.
 *
 * The function can be invoked repeatedly to squeeze more data from the
 * cSHAKE state.
 *
 * @param [in] ctx Initialized hash context
 * @param [out] out Buffer allocated by caller that is filled with the message
 *		    digest data.
 * @param [in] outlen Size of the output buffer to be filled.
 */
static inline void lc_cshake_final(struct lc_hash_ctx *ctx, uint8_t *out,
				   size_t outlen)
{
	lc_hash_set_digestsize(ctx, outlen);
	lc_hash_final(ctx, out);
}

/*
 * Separate cSHAKE API with re-initialization support
 *
 * Re-initialization means that any state created by the init operation can be
 * re-established during re-init.
 */
/// \cond DO_NOT_DOCUMENT
struct lc_cshake_ctx {
	uint8_t *shadow_ctx;
	struct lc_hash_ctx hash_ctx;
};

#define LC_CSHAKE_STATE_SIZE(x) (LC_HASH_STATE_SIZE(x))
#define LC_CSHAKE_STATE_SIZE_REINIT(x) (2 * LC_HASH_STATE_SIZE(x))
#define LC_CSHAKE_CTX_SIZE(x)                                                  \
	(LC_CSHAKE_STATE_SIZE(x) + sizeof(struct lc_cshake_ctx))
#define LC_CSHAKE_CTX_SIZE_REINIT(x)                                           \
	(LC_CSHAKE_STATE_SIZE_REINIT(x) + sizeof(struct lc_cshake_ctx))

#define _LC_CSHAKE_SET_CTX(name, hashname, ctx, offset)                        \
	_LC_HASH_SET_CTX((&name->hash_ctx), hashname, ctx, offset);            \
	name->shadow_ctx = NULL

#define LC_CSHAKE_SET_CTX(name, hashname)                                      \
	_LC_CSHAKE_SET_CTX(name, hashname, name, sizeof(struct lc_cshake_ctx))

#define _LC_CSHAKE_SET_CTX_REINIT(name, hashname, ctx, offset)                 \
	_LC_HASH_SET_CTX((&name->hash_ctx), hashname, ctx, offset);            \
	name->shadow_ctx = (uint8_t *)((uint8_t *)ctx + offset +               \
				       LC_HASH_STATE_SIZE(hashname))

#define LC_CSHAKE_SET_CTX_REINIT(name, hashname)                               \
	_LC_CSHAKE_SET_CTX_REINIT(name, hashname, name,                        \
				  sizeof(struct lc_cshake_ctx))
/// \endcond

/**
 * @brief Initialize the hash state with re-init support following the cSHAKE
 * specification
 *
 * @param [in] cshake_ctx Initialized hash context
 * @param [in] n N is a function-name bit string, used by NIST to define
 *		 functions based on cSHAKE. When no function other than cSHAKE
 *		 is desired, N is set to the empty string.
 * @param [in] nlen Length of n
 * @param [in] s S is a customization bit string. The user selects this string
 *		 to define a variant of the function. When no customization is
 *		 desired, S is set to the empty string.
 * @param [in] slen Length of s
 */
void lc_cshake_ctx_init(struct lc_cshake_ctx *cshake_ctx, const uint8_t *n,
			size_t nlen, const uint8_t *s, size_t slen);

/**
 * @brief Re-initialize CSHAKE context after a cshake_final operation
 *
 * This operation allows the CSHAKE context to be used again with the same key
 * set during cshake_init.
 *
 * @param [in] cshake_ctx Reference to cshake context implementation to be used
 *			  to perform CSHAKE calculation with.
 */
void lc_cshake_ctx_reinit(struct lc_cshake_ctx *cshake_ctx);

/**
 * @brief Update CSHAKE
 *
 * @param [in] cshake_ctx Reference to cshake context implementation to be used to
 *			  perform cSHAKE calculation with.
 * @param [in] in Buffer holding the data whose MAC shall be calculated
 * @param [in] inlen Length of the input buffer
 */
void lc_cshake_ctx_update(struct lc_cshake_ctx *cshake_ctx, const uint8_t *in,
			  size_t inlen);

/**
 * @brief Generate a cSHAKE message digest from a given state.
 *
 * The function can be invoked repeatedly to squeeze more data from the
 * cSHAKE state.
 *
 * @param [in] cshake_ctx Initialized hash context
 * @param [out] out Buffer allocated by caller that is filled with the message
 *		    digest data.
 * @param [in] outlen Size of the output buffer to be filled.
 */
void lc_cshake_ctx_final(struct lc_cshake_ctx *cshake_ctx, uint8_t *out,
			 size_t outlen);

/**
 * @brief Allocate CSHAKE context on heap
 *
 * NOTE: This is defined for cshake256 as of now.
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    CSHAKE calculation with. Use cshake256!
 * @param [out] cshake_ctx Allocated CSHAKE context
 * @param [in] flags Zero or more of the flags defined below
 *
 * @return 0 on success, < 0 on error
 */
int lc_cshake_ctx_alloc(const struct lc_hash *hash,
			struct lc_cshake_ctx **cshake_ctx, uint32_t flags);

/*
 * Support re-initialization of state. You set a key during cshake_init,
 * perform a full CSHAKE operation. After a cshake_final, the re-initialization
 * support allows you to call cshake_reinit and reuse the state for a new
 * operation without providing the keys again. If in doubt, initialize
 * the context with re-init support. The difference is that more memory is
 * allocated to retain the initialized state.
 */
#define LC_CSHAKE_FLAGS_SUPPORT_REINIT (1 << 0)

/**
 * @brief Zeroize and free CSHAKE context
 *
 * @param [in] cshake_ctx CSHAKE context to be zeroized and freed
 */
void lc_cshake_ctx_zero_free(struct lc_cshake_ctx *cshake_ctx);

/**
 * @brief Zeroize CSHAKE context allocated with either LC_CSHAKE_CTX_ON_STACK or
 *	  lc_cshake_alloc
 *
 * @param [in] cshake_ctx CSHAKE context to be zeroized
 */
static inline void lc_cshake_ctx_zero(struct lc_cshake_ctx *cshake_ctx)
{
	struct lc_hash_ctx *hash_ctx;
	const struct lc_hash *hash;

	if (!cshake_ctx)
		return;
	hash_ctx = &cshake_ctx->hash_ctx;
	hash = hash_ctx->hash;

	lc_memset_secure((uint8_t *)cshake_ctx + sizeof(struct lc_cshake_ctx),
			 0,
			 cshake_ctx->shadow_ctx ?
				 LC_CSHAKE_STATE_SIZE_REINIT(hash) :
				 LC_CSHAKE_STATE_SIZE(hash));
}

/**
 * @brief Allocate stack memory for the CSHAKE context
 *
 * This allocates the memory without re-initialization support
 *
 * @param [in] name Name of the stack variable - use lc_cshake256 or
 *		    lc_cshake128
 * @param [in] hashname Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_CSHAKE_CTX_ON_STACK(name, hashname)                                      \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_CSHAKE_CTX_SIZE(hashname),             \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_cshake_ctx *name = (struct lc_cshake_ctx *)name##_ctx_buf;        \
	LC_CSHAKE_SET_CTX(name, hashname);                                          \
	lc_cshake_ctx_zero(name);                                                   \
	_Pragma("GCC diagnostic pop")

/**
 * @brief Allocate stack memory for the CSHAKE context
 *
 * This allocates the memory with re-initialization support.
 * See CSHAKE_FLAGS_SUPPORT_REINIT for the explanation about re-initialization.
 *
 * @param [in] name Name of the stack variable - use lc_cshake256 or
 *		    lc_cshake128
 * @param [in] hashname Pointer of type struct hash referencing the hash
 *			 implementation to be used
 */
#define LC_CSHAKE_CTX_ON_STACK_REINIT(name, hashname)                               \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_CSHAKE_CTX_SIZE_REINIT(hashname),      \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_cshake_ctx *name = (struct lc_cshake_ctx *)name##_ctx_buf;        \
	LC_CSHAKE_SET_CTX_REINIT(name, hashname);                                   \
	lc_cshake_ctx_zero(name);                                                   \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_CSHAKE_H */
