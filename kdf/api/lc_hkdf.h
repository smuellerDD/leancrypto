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

#ifndef LC_HKDF_H
#define LC_HKDF_H

#include "ext_headers.h"
#include "lc_hmac.h"
#include "lc_rng.h"
#include "lc_memset_secure.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_hkdf_ctx {
	uint8_t partial[LC_SHA_MAX_SIZE_DIGEST];
	size_t partial_ptr;
	uint8_t ctr;
	uint8_t rng_initialized : 1;
	struct lc_hmac_ctx hmac_ctx;
};

#define LC_HKDF_STATE_SIZE(hashname) (LC_HMAC_CTX_SIZE(hashname))
#define LC_HKDF_CTX_SIZE(hashname)                                             \
	(sizeof(struct lc_hkdf_ctx) + LC_HKDF_STATE_SIZE(hashname))

#define _LC_HKDF_SET_CTX(name, hashname, ctx, offset)                          \
	_LC_HMAC_SET_CTX((&(name)->hmac_ctx), hashname, ctx, offset)

#define LC_HKDF_SET_CTX(name, hashname)                                        \
	_LC_HKDF_SET_CTX(name, hashname, name, sizeof(struct lc_hkdf_ctx))
/// \endcond

/**
 * @defgroup KDF Key Derivation Functions
 */
/**
 * @ingroup KDF
 * @brief HMAC-based Extract-and-Expand Key Derivation Function (HKDF) - RFC5869
 *	  Extract phase
 *
 * @param [in,out] hkdf_ctx The caller is expected to provide an allocated HMAC
 *			    cipher handle in. Yet, the caller does not need to
 *			    perform any operations on the handle. The extract
 *			    phase adjusts the HMAC cipher handle so that it is
 *			    ready for the expand phase.
 * @param [in] ikm Input Keying Material (see RFC5869)
 * @param [in] ikmlen Length of ikm buffer
 * @param [in] salt Optional salt value - if caller does not want to use a salt
 *		    set NULL here.
 * @param [in] saltlen Length of salt value buffer.
 *
 * @return 0 on success, < 0 on error
 */
int lc_hkdf_extract(struct lc_hkdf_ctx *hkdf_ctx, const uint8_t *ikm,
		    size_t ikmlen, const uint8_t *salt, size_t saltlen);

/**
 * @ingroup KDF
 * @brief HMAC-based Extract-and-Expand Key Derivation Function (HKDF) - RFC5869
 *	  Expand phase
 *
 * @param [in] hkdf_ctx Cipher handle for the operation. This call expects
 *			the caller to hand in a HMAC cipher handle that has
 *			been initialized with hkdf_extract.
 * @param [in] info Optional context and application specific information. This
 *		    may be NULL.
 * @param [in] infolen Size of info buffer.
 * @param [out] dst Buffer to store the derived bits in
 * @param [in] dlen Size of the destination buffer.
 *
 * @return 0 on success, < 0 on error
 */
int lc_hkdf_expand(struct lc_hkdf_ctx *hkdf_ctx, const uint8_t *info,
		   size_t infolen, uint8_t *dst, size_t dlen);

/**
 * @ingroup KDF
 * @brief Zeroize HKDF context allocated with either LC_HKDF_CTX_ON_STACK or
 *	  hkdf_alloc
 *
 * @param [in] hkdf_ctx HMAC context to be zeroized
 */
void lc_hkdf_zero(struct lc_hkdf_ctx *hkdf_ctx);

/**
 * @ingroup KDF
 * @brief Allocate HKDF context on heap
 *
 * @param [in] hash Reference to hash implementation to be used to perform
 *		    HMAC calculation with.
 * @param [out] hkdf_ctx Allocated HKDF context
 *
 * @return 0 on success, < 0 on error
 */
int lc_hkdf_alloc(const struct lc_hash *hash, struct lc_hkdf_ctx **hkdf_ctx);

/**
 * @ingroup KDF
 * @brief Zeroize and free HKDF context
 *
 * @param [in] hkdf_ctx HKDF context to be zeroized and freed
 */
void lc_hkdf_zero_free(struct lc_hkdf_ctx *hkdf_ctx);

/**
 * @ingroup KDF
 * @brief Allocate stack memory for the HKDF context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hashname Reference to lc_hash implementation
 */
#define LC_HKDF_CTX_ON_STACK(name, hashname)                                        \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_HKDF_CTX_SIZE(hashname),               \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_hkdf_ctx *name = (struct lc_hkdf_ctx *)name##_ctx_buf;            \
	LC_HKDF_SET_CTX(name, hashname);                                            \
	lc_hkdf_zero(name);                                                         \
	_Pragma("GCC diagnostic pop")

/**
 * @ingroup KDF
 * @brief HMAC-based Extract-and-Expand Key Derivation Function (HKDF) - RFC5869
 *	  Complete implementation
 *
 * @param [in] hash Reference to lc_hash implementation
 * @param [in] ikm Input Keying Material (see RFC5869)
 * @param [in] ikmlen Length of ikm buffer
 * @param [in] salt Optional salt value - if caller does not want to use a salt
 *		    set NULL here.
 * @param [in] saltlen Length of salt value buffer.
 * @param [in] info Optional context and application specific information. This
 *		    may be NULL.
 * @param [in] infolen Size of info buffer.
 * @param [out] dst Buffer to store the derived bits in
 * @param [in] dlen Size of the destination buffer.
 *
 * @return 0 on success, < 0 on error
 */
int lc_hkdf(const struct lc_hash *hash, const uint8_t *ikm, size_t ikmlen,
	    const uint8_t *salt, size_t saltlen, const uint8_t *info,
	    size_t infolen, uint8_t *dst, size_t dlen);

/******************************** HKDF as RNG *********************************/

/**
 * @defgroup KDFasRNG Key Derivation Functions used with RNG API
 *
 * The HKDF can be used as an RNG context for aggregated algorithms like
 * Kyber or Dilithium. The idea is that the KDF state can be initialized
 * from an input data to deterministically derive the values required for the
 * algorithms the RNG context is used with.
 */

/* HKDF DRNG implementation */
extern const struct lc_rng *lc_hkdf_rng;

#define LC_HKDF_DRNG_CTX_SIZE(hashname)                                        \
	(sizeof(struct lc_rng_ctx) + LC_HKDF_CTX_SIZE(hashname))

#define LC_HKDF_DRNG_SET_CTX(name, hashname) LC_HKDF_SET_CTX(name, hashname)

#define LC_HKDF_RNG_CTX(name, hashname)                                        \
	LC_RNG_CTX(name, lc_hkdf_rng);                                         \
	LC_HKDF_DRNG_SET_CTX(((struct lc_hkdf_ctx *)(name->rng_state)),        \
			     hashname);                                        \
	lc_rng_zero(name)

/**
 * @ingroup KDFasRNG
 * @brief Allocate stack memory for the HKDF DRNG context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hashname Reference to lc_hash implementation used for HKDF
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_HKDF_DRNG_CTX_ON_STACK(name, hashname)                                   \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_HKDF_DRNG_CTX_SIZE(hashname),          \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;              \
	LC_HKDF_RNG_CTX(name, hashname);                                            \
	_Pragma("GCC diagnostic pop")

/**
 * @ingroup KDFasRNG
 * @brief Allocation of a HKDF DRNG context
 *
 * @param [out] state HKDF DRNG context allocated by the function
 * @param [in] hash Reference to lc_hash implementation used for HKDF
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * \warning You MUST seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_hkdf_rng_alloc(struct lc_rng_ctx **state, const struct lc_hash *hash);

#ifdef __cplusplus
}
#endif

#endif /* LC_HKDF_H */
