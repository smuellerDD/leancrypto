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

#ifndef LC_KDF_CTR_H
#define LC_KDF_CTR_H

#include "ext_headers.h"
#include "lc_hash.h"
#include "lc_rng.h"
#include "lc_hmac.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup KDF
 * @brief Key-based Key Derivation in Counter Mode - SP800-108 - initialization
 *
 * @param [in,out] hmac_ctx The caller is expected to provide an allocated HMAC
 *			    cipher handle in. Yet, the caller does not need to
 *			    perform any operations on the handle. The extract
 *			    phase adjusts the HMAC cipher handle so that it is
 *			    ready for the expand phase.
 * @param [in] key Input Keying Material (see RFC5869)
 * @param [in] keylen Length of ikm buffer
 *
 * @return 0 on success, < 0 on error
 */
int lc_kdf_ctr_init(struct lc_hmac_ctx *hmac_ctx, const uint8_t *key,
		    size_t keylen);

/**
 * @ingroup KDF
 * @brief Key-based Key Derivation in Counter Mode - SP800-108 - data generation
 *
 * @param [in] hmac_ctx Cipher handle for the operation. This call expects
 *			the caller to hand in a HMAC cipher handle that has
 *			been initialized with hkdf_extract.
 * @param [in] label Optional context and application specific information. This
 *		     may be NULL.
 * @param [in] labellen Size of label buffer.
 * @param [out] dst Buffer to store the derived bits in
 * @param [in] dlen Size of the destination buffer.
 *
 * @return 0 on success, < 0 on error
 */
int lc_kdf_ctr_generate(struct lc_hmac_ctx *hmac_ctx, const uint8_t *label,
			size_t labellen, uint8_t *dst, size_t dlen);

/**
 * @ingroup KDF
 * @brief One-shot Key-based Key Derivation in Counter Mode - SP800-108
 *
 * @param [in] hash Hash implementation to use for the KDF operation - this
 *		    hash implementation is used for the HMAC calls.
 * @param [in] key Key from which the new key is to be derived from
 * @param [in] keylen Length of the key buffer.
 * @param [in] label Optional label string that is used to diversify the key
 * @param [in] labellen Length of the label buffer
 * @param [out] dst Buffer that is filled with the derived key. This buffer
 *		    with the size of keylen must be allocated by the caller.
 * @param [in] dlen Length of the key that shall be derived.
 *
 * @return 0 on success, < 0 on error
 */
int lc_kdf_ctr(const struct lc_hash *hash, const uint8_t *key, size_t keylen,
	       const uint8_t *label, size_t labellen, uint8_t *dst,
	       size_t dlen);

/***************************** Counter KDF as RNG *****************************/

/// \cond DO_NOT_DOCUMENT
struct lc_kdf_ctr_ctx {
	uint32_t counter;
	uint8_t rng_initialized : 1;
	struct lc_hmac_ctx hmac_ctx;
};

#define LC_CTR_KDF_STATE_SIZE(hashname) (LC_HMAC_CTX_SIZE(hashname))
#define LC_CTR_KDF_CTX_SIZE(hashname)                                          \
	(sizeof(struct lc_kdf_ctr_ctx) + LC_CTR_KDF_STATE_SIZE(hashname))

#define _LC_CTR_KDF_SET_CTX(name, hashname, ctx, offset)                       \
	_LC_HMAC_SET_CTX((&(name)->hmac_ctx), hashname, ctx, offset)

#define LC_CTR_KDF_SET_CTX(name, hashname)                                     \
	_LC_CTR_KDF_SET_CTX(name, hashname, name, sizeof(struct lc_kdf_ctr_ctx))

/* CTR_KDF DRNG implementation */
extern const struct lc_rng *lc_kdf_ctr_rng;

#define LC_CTR_KDF_DRNG_CTX_SIZE(hashname)                                     \
	(sizeof(struct lc_rng_ctx) + LC_CTR_KDF_CTX_SIZE(hashname))

#define LC_CTR_KDF_DRNG_SET_CTX(name, hashname)                                \
	LC_CTR_KDF_SET_CTX(name, hashname)

#define LC_CTR_KDF_RNG_CTX(name, hashname)                                     \
	LC_RNG_CTX(name, lc_kdf_ctr_rng);                                      \
	LC_CTR_KDF_DRNG_SET_CTX(((struct lc_kdf_ctr_ctx *)(name->rng_state)),  \
				hashname);                                     \
	lc_rng_zero(name)
/// \endcond

/**
 * @ingroup KDFasRNG
 * @brief Allocate stack memory for the Counter KDF DRNG context
 *
 * @param [in] name Name of the stack variable
 * @param [in] hashname Reference to lc_hash implementation used for CTR KDF
 *
 * \warning You MUST seed the DRNG!
 */
#define LC_CTR_KDF_DRNG_CTX_ON_STACK(name, hashname)                                \
	_Pragma("GCC diagnostic push")                                              \
		_Pragma("GCC diagnostic ignored \"-Wvla\"") _Pragma(                \
			"GCC diagnostic ignored \"-Wdeclaration-after-statement\"") \
			LC_ALIGNED_BUFFER(name##_ctx_buf,                           \
					  LC_CTR_KDF_DRNG_CTX_SIZE(hashname),       \
					  LC_HASH_COMMON_ALIGNMENT);                \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;              \
	LC_CTR_KDF_RNG_CTX(name, hashname);                                         \
	_Pragma("GCC diagnostic pop")

/**
 * @ingroup KDFasRNG
 * @brief Allocation of a Counter KDF DRNG context
 *
 * @param [out] state Counter KDF DRNG context allocated by the function
 * @param [in] hash Reference to lc_hash implementation used for CTR KDF
 *
 * The cipher handle including its memory is allocated with this function.
 *
 * The memory is pinned so that the DRNG state cannot be swapped out to disk.
 *
 * \warning You MUST seed the DRNG!
 *
 * @return 0 upon success; < 0 on error
 */
int lc_kdf_ctr_rng_alloc(struct lc_rng_ctx **state, const struct lc_hash *hash);

#ifdef __cplusplus
}
#endif

#endif /* LC_KDF_CTR_H */
