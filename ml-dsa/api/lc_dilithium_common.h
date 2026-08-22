/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_DILITHIUM_COMMON_H
#define LC_DILITHIUM_COMMON_H

#include "lc_hash.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lc_dilithium_ctx {
	/**
	 * @brief Hash context used internally to the library - it should not
	 * be touched by the user
	 */
	struct lc_hash_ctx dilithium_hash_ctx;

	/**
	 * @brief State memory of the hash context used internally to the
	 * library - it should not be touched by the user
	 */
	uint8_t shake_state[LC_HASH_STATE_SIZE_ALIGN(LC_SHA3_256_STATE_SIZE)];

	/**
	 * @brief When using HashML-DSA, set the hash reference used for the
	 * hash operation. Allowed values are lc_sha256, lc_sha512, lc_sha3_256,
	 * lc_sha3_384, lc_sha3_512, lc_shake128 and lc_shake256. Note, the
	 * actual message digest operation can be performed external to
	 * leancrypto. This parameter only shall indicate the used hash
	 * operation.
	 *
	 * \note Use \p lc_dilithium_ctx_hash or
	 * \p lc_dilithium_ed25519_ctx_hash to set this value.
	 */
	const struct lc_hash *dilithium_prehash_type;

	/**
	 * @brief length of the user context (allowed range between 0 and 255
	 * bytes)
	 *
	 * \note Use \p lc_dilithium_ctx_userctx or
	 * \p lc_dilithium_ed25519_ctx_userctx to set this value.
	 */
	size_t userctxlen;

	/**
	 * @brief buffer with a caller-specified context string
	 *
	 * \note Use \p lc_dilithium_ctx_userctx or
	 * \p lc_dilithium_ed25519_ctx_userctx to set this value.
	 */
	const uint8_t *userctx;

	/**
	 * @brief Pointer to the external mu.
	 *
	 * If set, the signature operation will use the provided mu instead of
	 * the message. In this case, the message pointer to the signature
	 * generation or verification can be NULL.
	 */
	const uint8_t *external_mu;
	size_t external_mu_len;

	/**
	 * @brief Pointer to the AHat buffer. This can be provided by the caller
	 * or it must be NULL otherwise.
	 *
	 * \note Use \p LC_DILITHIUM_CTX_ON_STACK_AHAT to provide memory for
	 * storing AHat in the caller context and thus make the signature
	 * operation much faster starting with the 2nd use of the key (pair).
	 */
	void *ahat;
	unsigned short ahat_size;

	/**
	 * @brief NIST category required for composite signatures
	 *
	 * The domain separation logic depends on the selection of the right
	 * OID for the "Domain" data.
	 */
	uint8_t nist_category;

	/**
	 * @brief Indicator whether it is a composite algorithm usage. This is
	 * used and set internally.
	 */
	unsigned int composite_algorithm : 1;

	/**
	 * @brief When set to true, only the ML-DSA.Sign_internal or
	 * ML-DSA.Verify_internal are performed (see FIPS 204 chapter 6).
	 * Otherwise the ML-DSA.Sign / ML-DSA.Verify (see FIPS chapter 5) is
	 * applied.
	 *
	 * \note Use \p lc_dilithium_ctx_internal or
	 * \p lc_dilithium_ed25519_ctx_internal to set this value.
	 *
	 * \warning Only set this value to true if you exactly know what you are
	 * doing!.
	 */
	unsigned int ml_dsa_internal : 1;

	/**
	 * @brief Was aHat already filled? This is used and set internally.
	 */
	unsigned int ahat_expanded : 1;
};

/**
 * @brief Dilithium stream context
 *
 * This structure is used for the init/update/final operation of the
 * Dilithium-ED25519 hybrid.
 */
struct lc_dilithium_ed25519_ctx {
	struct lc_dilithium_ctx dilithium_ctx;
	const uint8_t *msg_prefix;
	size_t msg_prefix_len;
};

/**
 * @brief Dilithium stream context
 *
 * This structure is used for the init/update/final operation of the
 * Dilithium-ED448 hybrid.
 */
struct lc_dilithium_ed448_ctx {
	struct lc_dilithium_ctx dilithium_ctx;
	const uint8_t *msg_prefix;
	size_t msg_prefix_len;
};

#ifdef __cplusplus
}
#endif

#endif /* LC_DILITHIUM_COMMON_H */
