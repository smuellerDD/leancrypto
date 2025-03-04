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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef LC_DILITHIUM_H
#define LC_DILITHIUM_H

#include "ext_headers.h"

#if defined __has_include
#if __has_include("lc_dilithium_87.h")
#include "lc_dilithium_87.h"
#define LC_DILITHIUM_87_ENABLED
#endif
#if __has_include("lc_dilithium_65.h")
#include "lc_dilithium_65.h"
#define LC_DILITHIUM_65_ENABLED
#endif
#if __has_include("lc_dilithium_44.h")
#include "lc_dilithium_44.h"
#define LC_DILITHIUM_44_ENABLED
#endif
#else
#error "Compiler misses __has_include"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum lc_dilithium_type {
	/** Unknown key type */
	LC_DILITHIUM_UNKNOWN,
	/** Dilithium 87 */
	LC_DILITHIUM_87,
	/** Dilithium 65 */
	LC_DILITHIUM_65,
	/** Dilithium 44 */
	LC_DILITHIUM_44,
};

/** @defgroup Dilithium ML-DSA / CRYSTALS-Dilithium Signature Mechanism
 *
 * Dilithium API concept
 *
 * The Dilithium API is accessible via the following header files with the
 * mentioned purpose.
 *
 * * lc_dilithium.h: This API is the generic API allowing the caller to select
 *   which Dilithium type (Dilithium 87, 65 or 44) are to be used. The selection
 *   is made either with the flag specified during key generation or by matching
 *   the size of the imported data with the different lc_dilithium_*_load API
 *   calls. All remaining APIs take the information about the Dilithium type
 *   from the provided input data.
 *
 *   This header file only provides inline functions which selectively call
 *   the API provided with the header files below.
 *
 * * lc_dilithium_87.h: Direct access to Dilithium 87.
 *
 * * lc_dilithium_65.h: Direct access to Dilithium 65.
 *
 * * lc_dilithium_44.h: Direct access to Dilithium 44.
 *
 * To support the stream mode of the Dilithium signature operation, a
 * context structure is required. This context structure can be allocated either
 * on the stack or heap with \p LC_DILITHIUM_CTX_ON_STACK or
 * \p lc_dilithium_ctx_alloc. The context should be zeroized
 * and freed (only for heap) with \p lc_dilithium_ctx_zero or
 * \p lc_dilithium_ctx_zero_free.
 */

/**
 * @brief Dilithium secret key
 */
struct lc_dilithium_sk {
	enum lc_dilithium_type dilithium_type;
	union {
#ifdef LC_DILITHIUM_87_ENABLED
		struct lc_dilithium_87_sk sk_87;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
		struct lc_dilithium_65_sk sk_65;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
		struct lc_dilithium_44_sk sk_44;
#endif
	} key;
};

/**
 * @brief Dilithium public key
 */
struct lc_dilithium_pk {
	enum lc_dilithium_type dilithium_type;
	union {
#ifdef LC_DILITHIUM_87_ENABLED
		struct lc_dilithium_87_pk pk_87;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
		struct lc_dilithium_65_pk pk_65;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
		struct lc_dilithium_44_pk pk_44;
#endif
	} key;
};

/**
 * @brief Dilithium signature
 */
struct lc_dilithium_sig {
	enum lc_dilithium_type dilithium_type;
	union {
#ifdef LC_DILITHIUM_87_ENABLED
		struct lc_dilithium_87_sig sig_87;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
		struct lc_dilithium_65_sig sig_65;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
		struct lc_dilithium_44_sig sig_44;
#endif
	} sig;
};

/**
 * @brief Allocate stack memory for the Dilithium stream context and additional
 * parameter relevant for the signature operation.
 *
 * In addition, the memory buffer returned by this allocation contains the space
 * for an expanded representation of the public key which is required in both,
 * signature generation and verification. When using this memory, the first
 * signature operation expands the key and any subsequent operation using this
 * context will re-use the expanded key which improves performance of the
 * signature operation significantly.
 *
 * As the same expanded structure is used for signature generation and
 * verification and the structure can be expanded by either operation, it
 * is perfectly legal to use one context for both operations as the expanded
 * key can (a) be generated from either the public or the secret key and (b)
 * it applies to both operations and (c) is identical irrespective it was
 * generated from the public or secret key.
 *
 * The provided context size is sufficiently large to support all ML-DSA key
 * sizes this library version offers support for.
 *
 * \note: ML-DSA AVX2 signature operation uses a completely different
 * algorithm which does not use a pre-pcomputed expanded key. Thus, if you know
 * you have AVX2 support, you *may* not need this larger buffer and you *can*
 * use \p LC_DILITHIUM_CTX_ON_STACK instead.
 *
 * \note: The expanded representation only uses public key data. Even when
 * deriving the expanded representation from a secret key, this data is only
 * obtained from a part that is considered public. Thus, this memory does not
 * require special protections. See FIPS 204 section 3.6.3 on the properties
 * and handling requirements of the Â matrix. Further, see the FIPS 204
 * ML-DSA.Sign_internal and ML-DSA.Verify_internal algorithm specification on
 * how this Â matrix is generated and that the input to the generation is public
 * data.
 *
 * \warning: One instance of the expanded key representation can only ever apply
 * to one given key (pair). If you want to reuse the context with multiple keys,
 * you MUST invalidate the potentially present expanded key representation. Such
 * invalidation is invoked with the method \p lc_dilithium_ctx_drop_ahat. Only
 * after this invalidation you can use the context with a different key.
 *
 * param [in] name Name of the stack variable
 */
#ifdef LC_DILITHIUM_87_ENABLED
#define LC_DILITHIUM_CTX_ON_STACK_AHAT(name)                                   \
	LC_DILITHIUM_87_CTX_ON_STACK_AHAT(name)
#elif defined(LC_DILITHIUM_65_ENABLED)
LC_DILITHIUM_CTX_ON_STACK_AHAT(name)
LC_DILITHIUM_65_CTX_ON_STACK_AHAT(name)
#elif defined(LC_DILITHIUM_44_ENABLED)
LC_DILITHIUM_CTX_ON_STACK_AHAT(name)
LC_DILITHIUM_44_CTX_ON_STACK_AHAT(name)
#endif

/**
 * @ingroup Dilithium
 * @brief Allocates Dilithium context on heap
 *
 * @param [out] ctx Dilithium context pointer
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ctx_alloc(struct lc_dilithium_ctx **ctx);

/**
 * @ingroup Dilithium
 * @brief Allocates Dilithium context on heap with support to keep the internal
 *	  representation of the key.
 *
 * \note See \p LC_DILITHIUM_CTX_ON_STACK_AHAT for details.
 *
 * @param [out] ctx Dilithium context pointer
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ctx_alloc_ahat(struct lc_dilithium_ctx **ctx);

/**
 * @ingroup Dilithium
 * @brief Zeroizes and frees Dilithium context on heap
 *
 * @param [out] ctx Dilithium context pointer
 */
void lc_dilithium_ctx_zero_free(struct lc_dilithium_ctx *ctx);

/**
 * @ingroup Dilithium
 * @brief Zeroizes Dilithium context either on heap or on stack
 *
 * @param [out] ctx Dilithium context pointer
 */
void lc_dilithium_ctx_zero(struct lc_dilithium_ctx *ctx);

/**
 * @ingroup Dilithium
 * @brief Mark the Dilithium context to execute ML-DSA.Sign_internal /
 *	  ML-DSA.Verify_internal.
 *
 * @param [in] ctx Dilithium context
 */
void lc_dilithium_ctx_internal(struct lc_dilithium_ctx *ctx);

/**
 * @ingroup Dilithium
 * @brief Set the hash type that was used for pre-hashing the message. The
 *	  message digest is used with the HashML-DSA. The message digest
 *	  is to be provided via the message pointer in the sign/verify APIs.
 *
 * @param [in] ctx Dilithium context
 * @param [in] hash Hash context referencing the used hash for pre-hashing the
 *		    message
 */
void lc_dilithium_ctx_hash(struct lc_dilithium_ctx *ctx,
			   const struct lc_hash *hash);

/**
 * @ingroup Dilithium
 * @brief Specify the optional user context string to be applied with the
 *	  Dilithium signature operation.
 *
 * @param [in] ctx Dilithium context
 * @param [in] userctx User context string
 * @param [in] userctxlen Size of the user context string
 */
void lc_dilithium_ctx_userctx(struct lc_dilithium_ctx *ctx,
			      const uint8_t *userctx, size_t userctxlen);

/**
 * @ingroup Dilithium
 * @brief Specify the optional external mu value.
 *
 * \note If the external mu is specified, the signature generation /
 * verification APIs do not require a message. In this case, the message buffer
 * can be set to NULL.
 *
 * \note If both a message and an external mu are provided, the external mu
 * takes precedence.
 *
 * @param [in] ctx Dilithium context
 * @param [in] external_mu User context string
 * @param [in] external_mu_len Size of the user context string
 */
void lc_dilithium_ctx_external_mu(struct lc_dilithium_ctx *ctx,
				  const uint8_t *external_mu,
				  size_t external_mu_len);

/**
 * @ingroup Dilithium
 * @brief Invalidate the expanded key that potentially is stored in the context.
 *
 * This call can be executed on a context irrespective it was allocated with
 * space for the expanded representation or not. Thus, the caller does not need
 * to track whether the context supports the expanded key.
 *
 * @param [in] ctx Dilithium context
 */
void lc_dilithium_ctx_drop_ahat(struct lc_dilithium_ctx *ctx);

/**
 * @ingroup Dilithium
 * @brief Obtain Dilithium type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_dilithium_type lc_dilithium_sk_type(const struct lc_dilithium_sk *sk);

/**
 * @ingroup Dilithium
 * @brief Obtain Dilithium type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_dilithium_type lc_dilithium_pk_type(const struct lc_dilithium_pk *pk);

/**
 * @ingroup Dilithium
 * @brief Obtain Dilithium type from signature
 *
 * @param [in] sig Signature from which the type is to be obtained
 *
 * @return key type
 */
enum lc_dilithium_type
lc_dilithium_sig_type(const struct lc_dilithium_sig *sig);

/**
 * @ingroup Dilithium
 * @brief Return the size of the Dilithium secret key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int
lc_dilithium_sk_size(enum lc_dilithium_type dilithium_type);

/**
 * @ingroup Dilithium
 * @brief Return the size of the Dilithium public key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int
lc_dilithium_pk_size(enum lc_dilithium_type dilithium_type);

/**
 * @ingroup Dilithium
 * @brief Return the size of the Dilithium signature.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int
lc_dilithium_sig_size(enum lc_dilithium_type dilithium_type);

/**
 * @ingroup Dilithium
 * @brief Load a Dilithium secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_dilithium_sk_load(struct lc_dilithium_sk *sk, const uint8_t *src_key,
			 size_t src_key_len);

/**
 * @ingroup Dilithium
 * @brief Load a Dilithium public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_dilithium_pk_load(struct lc_dilithium_pk *pk, const uint8_t *src_key,
			 size_t src_key_len);

/**
 * @ingroup Dilithium
 * @brief Load a Dilithium signature provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sig Secret key to be filled (the caller must have it allocated)
 * @param [in] src_sig Buffer that holds the signature to be imported
 * @param [in] src_sig_len Buffer length that holds the signature to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_dilithium_sig_load(struct lc_dilithium_sig *sig, const uint8_t *src_sig,
			  size_t src_sig_len);

/**
 * @ingroup Dilithium
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] dilithium_key Dilithium key pointer
 * @param [out] dilithium_key_len Length of the key buffer
 * @param [in] sk Dilithium secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_dilithium_sk_ptr(uint8_t **dilithium_key, size_t *dilithium_key_len,
			struct lc_dilithium_sk *sk);

/**
 * @ingroup Dilithium
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] dilithium_key Dilithium key pointer
 * @param [out] dilithium_key_len Length of the key buffer
 * @param [in] pk Dilithium publi key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_dilithium_pk_ptr(uint8_t **dilithium_key, size_t *dilithium_key_len,
			struct lc_dilithium_pk *pk);

/**
 * @ingroup Dilithium
 * @brief Obtain the reference to the Dilithium signature and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto signature,
 * too.
 *
 * @param [out] dilithium_sig Dilithium signature pointer
 * @param [out] dilithium_sig_len Length of the signature buffer
 * @param [in] sig Dilithium signature from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_dilithium_sig_ptr(uint8_t **dilithium_sig, size_t *dilithium_sig_len,
			 struct lc_dilithium_sig *sig);

/**
 * @ingroup Dilithium
 * @brief Generates Dilithium public and private key.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] dilithium_type type of the Dilithium key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_keypair(struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
			 struct lc_rng_ctx *rng_ctx,
			 enum lc_dilithium_type dilithium_type);

/**
 * @ingroup Dilithium
 * @brief Generates Dilithium public and private key from a given seed.
 *
 * The idea of the function is the allowance of FIPS 204 to maintain the seed
 * used to generate a key pair in lieu of maintaining a private key or the
 * key pair (which used much more memory). The seed must be treated equally
 * sensitive as a private key.
 *
 * The seed is generated by simply obtaining 32 bytes from a properly seeded
 * DRNG, i.e. the same way as a symmetric key would be generated.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] seed buffer with the seed data which must be exactly 32 bytes
 *		    in size
 * @param [in] seedlen length of the seed buffer
 * @param [in] dilithium_type type of the Dilithium key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_keypair_from_seed(struct lc_dilithium_pk *pk,
				   struct lc_dilithium_sk *sk,
				   const uint8_t *seed, size_t seedlen,
				   enum lc_dilithium_type dilithium_type);

/**
 * @brief Pairwise consistency check as per FIPS 140 IG
 *
 * This call should be invoked after generating a key pair in FIPS mode
 *
 * @param [in] pk Public key
 * @param [in] sk Secret key
 *
 * @return 0 on success, < 0 on error
 */
int lc_dilithium_pct(const struct lc_dilithium_pk *pk,
		     const struct lc_dilithium_sk *sk);

/**
 * @ingroup Dilithium
 * @brief Computes signature in one shot
 *
 * @param [out] sig pointer to output signature
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_sign(struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup Dilithium
 * @brief Computes signature woth user context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * Using the ctx structure, the caller can select 3 different types of ML-DSA:
 *
 * * ctx->dilithium_prehash_type set to a hash type, HashML-DSA is assumed which
 *   implies that the message m must be exactly digest size (FIPS 204 section
 *   5.4)
 *
 * * ctx->ml_dsa_internal set to 1, the ML-DSA.Sign_internal and
 *   .Verify_internal are executed (FIPS 204 chapter 6)
 *
 * * both aforementioned parameter set to NULL / 0, ML-DSA.Sign and
 *   ML-DSA.Verify are executed (FIPS 204 sections 5.2 and 5.3)
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx reference to the allocated Dilithium context handle
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_sign_ctx(struct lc_dilithium_sig *sig,
			  struct lc_dilithium_ctx *ctx, const uint8_t *m,
			  size_t mlen, const struct lc_dilithium_sk *sk,
			  struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup Dilithium
 * @brief Initializes a signature operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_dilithium_sign_update and lc_dilithium_sign_final.
 *
 * @param [in,out] ctx pointer Dilithium context
 * @param [in] sk pointer to bit-packed secret key
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
int lc_dilithium_sign_init(struct lc_dilithium_ctx *ctx,
			   const struct lc_dilithium_sk *sk);

/**
 * @ingroup Dilithium
 * @brief Add more data to an already initialized signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_dilithium_sign_init and lc_dilithium_sign_final.
 *
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *	      	   lc_dilithium_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_sign_update(struct lc_dilithium_ctx *ctx, const uint8_t *m,
			     size_t mlen);

/**
 * @ingroup Dilithium
 * @brief Computes signature
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *	      	   lc_dilithium_sign_init and filled with
 * 		   lc_dilithium_sign_update
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_sign_final(struct lc_dilithium_sig *sig,
			    struct lc_dilithium_ctx *ctx,
			    const struct lc_dilithium_sk *sk,
			    struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup Dilithium
 * @brief Verifies signature in one shot
 *
 * @param [in] sig pointer to input signature
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_dilithium_verify(const struct lc_dilithium_sig *sig, const uint8_t *m,
			size_t mlen, const struct lc_dilithium_pk *pk);

/**
 * @ingroup Dilithium
 * @brief Verifies signature with Dilithium context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * @param [in] sig pointer to input signature
 * @param [in] ctx reference to the allocated Dilithium context handle
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_dilithium_verify_ctx(const struct lc_dilithium_sig *sig,
			    struct lc_dilithium_ctx *ctx, const uint8_t *m,
			    size_t mlen, const struct lc_dilithium_pk *pk);

/**
 * @ingroup Dilithium
 * @brief Initializes a signature verification operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_dilithium_verify_update and
 * lc_dilithium_verify_final.
 *
 * @param [in,out] ctx pointer to an allocated Dilithium context
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
int lc_dilithium_verify_init(struct lc_dilithium_ctx *ctx,
			     const struct lc_dilithium_pk *pk);

/**
 * @ingroup Dilithium
 * @brief Add more data to an already initialized signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_dilithium_verify_init and
 * lc_dilithium_verify_final.
 *
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *		   lc_dilithium_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_verify_update(struct lc_dilithium_ctx *ctx, const uint8_t *m,
			       size_t mlen);

/**
 * @ingroup Dilithium
 * @brief Verifies signature
 *
 * @param [in] sig pointer to output signature
 * @param [in] ctx pointer to Dilithium context that was initialized with
 *		   lc_dilithium_sign_init and filled with
 *		   lc_dilithium_sign_update
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_dilithium_verify_final(const struct lc_dilithium_sig *sig,
			      struct lc_dilithium_ctx *ctx,
			      const struct lc_dilithium_pk *pk);

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED25519_SIG

/** @defgroup HybridDilithium ML-DSA / CRYSTALS-Dilithium Hybrid Signature Mechanism
 *
 * The Dilithium hybrid API performs signature operations with Dilithium and
 * the classic ED25519 algorithm at the same time. The API is identical to
 * the Dilithium API and can be used as a drop-in replacement.
 *
 * ED25519ph is used for the hybrid signature operation compliant to
 * RFC8032 using a NULL context. This approach is taken to support the
 * stream mode operation with init / update / final.
 *
 * To support the stream mode of the Dilithium signature operation, a
 * context structure is required. This context structure can be allocated either
 * on the stack or heap with \p LC_DILITHIUM_ED25519_CTX_ON_STACK or
 * \p lc_dilithium_ed25519_ctx_alloc. The context should be zeroized
 * and freed (only for heap) with \p lc_dilithium_ed25519_ctx_zero or
 * \p lc_dilithium_ed25519_ctx_zero_free.
 */

/**
 * @brief Dilithium secret key
 */
struct lc_dilithium_ed25519_sk {
	enum lc_dilithium_type dilithium_type;
	union {
#ifdef LC_DILITHIUM_87_ENABLED
		struct lc_dilithium_87_ed25519_sk sk_87;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
		struct lc_dilithium_65_ed25519_sk sk_65;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
		struct lc_dilithium_44_ed25519_sk sk_44;
#endif
	} key;
};

/**
 * @brief Dilithium public key
 */
struct lc_dilithium_ed25519_pk {
	enum lc_dilithium_type dilithium_type;
	union {
#ifdef LC_DILITHIUM_87_ENABLED
		struct lc_dilithium_87_ed25519_pk pk_87;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
		struct lc_dilithium_65_ed25519_pk pk_65;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
		struct lc_dilithium_44_ed25519_pk pk_44;
#endif
	} key;
};

/**
 * @brief Dilithium signature
 */
struct lc_dilithium_ed25519_sig {
	enum lc_dilithium_type dilithium_type;
	union {
#ifdef LC_DILITHIUM_87_ENABLED
		struct lc_dilithium_87_ed25519_sig sig_87;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
		struct lc_dilithium_65_ed25519_sig sig_65;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
		struct lc_dilithium_44_ed25519_sig sig_44;
#endif
	} sig;
};

/**
 * @ingroup HybridDilithium
 * @brief Allocates Dilithium-ED25519 context on heap
 *
 * @param [out] ctx Dilithium-ED25519 context pointer
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_ctx_alloc(struct lc_dilithium_ed25519_ctx **ctx);

/**
 * @ingroup HybridDilithium
 * @brief Zeroizes and frees Dilithium-ED25519 context on heap
 *
 * @param [out] ctx Dilithium-ED25519 context pointer
 */
void lc_dilithium_ed25519_ctx_zero_free(struct lc_dilithium_ed25519_ctx *ctx);

/**
 * @ingroup HybridDilithium
 * @brief Zeroizes Dilithium-ED25519 context either on heap or on stack
 *
 * @param [out] ctx Dilithium-ED25519 context pointer
 */
void lc_dilithium_ed25519_ctx_zero(struct lc_dilithium_ed25519_ctx *ctx);

/**
 * @ingroup HybridDilithium
 * @brief Set the hash type that was used for pre-hashing the message. The
 *	  message digest ist used with the HashML-DSA. The message digest
 *	  is to be provided via the message pointer in the sign/verify APIs.
 *
 * @param [in] ctx Dilithium-ED25519 context
 * @param [in] hash Hash context referencing the used hash for pre-hashing the
 *		    message
 */
void lc_dilithium_ed25519_ctx_hash(struct lc_dilithium_ed25519_ctx *ctx,
				   const struct lc_hash *hash);

/**
 * @ingroup HybridDilithium
 * @brief Mark the Dilithium context to execute ML-DSA.Sign_internal /
 *	  ML-DSA.Verify_internal.
 *
 * @param [in] ctx Dilithium-ED25519 context
 */
void lc_dilithium_ed25519_ctx_internal(struct lc_dilithium_ed25519_ctx *ctx);

/**
 * @ingroup HybridDilithium
 * @brief Specify the optional user context string to be applied with the
 *	  Dilithium-ED25519 signature operation.
 *
 * \warning The operation of the HashComposite-ML-DSA operation clears out
 * this context during processing. If this context is reused, the caller MUST
 * set the cotext again.
 *
 * @param [in] ctx Dilithium-ED25519 context
 * @param [in] userctx User context string
 * @param [in] userctxlen Size of the user context string
 */
void lc_dilithium_ed25519_ctx_userctx(struct lc_dilithium_ed25519_ctx *ctx,
				      const uint8_t *userctx,
				      size_t userctxlen);

/**
 * @ingroup HybridDilithium
 * @brief Obtain Dilithium type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_dilithium_type
lc_dilithium_ed25519_sk_type(const struct lc_dilithium_ed25519_sk *sk);

/**
 * @ingroup HybridDilithium
 * @brief Obtain Dilithium type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_dilithium_type
lc_dilithium_ed25519_pk_type(const struct lc_dilithium_ed25519_pk *pk);

/**
 * @ingroup HybridDilithium
 * @brief Obtain Dilithium type from signature
 *
 * @param [in] sig Signature from which the type is to be obtained
 *
 * @return key type
 */
enum lc_dilithium_type
lc_dilithium_ed25519_sig_type(const struct lc_dilithium_ed25519_sig *sig);

/**
 * @ingroup HybridDilithium
 * @brief Return the size of the Dilithium secret key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int
lc_dilithium_ed25519_sk_size(enum lc_dilithium_type dilithium_type);

/**
 * @ingroup HybridDilithium
 * @brief Return the size of the Dilithium public key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int
lc_dilithium_ed25519_pk_size(enum lc_dilithium_type dilithium_type);

/**
 * @ingroup HybridDilithium
 * @brief Return the size of the Dilithium signature.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int
lc_dilithium_ed25519_sig_size(enum lc_dilithium_type dilithium_type);

/**
 * @ingroup HybridDilithium
 * @brief Load a Dilithium secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] dilithium_src_key Buffer that holds the Dilithium key to be
 *	       imported
 * @param [in] dilithium_src_key_len Buffer length that holds the key to be
 *	       imported
 * @param [in] ed25519_src_key Buffer that holds the ED25519 key to be imported
 * @param [in] ed25519_src_key_len Buffer length that holds the key to be
 *	       imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_dilithium_ed25519_sk_load(struct lc_dilithium_ed25519_sk *sk,
				 const uint8_t *dilithium_src_key,
				 size_t dilithium_src_key_len,
				 const uint8_t *ed25519_src_key,
				 size_t ed25519_src_key_len);

/**
 * @ingroup HybridDilithium
 * @brief Load a Dilithium public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Secret key to be filled (the caller must have it allocated)
 * @param [in] dilithium_src_key Buffer that holds the Dilithium key to be
 *	       imported
 * @param [in] dilithium_src_key_len Buffer length that holds the key to be
 *	       imported
 * @param [in] ed25519_src_key Buffer that holds the ED25519 key to be imported
 * @param [in] ed25519_src_key_len Buffer length that holds the key to be
 *	       imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_dilithium_ed25519_pk_load(struct lc_dilithium_ed25519_pk *pk,
				 const uint8_t *dilithium_src_key,
				 size_t dilithium_src_key_len,
				 const uint8_t *ed25519_src_key,
				 size_t ed25519_src_key_len);

/**
 * @ingroup HybridDilithium
 * @brief Load a Dilithium signature provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sig Secret key to be filled (the caller must have it allocated)
 * @param [in] dilithium_src_sig Buffer that holds the Dilithium signature to be
 *	       imported
 * @param [in] dilithium_src_sig_len Buffer length that holds the Dilithium
 *	       signature to be imported
 * @param [in] ed25519_src_sig Buffer that holds the ED25519 signature to be
 *	       imported
 * @param [in] ed25519_src_sig_len Buffer length that holds the ED25519
 *	       signature to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_dilithium_ed25519_sig_load(struct lc_dilithium_ed25519_sig *sig,
				  const uint8_t *dilithium_src_sig,
				  size_t dilithium_src_sig_len,
				  const uint8_t *ed25519_src_sig,
				  size_t ed25519_src_sig_len);

/**
 * @ingroup HybridDilithium
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] dilithium_key Dilithium key pointer
 * @param [out] dilithium_key_len Length of the key buffer
 * @param [out] ed25519_key ED25519 key pointer
 * @param [out] ed25519_key_len ED25519 of the key buffer
 * @param [in] sk Dilithium secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_dilithium_ed25519_sk_ptr(uint8_t **dilithium_key,
				size_t *dilithium_key_len,
				uint8_t **ed25519_key, size_t *ed25519_key_len,
				struct lc_dilithium_ed25519_sk *sk);

/**
 * @ingroup HybridDilithium
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] dilithium_key Dilithium key pointer
 * @param [out] dilithium_key_len Length of the key buffer
 * @param [out] ed25519_key ED25519 key pointer
 * @param [out] ed25519_key_len ED25519 of the key buffer
 * @param [in] pk Dilithium publi key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_dilithium_ed25519_pk_ptr(uint8_t **dilithium_key,
				size_t *dilithium_key_len,
				uint8_t **ed25519_key, size_t *ed25519_key_len,
				struct lc_dilithium_ed25519_pk *pk);

/**
 * @ingroup HybridDilithium
 * @brief Obtain the reference to the Dilithium signature and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto signature,
 * too.
 *
 * @param [out] dilithium_sig Dilithium signature pointer
 * @param [out] dilithium_sig_len Length of the signature buffer
 * @param [out] ed25519_sig ED25519 signature pointer
 * @param [out] ed25519_sig_len ED25519 of the signature buffer
 * @param [in] sig Dilithium signature from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_dilithium_ed25519_sig_ptr(uint8_t **dilithium_sig,
				 size_t *dilithium_sig_len,
				 uint8_t **ed25519_sig, size_t *ed25519_sig_len,
				 struct lc_dilithium_ed25519_sig *sig);

/**
 * @ingroup HybridDilithium
 * @brief Generates Dilithium public and private key.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] dilithium_type type of the Dilithium key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_keypair(struct lc_dilithium_ed25519_pk *pk,
				 struct lc_dilithium_ed25519_sk *sk,
				 struct lc_rng_ctx *rng_ctx,
				 enum lc_dilithium_type dilithium_type);

/**
 * @ingroup HybridDilithium
 * @brief Computes signature in one shot
 *
 * \note The one-shot API provides the algorithm of Composite-ML-DSA as outlined
 * in https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html
 *
 * @param [out] sig pointer to output signature
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_sign(struct lc_dilithium_ed25519_sig *sig,
			      const uint8_t *m, size_t mlen,
			      const struct lc_dilithium_ed25519_sk *sk,
			      struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup HybridDilithium
 * @brief Computes signature with Dilithium context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * \note The one-shot API provides the algorithm of Composite-ML-DSA as outlined
 * in https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html
 * If the caller specifies a hash algorithm as pre-hash algorithm in the context
 * via \p lc_dilithium_ctx_hash then *only* the ML-DSA part is affected and
 * changed into a HashML-DSA which implies that the resulting operation is still
 * Composite-ML-DSA but with a HashML-DSA used internally - i.e. the resulting
 * algorithm does not comply to any standard. Therefore, it is best to not
 * use this method.
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx reference to the allocated Dilithium context handle
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_sign_ctx(struct lc_dilithium_ed25519_sig *sig,
				  struct lc_dilithium_ed25519_ctx *ctx,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_ed25519_sk *sk,
				  struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup HybridDilithium
 * @brief Initializes signature operation in stream mode
 *
 * \note The stream API provides the algorithm of HashComposite-ML-DSA as
 * outlined in
 * https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html.
 * The reason is that ED25519 cannot operate in stream mode and thus must be
 * turned into using a pre-hashed message.
 *
 * @param [in] ctx Dilithium-ED25519 context pointer
 * @param [in] sk pointer to bit-packed secret key
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_sign_init(struct lc_dilithium_ed25519_ctx *ctx,
				   const struct lc_dilithium_ed25519_sk *sk);

/**
 * @ingroup HybridDilithium
 * @brief Updates signature in stream mode
 *
 * @param [in] ctx Dilithium-ED25519 context pointer
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_sign_update(struct lc_dilithium_ed25519_ctx *ctx,
				     const uint8_t *m, size_t mlen);

/**
 * @ingroup HybridDilithium
 * @brief Computes signature in stream mode
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx Dilithium-ED25519 context pointer
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_sign_final(struct lc_dilithium_ed25519_sig *sig,
				    struct lc_dilithium_ed25519_ctx *ctx,
				    const struct lc_dilithium_ed25519_sk *sk,
				    struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup HybridDilithium
 * @brief Verifies signature in one shot
 *
 * \note The one-shot API provides the algorithm of Composite-ML-DSA as outlined
 * in https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html
 *
 * @param [in] sig pointer to input signature
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_dilithium_ed25519_verify(const struct lc_dilithium_ed25519_sig *sig,
				const uint8_t *m, size_t mlen,
				const struct lc_dilithium_ed25519_pk *pk);

/**
 * @ingroup HybridDilithium
 * @brief Verifies signature with Dilithium context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * \note The one-shot API provides the algorithm of Composite-ML-DSA as outlined
 * in https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html
 * If the caller specifies a hash algorithm as pre-hash algorithm in the context
 * via \p lc_dilithium_ctx_hash then *only* the ML-DSA part is affected and
 * changed into a HashML-DSA which implies that the resulting operation is still
 * Composite-ML-DSA but with a HashML-DSA used internally - i.e. the resulting
 * algorithm does not comply to any standard. Therefore, it is best to not
 * use this method.
 *
 * @param [in] sig pointer to input signature
 * @param [in] ctx reference to the allocated Dilithium context handle
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_dilithium_ed25519_verify_ctx(const struct lc_dilithium_ed25519_sig *sig,
				    struct lc_dilithium_ed25519_ctx *ctx,
				    const uint8_t *m, size_t mlen,
				    const struct lc_dilithium_ed25519_pk *pk);

/**
 * @ingroup HybridDilithium
 * @brief Initializes signature verification operation in stream mode
 *
 * \note The stream API provides the algorithm of HashComposite-ML-DSA as
 * outlined in
 * https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html.
 * The reason is that ED25519 cannot operate in stream mode and thus must be
 * turned into using a pre-hashed message.
 *
 * @param [in] ctx Dilithium-ED25519 context pointer
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_verify_init(struct lc_dilithium_ed25519_ctx *ctx,
				     const struct lc_dilithium_ed25519_pk *pk);

/**
 * @ingroup HybridDilithium
 * @brief Updates signature verification in stream mode
 *
 * @param [in] ctx Dilithium-ED25519 context pointer
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int lc_dilithium_ed25519_verify_update(struct lc_dilithium_ed25519_ctx *ctx,
				       const uint8_t *m, size_t mlen);

/**
 * @ingroup HybridDilithium
 * @brief Verifies signature in stream mode
 *
 * @param [in] sig pointer to input signatur
 * @param [in] ctx Dilithium-ED25519 context pointer
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_dilithium_ed25519_verify_final(const struct lc_dilithium_ed25519_sig *sig,
				      struct lc_dilithium_ed25519_ctx *ctx,
				      const struct lc_dilithium_ed25519_pk *pk);

#endif /* LC_DILITHIUM_ED25519_SIG */

#ifdef __cplusplus
}
#endif

#endif /* LC_DILITHIUM_H */
