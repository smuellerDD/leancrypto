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
 * https://github.com/pq-crystals/sphincs
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef LC_SPHINCS_H
#define LC_SPHINCS_H

#include "ext_headers.h"

#if defined __has_include
#if __has_include("lc_sphincs_shake_256s.h")
#include "lc_sphincs_shake_256s.h"
#define LC_SPHINCS_SHAKE_256s_ENABLED
#endif
#if __has_include("lc_sphincs_shake_256f.h")
#include "lc_sphincs_shake_256f.h"
#define LC_SPHINCS_SHAKE_256f_ENABLED
#endif
#if __has_include("lc_sphincs_shake_192s.h")
#include "lc_sphincs_shake_192s.h"
#define LC_SPHINCS_SHAKE_192s_ENABLED
#endif
#if __has_include("lc_sphincs_shake_192f.h")
#include "lc_sphincs_shake_192f.h"
#define LC_SPHINCS_SHAKE_192f_ENABLED
#endif
#if __has_include("lc_sphincs_shake_128s.h")
#include "lc_sphincs_shake_128s.h"
#define LC_SPHINCS_SHAKE_128s_ENABLED
#endif
#if __has_include("lc_sphincs_shake_128f.h")
#include "lc_sphincs_shake_128f.h"
#define LC_SPHINCS_SHAKE_128f_ENABLED
#endif
#else
#error "Compiler misses __has_include"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum lc_sphincs_type {
	/** Unknown key type */
	LC_SPHINCS_UNKNOWN,
	/** Sphincs 256s using SHAKE for signature operation */
	LC_SPHINCS_SHAKE_256s,
	/** Sphincs 256f using SHAKE for signature operation */
	LC_SPHINCS_SHAKE_256f,
	/** Sphincs 192s using SHAKE for signature operation */
	LC_SPHINCS_SHAKE_192s,
	/** Sphincs 192f using SHAKE for signature operation */
	LC_SPHINCS_SHAKE_192f,
	/** Sphincs 128s using SHAKE for signature operation */
	LC_SPHINCS_SHAKE_128s,
	/** Sphincs 128f using SHAKE for signature operation */
	LC_SPHINCS_SHAKE_128f,
};

/** @defgroup Sphincs SLH-DSA Signature Mechanism
 *
 * Leancrypto implements SLH-DSA (also known as Sphincs Plus). In the following
 * the term "Sphincs" is used to denote the reference to Sphincs Plus.
 *
 * Sphincs API concept
 *
 * The Sphincs API is accessible via the following header files with the
 * mentioned purpose.
 *
 * * lc_sphincs.h: This API is the generic API allowing the caller to select
 *   which Sphincs type (Sphincs 256s, 256f, 192s, 192f, 128s, 128f) are to be
 *   used. The selection is made either with the flag specified during key
 *   generation or by matching the size of the imported data with the different
 *   lc_sphincs_*_load API calls. All remaining APIs take the information about
 *   the Sphincs type from the provided input data.
 *
 *   This header file only provides inline functions which selectively call
 *   the API provided with the header files below.
 *
 * * lc_sphincs_shake_256s.h: Direct access to Sphincs 256s using SHAKE.
 *
 * * lc_sphincs_shake_256f.h: Direct access to Sphincs 256f using SHAKE.
 *
 * * lc_sphincs_shake_192s.h: Direct access to Sphincs 192s using SHAKE.
 *
 * * lc_sphincs_shake_192f.h: Direct access to Sphincs 192f using SHAKE.
 *
 * * lc_sphincs_shake_128s.h: Direct access to Sphincs 128s using SHAKE.
 *
 * * lc_sphincs_shake_128f.h: Direct access to Sphincs 128f using SHAKE.
 *
 * To support the stream mode of the Sphincs signature operation, a
 * context structure is required. This context structure can be allocated either
 * on the stack or heap with \p LC_SPHINCS_CTX_ON_STACK or
 * \p lc_sphincs_ctx_alloc. The context should be zeroized
 * and freed (only for heap) with \p lc_sphincs_ctx_zero or
 * \p lc_sphincs_ctx_zero_free.
 */

/**
 * @brief Sphincs secret key
 */
struct lc_sphincs_sk {
	enum lc_sphincs_type sphincs_type;
	union {
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		struct lc_sphincs_shake_256s_sk sk_shake_256s;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		struct lc_sphincs_shake_256f_sk sk_shake_256f;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		struct lc_sphincs_shake_192s_sk sk_shake_192s;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		struct lc_sphincs_shake_192f_sk sk_shake_192f;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		struct lc_sphincs_shake_128s_sk sk_shake_128s;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		struct lc_sphincs_shake_128f_sk sk_shake_128f;
#endif
	} key;
};

/**
 * @brief Sphincs public key
 */
struct lc_sphincs_pk {
	enum lc_sphincs_type sphincs_type;
	union {
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		struct lc_sphincs_shake_256s_pk pk_shake_256s;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		struct lc_sphincs_shake_256f_pk pk_shake_256f;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		struct lc_sphincs_shake_192s_pk pk_shake_192s;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		struct lc_sphincs_shake_192f_pk pk_shake_192f;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		struct lc_sphincs_shake_128s_pk pk_shake_128s;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		struct lc_sphincs_shake_128f_pk pk_shake_128f;
#endif
	} key;
};

/**
 * @brief Sphincs signature
 */
struct lc_sphincs_sig {
	enum lc_sphincs_type sphincs_type;
	union {
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		struct lc_sphincs_shake_256s_sig sig_shake_256s;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		struct lc_sphincs_shake_256f_sig sig_shake_256f;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		struct lc_sphincs_shake_192s_sig sig_shake_192s;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		struct lc_sphincs_shake_192f_sig sig_shake_192f;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		struct lc_sphincs_shake_128s_sig sig_shake_128s;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		struct lc_sphincs_shake_128f_sig sig_shake_128f;
#endif
	} sig;
};

/**
 * @ingroup Sphincs
 * @brief Allocates Sphincs context on heap
 *
 * @param [out] ctx Sphincs context pointer
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sphincs_ctx_alloc(struct lc_sphincs_ctx **ctx);

/**
 * @ingroup Sphincs
 * @brief Zeroizes and frees Sphincs context on heap
 *
 * @param [out] ctx Sphincs context pointer
 */
void lc_sphincs_ctx_zero_free(struct lc_sphincs_ctx *ctx);

/**
 * @ingroup Sphincs
 * @brief Zeroizes Sphincs context either on heap or on stack
 *
 * @param [out] ctx Sphincs context pointer
 */
void lc_sphincs_ctx_zero(struct lc_sphincs_ctx *ctx);

/**
 * @ingroup Sphincs
 * @brief Mark the Sphincs context to execute SLH-DSA.Sign_internal /
 *	  SLH-DSA.Verify_internal.
 *
 * @param [in] ctx Sphincs context
 */
void lc_sphincs_ctx_internal(struct lc_sphincs_ctx *ctx);

/**
 * @ingroup Sphincs
 * @brief Set the hash type that was used for pre-hashing the message. The
 *	  message digest is used with the HashSLH-DSA. The message digest
 *	  is to be provided via the message pointer in the sign/verify APIs.
 *
 * @param [in] ctx Sphincs context
 * @param [in] hash Hash context referencing the used hash for pre-hashing the
 *		    message
 */
void lc_sphincs_ctx_hash(struct lc_sphincs_ctx *ctx,
			 const struct lc_hash *hash);

/**
 * @ingroup Sphincs
 * @brief Specify the optional user context string to be applied with the
 *	  Sphincs signature operation.
 *
 * @param [in] ctx Sphincs context
 * @param [in] userctx User context string
 * @param [in] userctxlen Size of the user context string
 */
void lc_sphincs_ctx_userctx(struct lc_sphincs_ctx *ctx, const uint8_t *userctx,
			    size_t userctxlen);

/**
 * @ingroup Sphincs
 * @brief Obtain Sphincs type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_sphincs_type lc_sphincs_sk_type(const struct lc_sphincs_sk *sk);

/**
 * @ingroup Sphincs
 * @brief Obtain Sphincs type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_sphincs_type lc_sphincs_pk_type(const struct lc_sphincs_pk *pk);

/**
 * @ingroup Sphincs
 * @brief Obtain Sphincs type from signature
 *
 * @param [in] sig Signature from which the type is to be obtained
 *
 * @return key type
 */
enum lc_sphincs_type lc_sphincs_sig_type(const struct lc_sphincs_sig *sig);

/**
 * @ingroup Sphincs
 * @brief Return the size of the Sphincs secret key.
 *
 * @param [in] sphincs_type Sphincs type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int lc_sphincs_sk_size(enum lc_sphincs_type sphincs_type);

/**
 * @ingroup Sphincs
 * @brief Return the size of the Sphincs public key.
 *
 * @param [in] sphincs_type Sphincs type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int lc_sphincs_pk_size(enum lc_sphincs_type sphincs_type);

/**
 * @ingroup Sphincs
 * @brief Return the size of the Sphincs signature.
 *
 * @param [in] sphincs_type Sphincs type for which the size is requested
 *
 * @return requested size
 */
LC_PURE unsigned int lc_sphincs_sig_size(enum lc_sphincs_type sphincs_type);

/**
 * @ingroup Sphincs
 * @brief Load a Sphincs secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_sphincs_sk_load(struct lc_sphincs_sk *sk, const uint8_t *src_key,
		       size_t src_key_len);

/**
 * @ingroup Sphincs
 * @brief Set Sphincs key type to fast
 *
 * When loading a secret key, the load mechanism cannot detect whether the
 * key is to be used for the fast or small Sphincs operation (e.g. 256f vs
 * 256s). This API allows the caller to make the setting after key loading.
 * The library uses that decision for further operations.
 *
 * @param [in] sk Secret key to be set
 *
 * @return 0 on success or < 0 on error
 */
int lc_sphincs_sk_set_keytype_fast(struct lc_sphincs_sk *sk);

/**
 * @ingroup Sphincs
 * @brief Set Sphincs key type to small
 *
 * When loading a secret key, the load mechanism cannot detect whether the
 * key is to be used for the fast or small Sphincs operation (e.g. 256f vs
 * 256s). This API allows the caller to make the setting after key loading.
 * The library uses that decision for further operations.
 *
 * @param [in] sk Secret key to be set
 *
 * @return 0 on success or < 0 on error
 */
int lc_sphincs_sk_set_keytype_small(struct lc_sphincs_sk *sk);

/**
 * @ingroup Sphincs
 * @brief Load a Sphincs public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_sphincs_pk_load(struct lc_sphincs_pk *pk, const uint8_t *src_key,
		       size_t src_key_len);

/**
 * @ingroup Sphincs
 * @brief Set Sphincs key type to fast
 *
 * When loading a public key, the load mechanism cannot detect whether the
 * key is to be used for the fast or small Sphincs operation (e.g. 256f vs
 * 256s). This API allows the caller to make the setting after key loading.
 * The library uses that decision for further operations.
 *
 * @param [in] pk Public key to be set
 *
 * @return 0 on success or < 0 on error
 */
int lc_sphincs_pk_set_keytype_fast(struct lc_sphincs_pk *pk);

/**
 * @ingroup Sphincs
 * @brief Set Sphincs key type to small
 *
 * When loading a public key, the load mechanism cannot detect whether the
 * key is to be used for the fast or small Sphincs operation (e.g. 256f vs
 * 256s). This API allows the caller to make the setting after key loading.
 * The library uses that decision for further operations.
 *
 * @param [in] pk Public key to be set
 *
 * @return 0 on success or < 0 on error
 */
int lc_sphincs_pk_set_keytype_small(struct lc_sphincs_pk *pk);

/**
 * @ingroup Sphincs
 * @brief Load a Sphincs signature provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sig Secret key to be filled (the caller must have it allocated)
 * @param [in] src_sig Buffer that holds the signature to be imported
 * @param [in] src_sig_len Buffer length that holds the signature to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_sphincs_sig_load(struct lc_sphincs_sig *sig, const uint8_t *src_sig,
			size_t src_sig_len);

/**
 * @ingroup Sphincs
 * @brief Obtain the reference to the Sphincs key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] sphincs_key Sphincs key pointer
 * @param [out] sphincs_key_len Length of the key buffer
 * @param [in] sk Sphincs secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_sphincs_sk_ptr(uint8_t **sphincs_key, size_t *sphincs_key_len,
		      struct lc_sphincs_sk *sk);

/**
 * @ingroup Sphincs
 * @brief Obtain the reference to the Sphincs key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] sphincs_key Sphincs key pointer
 * @param [out] sphincs_key_len Length of the key buffer
 * @param [in] pk Sphincs publi key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_sphincs_pk_ptr(uint8_t **sphincs_key, size_t *sphincs_key_len,
		      struct lc_sphincs_pk *pk);

/**
 * @ingroup Sphincs
 * @brief Obtain the reference to the Sphincs signature and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto signature,
 * too.
 *
 * @param [out] sphincs_sig Sphincs signature pointer
 * @param [out] sphincs_sig_len Length of the signature buffer
 * @param [in] sig Sphincs signature from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_sphincs_sig_ptr(uint8_t **sphincs_sig, size_t *sphincs_sig_len,
		       struct lc_sphincs_sig *sig);

/**
 * @ingroup Sphincs
 * @brief Generates Sphincs public and private key.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] sphincs_type type of the Sphincs key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sphincs_keypair(struct lc_sphincs_pk *pk, struct lc_sphincs_sk *sk,
		       struct lc_rng_ctx *rng_ctx,
		       enum lc_sphincs_type sphincs_type);

/**
 * @ingroup Sphincs
 * @brief Generates Sphincs public and private key from a given seed.
 *
 * \warning FIPS 205 does not allow such a call. Therefore, this call will
 * always return -EOPNOTSUPP. The call is provided to allow seampless switch
 * from ML-DSA to SLH-DSA and back.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] seed buffer with the seed data which must be exactly 32 bytes
 *		    in size
 * @param [in] seedlen length of the seed buffer
 * @param [in] sphincs_type type of the Sphincs key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sphincs_keypair_from_seed(struct lc_sphincs_pk *pk,
				 struct lc_sphincs_sk *sk, const uint8_t *seed,
				 size_t seedlen,
				 enum lc_sphincs_type sphincs_type);

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
int lc_sphincs_pct(const struct lc_sphincs_pk *pk,
		   const struct lc_sphincs_sk *sk);

/**
 * @ingroup Sphincs
 * @brief Computes signature in one shot
 *
 * @param [out] sig pointer to output signature
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 * @param [in] sk pointer to secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sphincs_sign(struct lc_sphincs_sig *sig, const uint8_t *m, size_t mlen,
		    const struct lc_sphincs_sk *sk, struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup Sphincs
 * @brief Computes signature woth user context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * Using the ctx structure, the caller can select 3 different types of SLH-DSA:
 *
 * * ctx->sphincs_prehash_type set to a hash type, HashSLH-DSA is assumed which
 *   implies that the message m must be exactly digest size (FIPS 204 section
 *   5.4)
 *
 * * ctx->ml_dsa_internal set to 1, the SLH-DSA.Sign_internal and
 *   .Verify_internal are executed (FIPS 204 chapter 6)
 *
 * * both aforementioned parameter set to NULL / 0, SLH-DSA.Sign and
 *   SLH-DSA.Verify are executed (FIPS 204 sections 5.2 and 5.3)
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx reference to the allocated Sphincs context handle
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 * @param [in] sk pointer to secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sphincs_sign_ctx(struct lc_sphincs_sig *sig, struct lc_sphincs_ctx *ctx,
			const uint8_t *m, size_t mlen,
			const struct lc_sphincs_sk *sk,
			struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup Sphincs
 * @brief Initializes a signature operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_sphincs_sign_update and lc_sphincs_sign_final.
 *
 * \note
 * \parblock
 * The use of the init/update/final API implies that automatically
 * HashSLH-DSA is used. This is due to the fact that SLH-DSA cannot be used
 * in the init/update/final mode due to mathematical issues. By default, the
 * following hashes are used which are compliant to the requirement that the
 * message digest must be twice as large as the parameter n:
 *
 * * Sphincs 256s/f: SHA3-512
 * * Sphincs 192s/f: SHA3-384
 * * Sphincs 128s/f: SHA3-256
 *
 * It is permissible for the caller to select other message digest algorithms
 * by using setting the requested algorithm in the ctx using the
 * lc_sphincs_ctx_hash method *before* this init function is used. But mind
 * the basic requirement that the message digest size must be at least twice
 * the parameter n! This is checked by leancrypto during the signature
 * generation.
 * \endparblock
 *
 * @param [in,out] ctx pointer Sphincs context
 * @param [in] sk pointer to secret key
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
int lc_sphincs_sign_init(struct lc_sphincs_ctx *ctx,
			 const struct lc_sphincs_sk *sk);

/**
 * @ingroup Sphincs
 * @brief Add more data to an already initialized signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_sphincs_sign_init and lc_sphincs_sign_final.
 *
 * @param [in] ctx pointer to Sphincs context that was initialized with
 *	      	   lc_sphincs_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sphincs_sign_update(struct lc_sphincs_ctx *ctx, const uint8_t *m,
			   size_t mlen);

/**
 * @ingroup Sphincs
 * @brief Computes signature
 *
 * @param [out] sig pointer to output signature
 * @param [in] ctx pointer to Sphincs context that was initialized with
 *	      	   lc_sphincs_sign_init and filled with
 * 		   lc_sphincs_sign_update
 * @param [in] sk pointer to secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sphincs_sign_final(struct lc_sphincs_sig *sig,
			  struct lc_sphincs_ctx *ctx,
			  const struct lc_sphincs_sk *sk,
			  struct lc_rng_ctx *rng_ctx);

/**
 * @ingroup Sphincs
 * @brief Verifies signature in one shot
 *
 * @param [in] sig pointer to input signature
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_sphincs_verify(const struct lc_sphincs_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_sphincs_pk *pk);

/**
 * @ingroup Sphincs
 * @brief Verifies signature with Sphincs context in one shot
 *
 * This API allows the caller to provide an arbitrary context buffer which
 * is hashed together with the message to form the message digest to be signed.
 *
 * @param [in] sig pointer to input signature
 * @param [in] ctx reference to the allocated Sphincs context handle
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_sphincs_verify_ctx(const struct lc_sphincs_sig *sig,
			  struct lc_sphincs_ctx *ctx, const uint8_t *m,
			  size_t mlen, const struct lc_sphincs_pk *pk);

/**
 * @ingroup Sphincs
 * @brief Initializes a signature verification operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_sphincs_verify_update and
 * lc_sphincs_verify_final.
 *
 * \note
 * \parblock
 * The use of the init/update/final API implies that automatically
 * HashSLH-DSA is used. This is due to the fact that SLH-DSA cannot be used
 * in the init/update/final mode due to mathematical issues. By default, the
 * following hashes are used which are compliant to the requirement that the
 * message digest must be twice as large as the parameter n:
 *
 * * Sphincs 256s/f: SHA3-512
 * * Sphincs 192s/f: SHA3-384
 * * Sphincs 128s/f: SHA3-256
 *
 * It is permissible for the caller to select other message digest algorithms
 * by using setting the requested algorithm in the ctx using the
 * lc_sphincs_ctx_hash method *before* this init function is used.But mind
 * the basic requirement that the message digest size must be at least twice
 * the parameter n! This is checked by leancrypto during the signature
 * verification.
 * \endparblock
 *
 * @param [in,out] ctx pointer to an allocated Sphincs context
 * @param [in] pk pointer to public key
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
int lc_sphincs_verify_init(struct lc_sphincs_ctx *ctx,
			   const struct lc_sphincs_pk *pk);

/**
 * @ingroup Sphincs
 * @brief Add more data to an already initialized signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_sphincs_verify_init and
 * lc_sphincs_verify_final.
 *
 * @param [in] ctx pointer to Sphincs context that was initialized with
 *		   lc_sphincs_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sphincs_verify_update(struct lc_sphincs_ctx *ctx, const uint8_t *m,
			     size_t mlen);

/**
 * @ingroup Sphincs
 * @brief Verifies signature
 *
 * @param [in] sig pointer to output signature
 * @param [in] ctx pointer to Sphincs context that was initialized with
 *		   lc_sphincs_sign_init and filled with
 *		   lc_sphincs_sign_update
 * @param [in] pk pointer to public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
int lc_sphincs_verify_final(const struct lc_sphincs_sig *sig,
			    struct lc_sphincs_ctx *ctx,
			    const struct lc_sphincs_pk *pk);

#ifdef __cplusplus
}
#endif

#endif /* LC_SPHINCS_H */
