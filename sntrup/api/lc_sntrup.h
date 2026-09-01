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

#ifndef LC_SNTRUP_H
#define LC_SNTRUP_H

#include "ext_headers.h"
#include "lc_rng.h"

#if defined __has_include
#if __has_include("lc_sntrup_1277.h")
#include "lc_sntrup_1277.h"
#define LC_SNTRUP_1277_ENABLED
#endif
#if __has_include("lc_sntrup_1013.h")
#include "lc_sntrup_1013.h"
#define LC_SNTRUP_1013_ENABLED
#endif
#if __has_include("lc_sntrup_953.h")
#include "lc_sntrup_953.h"
#define LC_SNTRUP_953_ENABLED
#endif
#if __has_include("lc_sntrup_857.h")
#include "lc_sntrup_857.h"
#define LC_SNTRUP_857_ENABLED
#endif
#if __has_include("lc_sntrup_761.h")
#include "lc_sntrup_761.h"
#define LC_SNTRUP_761_ENABLED
#endif
#else
#error "Compiler misses __has_include"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum lc_sntrup_type {
	/** Unknown key type */
	LC_SNTRUP_UNKNOWN,
	/** SNTRUP 1277 */
	LC_SNTRUP_1277,
	/** SNTRUP 1013 */
	LC_SNTRUP_1013,
	/** SNTRUP 953 */
	LC_SNTRUP_953,
	/** SNTRUP 857 */
	LC_SNTRUP_857,
	/** SNTRUP 761 */
	LC_SNTRUP_761,
};

/** @defgroup SNTRUP SNTRUP Key Encapsulation Mechanism
 *
 * SNTRUP API concept
 *
 * The SNTRUP API is accessible via the following header files with the
 * mentioned purpose.
 *
 * * lc_sntrup.h: This API is the generic API allowing the caller to select
 *   which SNTRUP type (SNTRUP-1277, -1013, -953, -857 or -761) are to be used.
 *   The selection is made either with the flag specified during key generation
 *   or by matching the size of the imported data with the different
 *   lc_sntrup_*_load API calls. All remaining APIs take the information about
 *   the SNTRUP type from the provided input data.
 *
 *   This header file only provides inline functions which selectively call
 *   the API provided with the header files below.
 *
 * * lc_sntrup_1277.h: Direct access to SNTRUP-1277.
 *
 * * lc_sntrup_1013.h: Direct access to SNTRUP-1013.
 *
 * * lc_sntrup_953.h: Direct access to SNTRUP-953.
 *
 * * lc_sntrup_857.h: Direct access to SNTRUP-857.
 *
 * * lc_sntrup_761.h: Direct access to SNTRUP-761.
 */

/************************************* KEM ************************************/
/**
 * @brief SNTRUP secret key
 */
struct lc_sntrup_sk {
	enum lc_sntrup_type sntrup_type;
	union {
#ifdef LC_SNTRUP_1277_ENABLED
		struct lc_sntrup_1277_sk sk_sntrup_1277;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
		struct lc_sntrup_1013_sk sk_sntrup_1013;
#endif
#ifdef LC_SNTRUP_953_ENABLED
		struct lc_sntrup_953_sk sk_sntrup_953;
#endif
#ifdef LC_SNTRUP_857_ENABLED
		struct lc_sntrup_857_sk sk_sntrup_857;
#endif
#ifdef LC_SNTRUP_761_ENABLED
		struct lc_sntrup_761_sk sk_sntrup_761;
#endif
	} key;
};

/**
 * @brief SNTRUP public key
 */
struct lc_sntrup_pk {
	enum lc_sntrup_type sntrup_type;
	union {
#ifdef LC_SNTRUP_1277_ENABLED
		struct lc_sntrup_1277_pk pk_sntrup_1277;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
		struct lc_sntrup_1013_pk pk_sntrup_1013;
#endif
#ifdef LC_SNTRUP_953_ENABLED
		struct lc_sntrup_953_pk pk_sntrup_953;
#endif
#ifdef LC_SNTRUP_857_ENABLED
		struct lc_sntrup_857_pk pk_sntrup_857;
#endif
#ifdef LC_SNTRUP_761_ENABLED
		struct lc_sntrup_761_pk pk_sntrup_761;
#endif
	} key;
};

/**
 * @brief SNTRUP ciphertext
 */
struct lc_sntrup_ct {
	enum lc_sntrup_type sntrup_type;
	union {
#ifdef LC_SNTRUP_1277_ENABLED
		struct lc_sntrup_1277_ct ct_sntrup_1277;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
		struct lc_sntrup_1013_ct ct_sntrup_1013;
#endif
#ifdef LC_SNTRUP_953_ENABLED
		struct lc_sntrup_953_ct ct_sntrup_953;
#endif
#ifdef LC_SNTRUP_857_ENABLED
		struct lc_sntrup_857_ct ct_sntrup_857;
#endif
#ifdef LC_SNTRUP_761_ENABLED
		struct lc_sntrup_761_ct ct_sntrup_761;
#endif
	} key;
};

/**
 * @brief SNTRUP shared secret
 */
struct lc_sntrup_ss {
	enum lc_sntrup_type sntrup_type;
	union {
#ifdef LC_SNTRUP_1277_ENABLED
		struct lc_sntrup_1277_ss ss_sntrup_1277;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
		struct lc_sntrup_1013_ss ss_sntrup_1013;
#endif
#ifdef LC_SNTRUP_953_ENABLED
		struct lc_sntrup_953_ss ss_sntrup_953;
#endif
#ifdef LC_SNTRUP_857_ENABLED
		struct lc_sntrup_857_ss ss_sntrup_857;
#endif
#ifdef LC_SNTRUP_761_ENABLED
		struct lc_sntrup_761_ss ss_sntrup_761;
#endif
	} key;
};

/**
 * @ingroup SNTRUP
 * @brief Obtain SNTRUP type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_sntrup_type lc_sntrup_sk_type(const struct lc_sntrup_sk *sk);

/**
 * @ingroup SNTRUP
 * @brief Obtain SNTRUP type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_sntrup_type lc_sntrup_pk_type(const struct lc_sntrup_pk *pk);

/**
 * @ingroup SNTRUP
 * @brief Obtain SNTRUP type from SNTRUP ciphertext
 *
 * @param [in] ct Ciphertext from which the type is to be obtained
 *
 * @return key type
 */
enum lc_sntrup_type lc_sntrup_ct_type(const struct lc_sntrup_ct *ct);

/**
 * @ingroup SNTRUP
 * @brief Obtain SNTRUP type from shared secret
 *
 * @param [in] ss Shared secret key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_sntrup_type lc_sntrup_ss_type(const struct lc_sntrup_ss *ss);

/**
 * @ingroup SNTRUP
 * @brief Return the size of the SNTRUP secret key.
 *
 * @param [in] sntrup_type SNTRUP type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
unsigned int lc_sntrup_sk_size(enum lc_sntrup_type sntrup_type);

/**
 * @ingroup SNTRUP
 * @brief Return the size of the SNTRUP public key.
 *
 * @param [in] sntrup_type SNTRUP type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
unsigned int lc_sntrup_pk_size(enum lc_sntrup_type sntrup_type);

/**
 * @ingroup SNTRUP
 * @brief Return the size of the SNTRUP ciphertext.
 *
 * @param [in] sntrup_type SNTRUP type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
unsigned int lc_sntrup_ct_size(enum lc_sntrup_type sntrup_type);

/**
 * @ingroup SNTRUP
 * @brief Return the size of the SNTRUP shared secret.
 *
 * @param [in] sntrup_type SNTRUP type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
unsigned int lc_sntrup_ss_size(enum lc_sntrup_type sntrup_type);

/**
 * @ingroup SNTRUP
 * @brief Load a SNTRUP secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_sntrup_sk_load(struct lc_sntrup_sk *sk, const uint8_t *src_key,
		      size_t src_key_len);

/**
 * @ingroup SNTRUP
 * @brief Load a SNTRUP public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Public key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_sntrup_pk_load(struct lc_sntrup_pk *pk, const uint8_t *src_key,
		      size_t src_key_len);

/**
 * @ingroup SNTRUP
 * @brief Load a SNTRUP ciphertext key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] ct SNTRUP ciphertext to be filled (the caller must have it
 *		   allocated)
 * @param [in] src_key Buffer that holds the ciphertext to be imported
 * @param [in] src_key_len Buffer length that holds the ciphertext to be
 *			   imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_sntrup_ct_load(struct lc_sntrup_ct *ct, const uint8_t *src_key,
		      size_t src_key_len);

/**
 * @ingroup SNTRUP
 * @brief Load a SNTRUP shared secret provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] ss SNTRUP shared secret to be filled (the caller must have it
 *		   allocated)
 * @param [in] src_key Buffer that holds the shared secret to be imported
 * @param [in] src_key_len Buffer length that holds the shared secret to be
 *			   imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_sntrup_ss_load(struct lc_sntrup_ss *ss, const uint8_t *src_key,
		      size_t src_key_len);

/**
 * @ingroup SNTRUP
 * @brief Obtain the reference to the SNTRUP key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] sntrup_key SNTRUP key pointer
 * @param [out] sntrup_key_len Length of the key buffer
 * @param [in] sk SNTRUP secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_sntrup_sk_ptr(uint8_t **sntrup_key, size_t *sntrup_key_len,
		     struct lc_sntrup_sk *sk);

/**
 * @ingroup SNTRUP
 * @brief Obtain the reference to the SNTRUP key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] sntrup_key SNTRUP key pointer
 * @param [out] sntrup_key_len Length of the key buffer
 * @param [in] pk SNTRUP public key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_sntrup_pk_ptr(uint8_t **sntrup_key, size_t *sntrup_key_len,
		     struct lc_sntrup_pk *pk);

/**
 * @ingroup SNTRUP
 * @brief Obtain the reference to the SNTRUP ciphertext and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto ciphertext,
 * too.
 *
 * @param [out] sntrup_ct SNTRUP ciphertext pointer
 * @param [out] sntrup_ct_len Length of the ciphertext buffer
 * @param [in] ct SNTRUP ciphertext from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_sntrup_ct_ptr(uint8_t **sntrup_ct, size_t *sntrup_ct_len,
		     struct lc_sntrup_ct *ct);

/**
 * @ingroup SNTRUP
 * @brief Obtain the reference to the SNTRUP shared secret and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto shared secret,
 * too.
 *
 * @param [out] sntrup_ss SNTRUP shared secret pointer
 * @param [out] sntrup_ss_len Length of the shared secret buffer
 * @param [in] ss SNTRUP shared secret from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_sntrup_ss_ptr(uint8_t **sntrup_ss, size_t *sntrup_ss_len,
		     struct lc_sntrup_ss *ss);

/**
 * @ingroup SNTRUP
 * @brief Generates public and private key for IND-CCA2-secure SNTRUP key
 *        encapsulation mechanism
 *
 * @param [out] pk pointer to already allocated output public key
 * @param [out] sk pointer to already allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] sntrup_type type of the SNTRUP key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int lc_sntrup_keypair(struct lc_sntrup_pk *pk, struct lc_sntrup_sk *sk,
		      struct lc_rng_ctx *rng_ctx,
		      enum lc_sntrup_type sntrup_type);

/**
 * @ingroup SNTRUP
 * @brief Key encapsulation
 *
 * Generates cipher text and shared secret for given public key.
 *
 * @param [out] ct pointer to output cipher text to used for decapsulation
 * @param [out] ss pointer to output shared secret that will be also produced
 *		   during decapsulation
 * @param [in] pk pointer to input public key
 *
 * Returns 0 (success) or < 0 on error
 */
int lc_sntrup_enc(struct lc_sntrup_ct *ct, struct lc_sntrup_ss *ss,
		  const struct lc_sntrup_pk *pk);

/**
 * @ingroup SNTRUP
 * @brief Key decapsulation
 *
 * Generates shared secret for given cipher text and private key
 *
 * @param [out] ss pointer to output shared secret that is the same as produced
 *		   during encapsulation
 * @param [in] ct pointer to input cipher text generated during encapsulation
 * @param [in] sk pointer to input private key
 *
 * @return 0
 *
 * On failure, ss will contain a pseudo-random value.
 */
int lc_sntrup_dec(struct lc_sntrup_ss *ss, const struct lc_sntrup_ct *ct,
		  const struct lc_sntrup_sk *sk);

#ifdef __cplusplus
}
#endif

#endif /* LC_SNTRUP_H */
