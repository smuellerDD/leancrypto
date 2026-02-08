/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_HQC_H
#define LC_HQC_H

#include "ext_headers.h"

#if defined __has_include
#if __has_include("lc_hqc_256.h")
#include "lc_hqc_256.h"
#define LC_HQC_256_ENABLED
#endif
#if __has_include("lc_hqc_192.h")
#include "lc_hqc_192.h"
#define LC_HQC_192_ENABLED
#endif
#if __has_include("lc_hqc_128.h")
#include "lc_hqc_128.h"
#define LC_HQC_128_ENABLED
#endif
#else
#error "Compiler misses __has_include"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum lc_hqc_type {
	LC_HQC_UNKNOWN, /** Unknown key type */
	LC_HQC_256, /** HQC 256 */
	LC_HQC_192, /** HQC 192 */
	LC_HQC_128, /** HQC 128 */
};

/** @defgroup HQC HQC Key Encapsulation Mechanism
 *
 * HQC API concept
 *
 * The HQC API is accessible via the following header files with the mentioned
 * purpose.
 *
 * * lc_hqc.h: This API is the generic API allowing the caller to select
 *   which HQC type (HQC-256, -192 or -128) are to be used. The selection is
 *   made either with the flag specified during key generation or by matching
 *   the size of the imported data with the different lc_hqc_*_load API calls.
 *   All remaining APIs take the information about the HQC type from the
 *   provided input data.
 *
 *   This header file only provides inline functions which selectively call
 *   the API provided with the header files below.
 *
 * * lc_hqc_256.h: Direct access to HQC-256.
 *
 * * lc_hqc_192.h: Direct access to HQC-192.
 *
 * * lc_hqc_128.h: Direct access to HQC-128.
 */

/************************************* KEM ************************************/
/**
 * @brief HQC secret key
 */
struct lc_hqc_sk {
	enum lc_hqc_type hqc_type;
	union {
#ifdef LC_HQC_256_ENABLED
		struct lc_hqc_256_sk sk_256;
#endif
#ifdef LC_HQC_192_ENABLED
		struct lc_hqc_192_sk sk_192;
#endif
#ifdef LC_HQC_128_ENABLED
		struct lc_hqc_128_sk sk_128;
#endif
	} key;
};

/**
 * @brief HQC public key
 */
struct lc_hqc_pk {
	enum lc_hqc_type hqc_type;
	union {
#ifdef LC_HQC_256_ENABLED
		struct lc_hqc_256_pk pk_256;
#endif
#ifdef LC_HQC_192_ENABLED
		struct lc_hqc_192_pk pk_192;
#endif
#ifdef LC_HQC_128_ENABLED
		struct lc_hqc_128_pk pk_128;
#endif
	} key;
};

/**
 * @brief HQC ciphertext
 */
struct lc_hqc_ct {
	enum lc_hqc_type hqc_type;
	union {
#ifdef LC_HQC_256_ENABLED
		struct lc_hqc_256_ct ct_256;
#endif
#ifdef LC_HQC_192_ENABLED
		struct lc_hqc_192_ct ct_192;
#endif
#ifdef LC_HQC_128_ENABLED
		struct lc_hqc_128_ct ct_128;
#endif
	} key;
};

/**
 * @brief HQC shared secret
 */
struct lc_hqc_ss {
	enum lc_hqc_type hqc_type;
	union {
#ifdef LC_HQC_256_ENABLED
		struct lc_hqc_256_ss ss_256;
#endif
#ifdef LC_HQC_192_ENABLED
		struct lc_hqc_192_ss ss_192;
#endif
#ifdef LC_HQC_128_ENABLED
		struct lc_hqc_128_ss ss_128;
#endif
	} key;
};

/**
 * @ingroup HQC
 * @brief Obtain HQC type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_hqc_type lc_hqc_sk_type(const struct lc_hqc_sk *sk);

/**
 * @ingroup HQC
 * @brief Obtain HQC type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_hqc_type lc_hqc_pk_type(const struct lc_hqc_pk *pk);

/**
 * @ingroup HQC
 * @brief Obtain HQC type from HQC ciphertext
 *
 * @param [in] ct Ciphertext from which the type is to be obtained
 *
 * @return key type
 */
enum lc_hqc_type lc_hqc_ct_type(const struct lc_hqc_ct *ct);

/**
 * @ingroup HQC
 * @brief Obtain HQC type from shared secret
 *
 * @param [in] ss Shared secret key from which the type is to be obtained
 *
 * @return key type
 */
enum lc_hqc_type lc_hqc_ss_type(const struct lc_hqc_ss *ss);

/**
 * @ingroup HQC
 * @brief Return the size of the HQC secret key.
 *
 * @param [in] hqc_type HQC type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
unsigned int lc_hqc_sk_size(enum lc_hqc_type hqc_type);

/**
 * @ingroup HQC
 * @brief Return the size of the HQC public key.
 *
 * @param [in] hqc_type HQC type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
unsigned int lc_hqc_pk_size(enum lc_hqc_type hqc_type);

/**
 * @ingroup HQC
 * @brief Return the size of the HQC ciphertext.
 *
 * @param [in] hqc_type HQC type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
unsigned int lc_hqc_ct_size(enum lc_hqc_type hqc_type);

/**
 * @ingroup HQC
 * @brief Return the size of the HQC shared secret.
 *
 * @param [in] hqc_type HQC type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
unsigned int lc_hqc_ss_size(enum lc_hqc_type hqc_type);

/**
 * @ingroup HQC
 * @brief Load a HQC secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_hqc_sk_load(struct lc_hqc_sk *sk, const uint8_t *src_key,
		   size_t src_key_len);

/**
 * @ingroup HQC
 * @brief Load a HQC public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Public key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_hqc_pk_load(struct lc_hqc_pk *pk, const uint8_t *src_key,
		   size_t src_key_len);

/**
 * @ingroup HQC
 * @brief Load a HQC ciphertext key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] ct HQC ciphertext to be filled (the caller must have it
 *		   allocated)
 * @param [in] src_key Buffer that holds the ciphertext to be imported
 * @param [in] src_key_len Buffer length that holds the ciphertext to be
 *			   imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_hqc_ct_load(struct lc_hqc_ct *ct, const uint8_t *src_key,
		   size_t src_key_len);

/**
 * @ingroup HQC
 * @brief Load a HQC shared secret provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] ss HQC shared secret to be filled (the caller must have it
 *		   allocated)
 * @param [in] src_key Buffer that holds the shared secret to be imported
 * @param [in] src_key_len Buffer length that holds the shared secret to be
 *			   imported
 *
 * @return 0 on success or < 0 on error
 */
int lc_hqc_ss_load(struct lc_hqc_ss *ss, const uint8_t *src_key,
		   size_t src_key_len);

/**
 * @ingroup HQC
 * @brief Obtain the reference to the HQC key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] hqc_key HQC key pointer
 * @param [out] hqc_key_len Length of the key buffer
 * @param [in] sk HQC secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_hqc_sk_ptr(uint8_t **hqc_key, size_t *hqc_key_len, struct lc_hqc_sk *sk);

/**
 * @ingroup HQC
 * @brief Obtain the reference to the HQC key and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] hqc_key HQC key pointer
 * @param [out] hqc_key_len Length of the key buffer
 * @param [in] pk HQC public key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_hqc_pk_ptr(uint8_t **hqc_key, size_t *hqc_key_len, struct lc_hqc_pk *pk);

/**
 * @ingroup HQC
 * @brief Obtain the reference to the HQC ciphertext and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto ciphertext,
 * too.
 *
 * @param [out] hqc_ct HQC ciphertext pointer
 * @param [out] hqc_ct_len Length of the ciphertext buffer
 * @param [in] ct HQC ciphertext from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_hqc_ct_ptr(uint8_t **hqc_ct, size_t *hqc_ct_len, struct lc_hqc_ct *ct);

/**
 * @ingroup HQC
 * @brief Obtain the reference to the HQC shared secret and its length
 *
 * \note Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto shared secret,
 * too.
 *
 * @param [out] hqc_ss HQC shared secret pointer
 * @param [out] hqc_ss_len Length of the shared secret buffer
 * @param [in] ss HQC shared secret from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
int lc_hqc_ss_ptr(uint8_t **hqc_ss, size_t *hqc_ss_len, struct lc_hqc_ss *ss);

/**
 * @ingroup HQC
 * @brief Generates public and private key for IND-CCA2-secure HQC key
 *        encapsulation mechanism
 *
 * @param [out] pk pointer to already allocated output public key
 * @param [out] sk pointer to already allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] hqc_type type of the HQC key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int lc_hqc_keypair(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
		   struct lc_rng_ctx *rng_ctx, enum lc_hqc_type hqc_type);

/**
 * @ingroup HQC
 * @brief Generates HQC public and private key from a given seed.
 *
 * The idea of the function is the allowance of FIPS 203 to maintain the seed
 * used to generate a key pair in lieu of maintaining a private key or the
 * key pair (which used much more memory). The seed must be treated equally
 * sensitive as a private key.
 *
 * The seed is generated by simply obtaining 64 bytes from a properly seeded
 * DRNG, i.e. the same way as a symmetric key would be generated.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] seed buffer with the seed data which must be exactly 64 bytes
 *		    in size
 * @param [in] seedlen length of the seed buffer
 * @param [in] hqc_type type of the HQC key to generate
 *
 * @return 0 (success) or < 0 on error
 */
int lc_hqc_keypair_from_seed(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
			     const uint8_t *seed, size_t seedlen,
			     enum lc_hqc_type hqc_type);

/**
 * @ingroup HQC
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
int lc_hqc_enc(struct lc_hqc_ct *ct, struct lc_hqc_ss *ss,
	       const struct lc_hqc_pk *pk);

/**
 * @ingroup HQC
 * @brief Key encapsulation with KDF applied to shared secret
 *
 * Generates cipher text and shared secret for given public key. The shared
 * secret is derived from the HQC SS using the KDF derived from the round 3
 * definition of HQC:
 *```
 *	SS <- KMAC256(K = HQC-SS, X = HQC-CT, L = requested SS length,
 *		      S = "HQC KEM SS")
 *```
 * @param [out] ct pointer to output cipher text to used for decapsulation
 * @param [out] ss pointer to output shared secret that will be also produced
 *		   during decapsulation
 * @param [in] ss_len length of shared secret to be generated
 * @param [in] pk pointer to input public key
 *
 * Returns 0 (success) or < 0 on error
 */
int lc_hqc_enc_kdf(struct lc_hqc_ct *ct, uint8_t *ss, size_t ss_len,
		   const struct lc_hqc_pk *pk);

/**
 * @ingroup HQC
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
int lc_hqc_dec(struct lc_hqc_ss *ss, const struct lc_hqc_ct *ct,
	       const struct lc_hqc_sk *sk);

/**
 * @ingroup HQC
 * @brief Key decapsulation with KDF applied to shared secret
 *
 * Generates cipher text and shared secret for given private key. The shared
 * secret is derived from the HQC SS using the KDF derived from the round 3
 * definition of HQC:
 *```
 *	SS <- KMAC256(K = HQC-SS, X = HQC-CT, L = requested SS length,
 *		      S = "HQC KEM SS")
 *```
 * @param [out] ss pointer to output shared secret that is the same as produced
 *		   during encapsulation
 * @param [in] ss_len length of shared secret to be generated
 * @param [in] ct pointer to input cipher text generated during encapsulation
 * @param [in] sk pointer to input private key
 *
 * @return 0
 *
 * On failure, ss will contain a pseudo-random value.
 */
int lc_hqc_dec_kdf(uint8_t *ss, size_t ss_len, const struct lc_hqc_ct *ct,
		   const struct lc_hqc_sk *sk);

enum lc_hqc_alg_operation {
	/** Unknown operation */
	lc_alg_operation_hqc_unknown,
	/** HQC: key generation operation */
	lc_alg_operation_hqc_keygen,
	/** HQC: encapsulation operation */
	lc_alg_operation_hqc_enc,
	/** HQC: decapsulation operation */
	lc_alg_operation_hqc_dec,
	/** HQC: encapsulation operation with KDF */
	lc_alg_operation_hqc_enc_kdf,
	/** HQC: decapsulation operation with KDF */
	lc_alg_operation_hqc_dec_kdf,
};

/**
 * @ingroup HQC
 * @brief Obtain algorithm status
 *
 * @param [in] hqc_type HQC algorithm type
 * @param [in] operation HQC algorithm operation
 *
 * @return algorithm status
 */
enum lc_alg_status_val
lc_hqc_alg_status(const enum lc_hqc_type hqc_type,
		  const enum lc_hqc_alg_operation operation);

#ifdef __cplusplus
}
#endif

#endif /* LC_HQC_H */
