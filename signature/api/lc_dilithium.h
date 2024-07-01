/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
	LC_DILITHIUM_UNKNOWN, /** Unknown key type */
	LC_DILITHIUM_87, /** Dilithium 87 */
	LC_DILITHIUM_65, /** Dilithium 65 */
	LC_DILITHIUM_44, /** Dilithium 44 */
};

/**
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
 * * lc_dilithium_44.h: Direct access to Dilithium 44
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
 * @brief Obtain Dilithium type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_dilithium_type lc_dilithium_sk_type(
	const struct lc_dilithium_sk *sk)
{
	if (!sk)
		return LC_DILITHIUM_UNKNOWN;
	return sk->dilithium_type;
}

/**
 * @brief Obtain Dilithium type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_dilithium_type lc_dilithium_pk_type(
	const struct lc_dilithium_pk *pk)
{
	if (!pk)
		return LC_DILITHIUM_UNKNOWN;
	return pk->dilithium_type;
}

/**
 * @brief Obtain Dilithium type from signature
 *
 * @param [in] sig Signature from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_dilithium_type lc_dilithium_sig_type(
	const struct lc_dilithium_sig *sig)
{
	if (!sig)
		return LC_DILITHIUM_UNKNOWN;
	return sig->dilithium_type;
}

/**
 * @brief Return the size of the Dilithium secret key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_dilithium_sk_size(enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_sk, key.sk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_sk, key.sk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_sk, key.sk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @brief Return the size of the Dilithium public key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_dilithium_pk_size(enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_pk, key.pk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_pk, key.pk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_pk, key.pk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @brief Return the size of the Dilithium signature.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_dilithium_sig_size(enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_sig, sig.sig_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_sig, sig.sig_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_sig, sig.sig_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @brief Load a Dilithium secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_dilithium_sk_load(struct lc_dilithium_sk *sk,
				       const uint8_t *src_key,
				       size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (src_key_len == lc_dilithium_sk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_sk *_sk = &sk->key.sk_87;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (src_key_len == lc_dilithium_sk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_sk *_sk = &sk->key.sk_65;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (src_key_len == lc_dilithium_sk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_sk *_sk = &sk->key.sk_44;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Load a Dilithium public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_dilithium_pk_load(struct lc_dilithium_pk *pk,
				       const uint8_t *src_key,
				       size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (src_key_len == lc_dilithium_pk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_pk *_pk = &pk->key.pk_87;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (src_key_len == lc_dilithium_pk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_pk *_pk = &pk->key.pk_65;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (src_key_len == lc_dilithium_pk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_pk *_pk = &pk->key.pk_44;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Load a Dilithium signature provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sig Secret key to be filled (the caller must have it allocated)
 * @param [in] src_sig Buffer that holds the signature to be imported
 * @param [in] src_sig_len Buffer length that holds the signature to be imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_dilithium_sig_load(struct lc_dilithium_sig *sig,
					const uint8_t *src_sig,
					size_t src_sig_len)
{
	if (!sig || !src_sig || src_sig_len == 0) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (src_sig_len == lc_dilithium_sig_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_sig *_sig = &sig->sig.sig_87;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (src_sig_len == lc_dilithium_sig_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_sig *_sig = &sig->sig.sig_65;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (src_sig_len == lc_dilithium_sig_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_sig *_sig = &sig->sig.sig_44;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] dilithium_key Dilithium key pointer
 * @param [out] dilithium_key_len Length of the key buffer
 * @param [in] sk Dilithium secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_dilithium_sk_ptr(uint8_t **dilithium_key,
				      size_t *dilithium_key_len,
				      struct lc_dilithium_sk *sk)
{
	if (!sk || !dilithium_key || !dilithium_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_sk *_sk = &sk->key.sk_87;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_sk *_sk = &sk->key.sk_65;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_sk *_sk = &sk->key.sk_44;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] dilithium_key Dilithium key pointer
 * @param [out] dilithium_key_len Length of the key buffer
 * @param [in] pk Dilithium publi key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_dilithium_pk_ptr(uint8_t **dilithium_key,
				      size_t *dilithium_key_len,
				      struct lc_dilithium_pk *pk)
{
	if (!pk || !dilithium_key || !dilithium_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_pk *_pk = &pk->key.pk_87;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_pk *_pk = &pk->key.pk_65;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_pk *_pk = &pk->key.pk_44;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Obtain the reference to the Dilithium signature and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto signature,
 * too.
 *
 * @param [out] dilithium_sig Dilithium signature pointer
 * @param [out] dilithium_sig_len Length of the signature buffer
 * @param [in] sig Dilithium signature from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_dilithium_sig_ptr(uint8_t **dilithium_sig,
				       size_t *dilithium_sig_len,
				       struct lc_dilithium_sig *sig)
{
	if (!sig || !dilithium_sig || !dilithium_sig_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_sig *_sig = &sig->sig.sig_87;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_sig *_sig = &sig->sig.sig_65;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_sig *_sig = &sig->sig.sig_44;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief lc_dilithium_keypair - Generates Dilithium public and private key.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] dilithium_type type of the Dilithium key to generate
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_dilithium_keypair(struct lc_dilithium_pk *pk,
				       struct lc_dilithium_sk *sk,
				       struct lc_rng_ctx *rng_ctx,
				       enum lc_dilithium_type dilithium_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_87_keypair(&pk->key.pk_87, &sk->key.sk_87,
					       rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_65_keypair(&pk->key.pk_65, &sk->key.sk_65,
					       rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_44_keypair(&pk->key.pk_44, &sk->key.sk_44,
					       rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @brief lc_dilithium_keypair_from_seed - Generates Dilithium public and
 *					   private key from a given seed.
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
static inline int
lc_dilithium_keypair_from_seed(struct lc_dilithium_pk *pk,
			       struct lc_dilithium_sk *sk, const uint8_t *seed,
			       size_t seedlen,
			       enum lc_dilithium_type dilithium_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_87_keypair_from_seed(
			&pk->key.pk_87, &sk->key.sk_87, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_65_keypair_from_seed(
			&pk->key.pk_65, &sk->key.sk_65, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_44_keypair_from_seed(
			&pk->key.pk_44, &sk->key.sk_44, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @param lc_dilithium_sign - Computes signature in one shot
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
static inline int lc_dilithium_sign(struct lc_dilithium_sig *sig,
				    const uint8_t *m, size_t mlen,
				    const struct lc_dilithium_sk *sk,
				    struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_sign(&sig->sig.sig_87, m, mlen,
					    &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_sign(&sig->sig.sig_65, m, mlen,
					    &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_sign(&sig->sig.sig_44, m, mlen,
					    &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @param lc_dilithium_sign_init - Initializes a signature operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_dilithium_sign_update and lc_dilithium_sign_final.
 *
 * @param  [in,out] hash_ctx pointer to an allocated (but not yet initialized)
 *			    hash context - this hash context MUST use
 *			    lc_shake256 as otherwise the function will return
 *			    an error.
 * @param [in] sk pointer to bit-packed secret key
 *
 * NOTE: This API call is NOT yet stable and thus will not cause a the
 *	 libraries major version to change. An update request is filed with
 *	 the FIPS 204 authors to change the cause for providing the sk parameter
 *	 in the init call. Once that change is applied, the sk parameter is
 *	 removed for good.
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
static inline int lc_dilithium_sign_init(struct lc_hash_ctx *hash_ctx,
					 const struct lc_dilithium_sk *sk)
{
	if (!sk)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_sign_init(hash_ctx, &sk->key.sk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_sign_init(hash_ctx, &sk->key.sk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_sign_init(hash_ctx, &sk->key.sk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @param lc_dilithium_sign_update - Add more data to an already initialized
 *				     signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_dilithium_sign_init and lc_dilithium_sign_final.
 *
 * @param [in,out] hash_ctx pointer to hash context that was initialized with
 *			    lc_dilithium_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_dilithium_sign_update(struct lc_hash_ctx *hash_ctx,
					   const uint8_t *m, size_t mlen)
{
#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_sign_update(hash_ctx, m, mlen);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_sign_update(hash_ctx, m, mlen);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_sign_update(hash_ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

/**
 * @param lc_dilithium_sign_final - Computes signature
 *
 * @param [out] sig pointer to output signature
 * @param [in] hash_ctx pointer to hash context that was initialized with
 *			lc_dilithium_sign_init and filled with
 *			lc_dilithium_sign_update
 * @param [in] sk pointer to bit-packed secret key
 * @param [in] rng_ctx pointer to seeded random number generator context - when
 *		       pointer is non-NULL, perform a randomized signing.
 *		       Otherwise use deterministic signing.
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_dilithium_sign_final(struct lc_dilithium_sig *sig,
					  struct lc_hash_ctx *hash_ctx,
					  const struct lc_dilithium_sk *sk,
					  struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_sign_final(&sig->sig.sig_87, hash_ctx,
						  &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_sign_final(&sig->sig.sig_65, hash_ctx,
						  &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_sign_final(&sig->sig.sig_44, hash_ctx,
						  &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @brief lc_dilithium_verify - Verifies signature in one shot
 *
 * @param [in] sig pointer to input signature
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
static inline int lc_dilithium_verify(const struct lc_dilithium_sig *sig,
				      const uint8_t *m, size_t mlen,
				      const struct lc_dilithium_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_verify(&sig->sig.sig_87, m, mlen,
					      &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_verify(&sig->sig.sig_65, m, mlen,
					      &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_verify(&sig->sig.sig_44, m, mlen,
					      &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @param lc_dilithium_verify_init - Initializes a signature verification
 * 				     operation
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_dilithium_verify_update and
 * lc_dilithium_verify_final.
 *
 * @param [in,out] hash_ctx pointer to an allocated (but not yet initialized)
 *			    hash context - this hash context MUST use
 *			    lc_shake256 as otherwise the function will return
 *			    an error.
 * @param [in] pk pointer to bit-packed public key
 *
 * NOTE: This API call is NOT yet stable and thus will not cause a the
 *	 libraries major version to change. An update request is filed with
 *	 the FIPS 204 authors to change the cause for providing the pk parameter
 *	 in the init call. Once that change is applied, the pk parameter is
 *	 removed for good.
 *
 * @return 0 (success) or < 0 on error; -EOPNOTSUPP is returned if a different
 *	   hash than lc_shake256 is used.
 */
static inline int lc_dilithium_verify_init(struct lc_hash_ctx *hash_ctx,
					   const struct lc_dilithium_pk *pk)
{
	if (!pk)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_verify_init(hash_ctx, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_verify_init(hash_ctx, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_verify_init(hash_ctx, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @param lc_dilithium_verify_update - Add more data to an already initialized
 *				       signature state
 *
 * This call is intended to support messages that are located in non-contiguous
 * places and even becomes available at different times. This call is to be
 * used together with the lc_dilithium_verify_init and
 * lc_dilithium_verify_final.
 *
 * @param [in,out] hash_ctx pointer to hash context that was initialized with
 *			    lc_dilithium_sign_init
 * @param [in] m pointer to message to be signed
 * @param [in] mlen length of message
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_dilithium_verify_update(struct lc_hash_ctx *hash_ctx,
					     const uint8_t *m, size_t mlen)
{
#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_verify_update(hash_ctx, m, mlen);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_verify_update(hash_ctx, m, mlen);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_verify_update(hash_ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

/**
 * @param lc_dilithium_verify_final - Verifies signature
 *
 * @param [in] sig pointer to output signature
 * @param [in] hash_ctx pointer to hash context that was initialized with
 *			lc_dilithium_sign_init and filled with
 *			lc_dilithium_sign_update
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
static inline int lc_dilithium_verify_final(const struct lc_dilithium_sig *sig,
					    struct lc_hash_ctx *hash_ctx,
					    const struct lc_dilithium_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_verify_final(&sig->sig.sig_87, hash_ctx,
						    &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_verify_final(&sig->sig.sig_65, hash_ctx,
						    &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_verify_final(&sig->sig.sig_44, hash_ctx,
						    &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED25519_SIG

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
 * @brief Obtain Dilithium type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_dilithium_type lc_dilithium_ed25519_sk_type(
	const struct lc_dilithium_ed25519_sk *sk)
{
	if (!sk)
		return LC_DILITHIUM_UNKNOWN;
	return sk->dilithium_type;
}

/**
 * @brief Obtain Dilithium type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_dilithium_type lc_dilithium_ed25519_pk_type(
	const struct lc_dilithium_ed25519_pk *pk)
{
	if (!pk)
		return LC_DILITHIUM_UNKNOWN;
	return pk->dilithium_type;
}

/**
 * @brief Obtain Dilithium type from signature
 *
 * @param [in] sig Signature from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_dilithium_type lc_dilithium_ed25519_sig_type(
	const struct lc_dilithium_ed25519_sig *sig)
{
	if (!sig)
		return LC_DILITHIUM_UNKNOWN;
	return sig->dilithium_type;
}

/**
 * @brief Return the size of the Dilithium secret key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_dilithium_ed25519_sk_size(enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sk,
				      key.sk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sk,
				      key.sk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sk,
				      key.sk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @brief Return the size of the Dilithium public key.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_dilithium_ed25519_pk_size(enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_pk,
				      key.pk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_pk,
				      key.pk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_pk,
				      key.pk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @brief Return the size of the Dilithium signature.
 *
 * @param [in] dilithium_type Dilithium type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_dilithium_ed25519_sig_size(enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sig,
				      sig.sig_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sig,
				      sig.sig_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sig,
				      sig.sig_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

/**
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
static inline int lc_dilithium_ed25519_sk_load(
	struct lc_dilithium_ed25519_sk *sk, const uint8_t *dilithium_src_key,
	size_t dilithium_src_key_len, const uint8_t *ed25519_src_key,
	size_t ed25519_src_key_len)
{
	if (!sk || !dilithium_src_key || !ed25519_src_key ||
	    ed25519_src_key_len != LC_ED25519_SECRETKEYBYTES) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_sk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed25519_sk *_sk = &sk->key.sk_87;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed25519.sk, ed25519_src_key,
		       ed25519_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_sk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed25519_sk *_sk = &sk->key.sk_65;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed25519.sk, ed25519_src_key,
		       ed25519_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_key_len ==
			lc_dilithium_sk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed25519_sk *_sk = &sk->key.sk_44;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed25519.sk, ed25519_src_key,
		       ed25519_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
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
static inline int lc_dilithium_ed25519_pk_load(
	struct lc_dilithium_ed25519_pk *pk, const uint8_t *dilithium_src_key,
	size_t dilithium_src_key_len, const uint8_t *ed25519_src_key,
	size_t ed25519_src_key_len)
{
	if (!pk || !dilithium_src_key || !ed25519_src_key ||
	    ed25519_src_key_len != LC_ED25519_PUBLICKEYBYTES) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed25519_pk *_pk = &pk->key.pk_87;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed25519.pk, ed25519_src_key,
		       ed25519_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed25519_pk *_pk = &pk->key.pk_65;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed25519.pk, ed25519_src_key,
		       ed25519_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed25519_pk *_pk = &pk->key.pk_44;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed25519.pk, ed25519_src_key,
		       ed25519_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
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
static inline int lc_dilithium_ed25519_sig_load(
	struct lc_dilithium_ed25519_sig *sig, const uint8_t *dilithium_src_sig,
	size_t dilithium_src_sig_len, const uint8_t *ed25519_src_sig,
	size_t ed25519_src_sig_len)
{
	if (!sig || !dilithium_src_sig || !ed25519_src_sig ||
	    ed25519_src_sig_len != LC_ED25519_SIGBYTES) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed25519_sig *_sig = &sig->sig.sig_87;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed25519.sig, ed25519_src_sig,
		       ed25519_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed25519_sig *_sig = &sig->sig.sig_65;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed25519.sig, ed25519_src_sig,
		       ed25519_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed25519_sig *_sig = &sig->sig.sig_44;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed25519.sig, ed25519_src_sig,
		       ed25519_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
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
static inline int
lc_dilithium_ed25519_sk_ptr(uint8_t **dilithium_key, size_t *dilithium_key_len,
			    uint8_t **ed25519_key, size_t *ed25519_key_len,
			    struct lc_dilithium_ed25519_sk *sk)
{
	if (!sk || !dilithium_key || !dilithium_key_len || !ed25519_key ||
	    !ed25519_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed25519_sk *_sk = &sk->key.sk_87;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed25519_key = _sk->sk_ed25519.sk;
		*ed25519_key_len = LC_ED25519_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed25519_sk *_sk = &sk->key.sk_65;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed25519_key = _sk->sk_ed25519.sk;
		*ed25519_key_len = LC_ED25519_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed25519_sk *_sk = &sk->key.sk_44;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed25519_key = _sk->sk_ed25519.sk;
		*ed25519_key_len = LC_ED25519_SECRETKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Obtain the reference to the Dilithium key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
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
static inline int
lc_dilithium_ed25519_pk_ptr(uint8_t **dilithium_key, size_t *dilithium_key_len,
			    uint8_t **ed25519_key, size_t *ed25519_key_len,
			    struct lc_dilithium_ed25519_pk *pk)
{
	if (!pk || !dilithium_key || !dilithium_key_len || !ed25519_key ||
	    !ed25519_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed25519_pk *_pk = &pk->key.pk_87;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed25519_key = _pk->pk_ed25519.pk;
		*ed25519_key_len = LC_ED25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed25519_pk *_pk = &pk->key.pk_65;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed25519_key = _pk->pk_ed25519.pk;
		*ed25519_key_len = LC_ED25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed25519_pk *_pk = &pk->key.pk_44;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed25519_key = _pk->pk_ed25519.pk;
		*ed25519_key_len = LC_ED25519_PUBLICKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Obtain the reference to the Dilithium signature and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
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
static inline int
lc_dilithium_ed25519_sig_ptr(uint8_t **dilithium_sig, size_t *dilithium_sig_len,
			     uint8_t **ed25519_sig, size_t *ed25519_sig_len,
			     struct lc_dilithium_ed25519_sig *sig)
{
	if (!sig || !dilithium_sig || !dilithium_sig_len || !ed25519_sig ||
	    !ed25519_sig_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed25519_sig *_sig = &sig->sig.sig_87;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed25519_sig = _sig->sig_ed25519.sig;
		*ed25519_sig_len = LC_ED25519_SIGBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed25519_sig *_sig = &sig->sig.sig_65;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed25519_sig = _sig->sig_ed25519.sig;
		*ed25519_sig_len = LC_ED25519_SIGBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed25519_sig *_sig = &sig->sig.sig_44;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed25519_sig = _sig->sig_ed25519.sig;
		*ed25519_sig_len = LC_ED25519_SIGBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief lc_dilithium_ed25519_keypair - Generates Dilithium public and private
 *					 key.
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] dilithium_type type of the Dilithium key to generate
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_dilithium_ed25519_keypair(
	struct lc_dilithium_ed25519_pk *pk, struct lc_dilithium_ed25519_sk *sk,
	struct lc_rng_ctx *rng_ctx, enum lc_dilithium_type dilithium_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_87_ed25519_keypair(&pk->key.pk_87,
						       &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_65_ed25519_keypair(&pk->key.pk_65,
						       &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		pk->dilithium_type = dilithium_type;
		sk->dilithium_type = dilithium_type;
		return lc_dilithium_44_ed25519_keypair(&pk->key.pk_44,
						       &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @param lc_dilithium_ed25519_sign - Computes signature in one shot
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
static inline int lc_dilithium_ed25519_sign(
	struct lc_dilithium_ed25519_sig *sig, const uint8_t *m, size_t mlen,
	const struct lc_dilithium_ed25519_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_ed25519_sign(&sig->sig.sig_87, m, mlen,
						    &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_ed25519_sign(&sig->sig.sig_65, m, mlen,
						    &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_ed25519_sign(&sig->sig.sig_44, m, mlen,
						    &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @brief lc_dilithium_ed25519_verify - Verifies signature in one shot
 *
 * @param [in] sig pointer to input signature
 * @param [in] m pointer to message
 * @param [in] mlen length of message
 * @param [in] pk pointer to bit-packed public key
 *
 * @return 0 if signature could be verified correctly and -EBADMSG when
 * signature cannot be verified, < 0 on other errors
 */
static inline int
lc_dilithium_ed25519_verify(const struct lc_dilithium_ed25519_sig *sig,
			    const uint8_t *m, size_t mlen,
			    const struct lc_dilithium_ed25519_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed25519_verify(&sig->sig.sig_87, m, mlen,
						      &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed25519_verify(&sig->sig.sig_65, m, mlen,
						      &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed25519_verify(&sig->sig.sig_44, m, mlen,
						      &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

#endif /* LC_DILITHIUM_ED25519_SIG */

#ifdef __cplusplus
}
#endif

#endif /* LC_DILITHIUM_H */
