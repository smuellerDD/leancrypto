/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_BIKE_H
#define LC_BIKE_H

#include "ext_headers.h"

#if defined __has_include
#if __has_include("lc_bike_5.h")
#include "lc_bike_5.h"
#define LC_BIKE_5_ENABLED
#endif
#if __has_include("lc_bike_3.h")
#include "lc_bike_3.h"
#define LC_BIKE_3_ENABLED
#endif
#if __has_include("lc_bike_1.h")
#include "lc_bike_1.h"
#define LC_BIKE_1_ENABLED
#endif
#else
#error "Compiler misses __has_include"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum lc_bike_type {
	LC_BIKE_UNKNOWN, /** Unknown key type */
	LC_BIKE_5, /** BIKE 5 */
	LC_BIKE_3, /** BIKE 3 */
	LC_BIKE_1, /** BIKE 1 */
};

/** @defgroup BIKE BIKE Key Encapsulation Mechanism
 *
 * BIKE API concept
 *
 * The BIKE API is accessible via the following header files with the mentioned
 * purpose.
 *
 * * lc_bike.h: This API is the generic API allowing the caller to select
 *   which BIKE type (BIKE 5, 3 or 1) are to be used. The selection is
 *   made either with the flag specified during key generation or by matching
 *   the size of the imported data with the different lc_bike_*_load API calls.
 *   All remaining APIs take the information about the BIKE type from the
 *   provided input data.
 *
 *   This header file only provides inline functions which selectively call
 *   the API provided with the header files below.
 *
 * * lc_bike_5.h: Direct access to BIKE 5.
 *
 * * lc_bike_3.h: Direct access to BIKE 3.
 *
 * * lc_bike_1.h: Direct access to BIKE 1.
 */

/************************************* KEM ************************************/
/**
 * @brief BIKE secret key
 */
struct lc_bike_sk {
	enum lc_bike_type bike_type;
	union {
#ifdef LC_BIKE_5_ENABLED
		struct lc_bike_5_sk sk_5;
#endif
#ifdef LC_BIKE_3_ENABLED
		struct lc_bike_3_sk sk_3;
#endif
#ifdef LC_BIKE_1_ENABLED
		struct lc_bike_1_sk sk_1;
#endif
	} key;
};

/**
 * @brief BIKE public key
 */
struct lc_bike_pk {
	enum lc_bike_type bike_type;
	union {
#ifdef LC_BIKE_5_ENABLED
		struct lc_bike_5_pk pk_5;
#endif
#ifdef LC_BIKE_3_ENABLED
		struct lc_bike_3_pk pk_3;
#endif
#ifdef LC_BIKE_1_ENABLED
		struct lc_bike_1_pk pk_1;
#endif
	} key;
};

/**
 * @brief BIKE ciphertext
 */
struct lc_bike_ct {
	enum lc_bike_type bike_type;
	union {
#ifdef LC_BIKE_5_ENABLED
		struct lc_bike_5_ct ct_5;
#endif
#ifdef LC_BIKE_3_ENABLED
		struct lc_bike_3_ct ct_3;
#endif
#ifdef LC_BIKE_1_ENABLED
		struct lc_bike_1_ct ct_1;
#endif
	} key;
};

/**
 * @brief BIKE shared secret
 */
struct lc_bike_ss {
	enum lc_bike_type bike_type;
	union {
#ifdef LC_BIKE_5_ENABLED
		struct lc_bike_5_ss ss_5;
#endif
#ifdef LC_BIKE_3_ENABLED
		struct lc_bike_3_ss ss_3;
#endif
#ifdef LC_BIKE_1_ENABLED
		struct lc_bike_1_ss ss_1;
#endif
	} key;
};

/**
 * @ingroup BIKE
 * @brief Obtain BIKE type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_bike_type lc_bike_sk_type(const struct lc_bike_sk *sk)
{
	if (!sk)
		return LC_BIKE_UNKNOWN;
	return sk->bike_type;
}

/**
 * @ingroup BIKE
 * @brief Obtain BIKE type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_bike_type lc_bike_pk_type(const struct lc_bike_pk *pk)
{
	if (!pk)
		return LC_BIKE_UNKNOWN;
	return pk->bike_type;
}

/**
 * @ingroup BIKE
 * @brief Obtain BIKE type from BIKE ciphertext
 *
 * @param [in] ct Ciphertext from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_bike_type lc_bike_ct_type(const struct lc_bike_ct *ct)
{
	if (!ct)
		return LC_BIKE_UNKNOWN;
	return ct->bike_type;
}

/**
 * @ingroup BIKE
 * @brief Obtain BIKE type from shared secret
 *
 * @param [in] ss Shared secret key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_bike_type lc_bike_ss_type(const struct lc_bike_ss *ss)
{
	if (!ss)
		return LC_BIKE_UNKNOWN;
	return ss->bike_type;
}

/**
 * @ingroup BIKE
 * @brief Return the size of the BIKE secret key.
 *
 * @param [in] bike_type BIKE type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int lc_bike_sk_size(enum lc_bike_type bike_type)
{
	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_member_size(struct lc_bike_sk, key.sk_5);
#else
		return 0;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_member_size(struct lc_bike_sk, key.sk_3);
#else
		return 0;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_member_size(struct lc_bike_sk, key.sk_1);
#else
		return 0;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup BIKE
 * @brief Return the size of the BIKE public key.
 *
 * @param [in] bike_type BIKE type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int lc_bike_pk_size(enum lc_bike_type bike_type)
{
	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_member_size(struct lc_bike_pk, key.pk_5);
#else
		return 0;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_member_size(struct lc_bike_pk, key.pk_3);
#else
		return 0;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_member_size(struct lc_bike_pk, key.pk_1);
#else
		return 0;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup BIKE
 * @brief Return the size of the BIKE ciphertext.
 *
 * @param [in] bike_type BIKE type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int lc_bike_ct_size(enum lc_bike_type bike_type)
{
	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_member_size(struct lc_bike_ct, key.ct_5);
#else
		return 0;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_member_size(struct lc_bike_ct, key.ct_3);
#else
		return 0;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_member_size(struct lc_bike_ct, key.ct_1);
#else
		return 0;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup BIKE
 * @brief Return the size of the BIKE shared secret.
 *
 * @param [in] bike_type BIKE type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int lc_bike_ss_size(enum lc_bike_type bike_type)
{
	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_member_size(struct lc_bike_ss, key.ss_5);
#else
		return 0;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_member_size(struct lc_bike_ss, key.ss_3);
#else
		return 0;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_member_size(struct lc_bike_ss, key.ss_1);
#else
		return 0;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup BIKE
 * @brief Load a BIKE secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_bike_sk_load(struct lc_bike_sk *sk,
				   const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (src_key_len == lc_bike_sk_size(LC_BIKE_5)) {
		struct lc_bike_5_sk *_sk = &sk->key.sk_5;

		memcpy(_sk, src_key, src_key_len);
		sk->bike_type = LC_BIKE_5;
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (src_key_len == lc_bike_sk_size(LC_BIKE_3)) {
		struct lc_bike_3_sk *_sk = &sk->key.sk_3;

		memcpy(_sk, src_key, src_key_len);
		sk->bike_type = LC_BIKE_3;
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (src_key_len == lc_bike_sk_size(LC_BIKE_1)) {
		struct lc_bike_1_sk *_sk = &sk->key.sk_1;

		memcpy(_sk, src_key, src_key_len);
		sk->bike_type = LC_BIKE_1;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup BIKE
 * @brief Load a BIKE public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Public key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_bike_pk_load(struct lc_bike_pk *pk,
				   const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (src_key_len == lc_bike_pk_size(LC_BIKE_5)) {
		struct lc_bike_5_pk *_pk = &pk->key.pk_5;

		memcpy(_pk, src_key, src_key_len);
		pk->bike_type = LC_BIKE_5;
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (src_key_len == lc_bike_pk_size(LC_BIKE_3)) {
		struct lc_bike_3_pk *_pk = &pk->key.pk_3;

		memcpy(_pk, src_key, src_key_len);
		pk->bike_type = LC_BIKE_3;
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (src_key_len == lc_bike_pk_size(LC_BIKE_1)) {
		struct lc_bike_1_pk *_pk = &pk->key.pk_1;

		memcpy(_pk, src_key, src_key_len);
		pk->bike_type = LC_BIKE_1;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup BIKE
 * @brief Load a BIKE ciphertext key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] ct BIKE ciphertext to be filled (the caller must have it
 *		   allocated)
 * @param [in] src_key Buffer that holds the ciphertext to be imported
 * @param [in] src_key_len Buffer length that holds the ciphertext to be
 *			   imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_bike_ct_load(struct lc_bike_ct *ct,
				   const uint8_t *src_key, size_t src_key_len)
{
	if (!ct || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (src_key_len == lc_bike_ct_size(LC_BIKE_5)) {
		struct lc_bike_5_ct *_ct = &ct->key.ct_5;

		memcpy(_ct, src_key, src_key_len);
		ct->bike_type = LC_BIKE_5;
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (src_key_len == lc_bike_ct_size(LC_BIKE_3)) {
		struct lc_bike_3_ct *_ct = &ct->key.ct_3;

		memcpy(_ct, src_key, src_key_len);
		ct->bike_type = LC_BIKE_3;
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (src_key_len == lc_bike_ct_size(LC_BIKE_1)) {
		struct lc_bike_1_ct *_ct = &ct->key.ct_1;

		memcpy(_ct, src_key, src_key_len);
		ct->bike_type = LC_BIKE_1;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup BIKE
 * @brief Load a BIKE shared secret provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] ss BIKE shared secret to be filled (the caller must have it
 *		   allocated)
 * @param [in] src_key Buffer that holds the shared secret to be imported
 * @param [in] src_key_len Buffer length that holds the shared secret to be
 *			   imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_bike_ss_load(struct lc_bike_ss *ss,
				   const uint8_t *src_key, size_t src_key_len)
{
	if (!ss || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (src_key_len == lc_bike_ss_size(LC_BIKE_5)) {
		struct lc_bike_5_ss *_ss = &ss->key.ss_5;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->bike_type = LC_BIKE_5;
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (src_key_len == lc_bike_ss_size(LC_BIKE_3)) {
		struct lc_bike_3_ss *_ss = &ss->key.ss_3;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->bike_type = LC_BIKE_3;
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (src_key_len == lc_bike_ss_size(LC_BIKE_1)) {
		struct lc_bike_1_ss *_ss = &ss->key.ss_1;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->bike_type = LC_BIKE_1;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup BIKE
 * @brief Obtain the reference to the BIKE key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] bike_key BIKE key pointer
 * @param [out] bike_key_len Length of the key buffer
 * @param [in] sk BIKE secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_bike_sk_ptr(uint8_t **bike_key, size_t *bike_key_len,
				  struct lc_bike_sk *sk)
{
	if (!sk || !bike_key || !bike_key_len) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (sk->bike_type == LC_BIKE_5) {
		struct lc_bike_5_sk *_sk = &sk->key.sk_5;

		*bike_key = (uint8_t *)_sk;
		*bike_key_len = lc_bike_sk_size(sk->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (sk->bike_type == LC_BIKE_3) {
		struct lc_bike_3_sk *_sk = &sk->key.sk_3;

		*bike_key = (uint8_t *)_sk;
		*bike_key_len = lc_bike_sk_size(sk->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (sk->bike_type == LC_BIKE_1) {
		struct lc_bike_1_sk *_sk = &sk->key.sk_1;

		*bike_key = (uint8_t *)_sk;
		*bike_key_len = lc_bike_sk_size(sk->bike_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup BIKE
 * @brief Obtain the reference to the BIKE key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] bike_key BIKE key pointer
 * @param [out] bike_key_len Length of the key buffer
 * @param [in] pk BIKE public key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_bike_pk_ptr(uint8_t **bike_key, size_t *bike_key_len,
				  struct lc_bike_pk *pk)
{
	if (!pk || !bike_key || !bike_key_len) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (pk->bike_type == LC_BIKE_5) {
		struct lc_bike_5_pk *_pk = &pk->key.pk_5;

		*bike_key = (uint8_t *)_pk;
		*bike_key_len = lc_bike_pk_size(pk->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (pk->bike_type == LC_BIKE_3) {
		struct lc_bike_3_pk *_pk = &pk->key.pk_3;

		*bike_key = (uint8_t *)_pk;
		*bike_key_len = lc_bike_pk_size(pk->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (pk->bike_type == LC_BIKE_1) {
		struct lc_bike_1_pk *_pk = &pk->key.pk_1;

		*bike_key = (uint8_t *)_pk;
		*bike_key_len = lc_bike_pk_size(pk->bike_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup BIKE
 * @brief Obtain the reference to the BIKE ciphertext and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto ciphertext,
 * too.
 *
 * @param [out] bike_ct BIKE ciphertext pointer
 * @param [out] bike_ct_len Length of the ciphertext buffer
 * @param [in] ct BIKE ciphertext from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_bike_ct_ptr(uint8_t **bike_ct, size_t *bike_ct_len,
				  struct lc_bike_ct *ct)
{
	if (!ct || !bike_ct || !bike_ct_len) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (ct->bike_type == LC_BIKE_5) {
		struct lc_bike_5_ct *_ct = &ct->key.ct_5;

		*bike_ct = (uint8_t *)_ct;
		*bike_ct_len = lc_bike_ct_size(ct->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (ct->bike_type == LC_BIKE_3) {
		struct lc_bike_3_ct *_ct = &ct->key.ct_3;

		*bike_ct = (uint8_t *)_ct;
		*bike_ct_len = lc_bike_ct_size(ct->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (ct->bike_type == LC_BIKE_1) {
		struct lc_bike_1_ct *_ct = &ct->key.ct_1;

		*bike_ct = (uint8_t *)_ct;
		*bike_ct_len = lc_bike_ct_size(ct->bike_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup BIKE
 * @brief Obtain the reference to the BIKE shared secret and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto shared secret,
 * too.
 *
 * @param [out] bike_ss BIKE shared secret pointer
 * @param [out] bike_ss_len Length of the shared secret buffer
 * @param [in] ss BIKE shared secret from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_bike_ss_ptr(uint8_t **bike_ss, size_t *bike_ss_len,
				  struct lc_bike_ss *ss)
{
	if (!ss || !bike_ss || !bike_ss_len) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (ss->bike_type == LC_BIKE_5) {
		struct lc_bike_5_ss *_ss = &ss->key.ss_5;

		*bike_ss = _ss->ss;
		*bike_ss_len = lc_bike_ss_size(ss->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (ss->bike_type == LC_BIKE_3) {
		struct lc_bike_3_ss *_ss = &ss->key.ss_3;

		*bike_ss = _ss->ss;
		*bike_ss_len = lc_bike_ss_size(ss->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (ss->bike_type == LC_BIKE_1) {
		struct lc_bike_1_ss *_ss = &ss->key.ss_1;

		*bike_ss = _ss->ss;
		*bike_ss_len = lc_bike_ss_size(ss->bike_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup BIKE
 * @brief Generates public and private key for IND-CCA2-secure BIKE key
 *        encapsulation mechanism
 *
 * @param [out] pk pointer to already allocated output public key
 * @param [out] sk pointer to already allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] bike_type type of the BIKE key to generate
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_bike_keypair(struct lc_bike_pk *pk,
				   struct lc_bike_sk *sk,
				   struct lc_rng_ctx *rng_ctx,
				   enum lc_bike_type bike_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_5_keypair(&pk->key.pk_5, &sk->key.sk_5,
					     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_3_keypair(&pk->key.pk_3, &sk->key.sk_3,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_1_keypair(&pk->key.pk_1, &sk->key.sk_1,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup BIKE
 * @brief Generates BIKE public and private key from a given seed.
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
 * @param [in] bike_type type of the BIKE key to generate
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_bike_keypair_from_seed(struct lc_bike_pk *pk,
					    struct lc_bike_sk *sk,
					    const uint8_t *seed,
					    size_t seedlen,
					    enum lc_bike_type bike_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_5_keypair_from_seed(
			&pk->key.pk_5, &sk->key.sk_5, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_3_keypair_from_seed(
			&pk->key.pk_3, &sk->key.sk_3, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_1_keypair_from_seed(
			&pk->key.pk_1, &sk->key.sk_1, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup BIKE
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
static inline int lc_bike_enc(struct lc_bike_ct *ct, struct lc_bike_ss *ss,
			       const struct lc_bike_pk *pk)
{
	if (!ct || !ss || !pk)
		return -EINVAL;

	switch (pk->bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		ct->bike_type = LC_BIKE_5;
		ss->bike_type = LC_BIKE_5;
		return lc_bike_5_enc(&ct->key.ct_5, &ss->key.ss_5,
					 &pk->key.pk_5);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		ct->bike_type = LC_BIKE_3;
		ss->bike_type = LC_BIKE_3;
		return lc_bike_3_enc(&ct->key.ct_3, &ss->key.ss_3,
					&pk->key.pk_3);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		ct->bike_type = LC_BIKE_1;
		ss->bike_type = LC_BIKE_1;
		return lc_bike_1_enc(&ct->key.ct_1, &ss->key.ss_1,
					&pk->key.pk_1);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup BIKE
 * @brief Key encapsulation with KDF applied to shared secret
 *
 * Generates cipher text and shared secret for given public key. The shared
 * secret is derived from the BIKE SS using the KDF derived from the round 3
 * definition of BIKE:
 *
 *	SS <- KMAC256(K = BIKE-SS, X = BIKE-CT, L = requested SS length,
 *		      S = "BIKE KEM SS")
 *
 * @param [out] ct pointer to output cipher text to used for decapsulation
 * @param [out] ss pointer to output shared secret that will be also produced
 *		   during decapsulation
 * @param [in] ss_len length of shared secret to be generated
 * @param [in] pk pointer to input public key
 *
 * Returns 0 (success) or < 0 on error
 */
static inline int lc_bike_enc_kdf(struct lc_bike_ct *ct, uint8_t *ss,
				   size_t ss_len, const struct lc_bike_pk *pk)
{
	if (!ct || !pk)
		return -EINVAL;

	switch (pk->bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		ct->bike_type = LC_BIKE_5;
		return lc_bike_5_enc_kdf(&ct->key.ct_5, ss, ss_len,
					     &pk->key.pk_5);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		ct->bike_type = LC_BIKE_3;
		return lc_bike_3_enc_kdf(&ct->key.ct_3, ss, ss_len,
					    &pk->key.pk_3);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		ct->bike_type = LC_BIKE_1;
		return lc_bike_1_enc_kdf(&ct->key.ct_1, ss, ss_len,
					    &pk->key.pk_1);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup BIKE
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
static inline int lc_bike_dec(struct lc_bike_ss *ss,
			       const struct lc_bike_ct *ct,
			       const struct lc_bike_sk *sk)
{
	if (!ss || !ct || !sk || ct->bike_type != sk->bike_type)
		return -EINVAL;

	switch (sk->bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		ss->bike_type = LC_BIKE_5;
		return lc_bike_5_dec(&ss->key.ss_5, &ct->key.ct_5,
					 &sk->key.sk_5);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		ss->bike_type = LC_BIKE_3;
		return lc_bike_3_dec(&ss->key.ss_3, &ct->key.ct_3,
					&sk->key.sk_3);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		ss->bike_type = LC_BIKE_1;
		return lc_bike_1_dec(&ss->key.ss_1, &ct->key.ct_1,
					&sk->key.sk_1);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup BIKE
 * @brief Key decapsulation with KDF applied to shared secret
 *
 * Generates cipher text and shared secret for given private key. The shared
 * secret is derived from the BIKE SS using the KDF derived from the round 3
 * definition of BIKE:
 *
 *	SS <- KMAC256(K = BIKE-SS, X = BIKE-CT, L = requested SS length,
 *		      S = "BIKE KEM SS")
 *
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
static inline int lc_bike_dec_kdf(uint8_t *ss, size_t ss_len,
				   const struct lc_bike_ct *ct,
				   const struct lc_bike_sk *sk)
{
	if (!ct || !sk || ct->bike_type != sk->bike_type)
		return -EINVAL;

	switch (sk->bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_bike_5_dec_kdf(ss, ss_len, &ct->key.ct_5,
					     &sk->key.sk_5);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_bike_3_dec_kdf(ss, ss_len, &ct->key.ct_3,
					    &sk->key.sk_3);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_bike_1_dec_kdf(ss, ss_len, &ct->key.ct_1,
					    &sk->key.sk_1);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* LC_BIKE_H */
