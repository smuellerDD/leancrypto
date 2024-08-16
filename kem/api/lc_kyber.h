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

#ifndef LC_KYBER_H
#define LC_KYBER_H

#include "ext_headers.h"

#if defined __has_include
#if __has_include("lc_kyber_1024.h")
#include "lc_kyber_1024.h"
#define LC_KYBER_1024_ENABLED
#endif
#if __has_include("lc_kyber_768.h")
#include "lc_kyber_768.h"
#define LC_KYBER_768_ENABLED
#endif
#if __has_include("lc_kyber_512.h")
#include "lc_kyber_512.h"
#define LC_KYBER_512_ENABLED
#endif
#else
#error "Compiler misses __has_include"
#endif

#ifdef __cplusplus
extern "C" {
#endif

enum lc_kyber_type {
	LC_KYBER_UNKNOWN, /** Unknown key type */
	LC_KYBER_1024, /** Kyber 1024 */
	LC_KYBER_768, /** Kyber 768 */
	LC_KYBER_512, /** Kyber 512 */
};

/** @defgroup Kyber ML-KEM / CRYSTALS-Kyber Key Encapsulation Mechanism
 *
 * Kyber API concept
 *
 * The Kyber API is accessible via the following header files with the mentioned
 * purpose.
 *
 * * lc_kyber.h: This API is the generic API allowing the caller to select
 *   which Kyber type (Kyber 1024, 768 or 512) are to be used. The selection is
 *   made either with the flag specified during key generation or by matching
 *   the size of the imported data with the different lc_kyber_*_load API calls.
 *   All remaining APIs take the information about the Kyber type from the
 *   provided input data.
 *
 *   This header file only provides inline functions which selectively call
 *   the API provided with the header files below.
 *
 * * lc_kyber_1024.h: Direct access to Kyber 1024.
 *
 * * lc_kyber_768.h: Direct access to Kyber 768.
 *
 * * lc_kyber_512.h: Direct access to Kyber 512.
 */

/************************************* KEM ************************************/
/**
 * @brief Kyber secret key
 */
struct lc_kyber_sk {
	enum lc_kyber_type kyber_type;
	union {
#ifdef LC_KYBER_1024_ENABLED
		struct lc_kyber_1024_sk sk_1024;
#endif
#ifdef LC_KYBER_768_ENABLED
		struct lc_kyber_768_sk sk_768;
#endif
#ifdef LC_KYBER_512_ENABLED
		struct lc_kyber_512_sk sk_512;
#endif
	} key;
};

/**
 * @brief Kyber public key
 */
struct lc_kyber_pk {
	enum lc_kyber_type kyber_type;
	union {
#ifdef LC_KYBER_1024_ENABLED
		struct lc_kyber_1024_pk pk_1024;
#endif
#ifdef LC_KYBER_768_ENABLED
		struct lc_kyber_768_pk pk_768;
#endif
#ifdef LC_KYBER_512_ENABLED
		struct lc_kyber_512_pk pk_512;
#endif
	} key;
};

/**
 * @brief Kyber ciphertext
 */
struct lc_kyber_ct {
	enum lc_kyber_type kyber_type;
	union {
#ifdef LC_KYBER_1024_ENABLED
		struct lc_kyber_1024_ct ct_1024;
#endif
#ifdef LC_KYBER_768_ENABLED
		struct lc_kyber_768_ct ct_768;
#endif
#ifdef LC_KYBER_512_ENABLED
		struct lc_kyber_512_ct ct_512;
#endif
	} key;
};

/**
 * @brief Kyber shared secret
 */
struct lc_kyber_ss {
	enum lc_kyber_type kyber_type;
	union {
#ifdef LC_KYBER_1024_ENABLED
		struct lc_kyber_1024_ss ss_1024;
#endif
#ifdef LC_KYBER_768_ENABLED
		struct lc_kyber_768_ss ss_768;
#endif
#ifdef LC_KYBER_512_ENABLED
		struct lc_kyber_512_ss ss_512;
#endif
	} key;
};

/**
 * @ingroup Kyber
 * @brief Obtain Kyber type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_kyber_type lc_kyber_sk_type(const struct lc_kyber_sk *sk)
{
	if (!sk)
		return LC_KYBER_UNKNOWN;
	return sk->kyber_type;
}

/**
 * @ingroup Kyber
 * @brief Obtain Kyber type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_kyber_type lc_kyber_pk_type(const struct lc_kyber_pk *pk)
{
	if (!pk)
		return LC_KYBER_UNKNOWN;
	return pk->kyber_type;
}

/**
 * @ingroup Kyber
 * @brief Obtain Kyber type from Kyber ciphertext
 *
 * @param [in] ct Ciphertext from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_kyber_type lc_kyber_ct_type(const struct lc_kyber_ct *ct)
{
	if (!ct)
		return LC_KYBER_UNKNOWN;
	return ct->kyber_type;
}

/**
 * @ingroup Kyber
 * @brief Obtain Kyber type from shared secret
 *
 * @param [in] ss Shared secret key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_kyber_type lc_kyber_ss_type(const struct lc_kyber_ss *ss)
{
	if (!ss)
		return LC_KYBER_UNKNOWN;
	return ss->kyber_type;
}

/**
 * @ingroup Kyber
 * @brief Return the size of the Kyber secret key.
 *
 * @param [in] kyber_type Kyber type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int lc_kyber_sk_size(enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_sk, key.sk_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_sk, key.sk_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_sk, key.sk_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup Kyber
 * @brief Return the size of the Kyber public key.
 *
 * @param [in] kyber_type Kyber type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int lc_kyber_pk_size(enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_pk, key.pk_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_pk, key.pk_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_pk, key.pk_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup Kyber
 * @brief Return the size of the Kyber ciphertext.
 *
 * @param [in] kyber_type Kyber type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int lc_kyber_ct_size(enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_ct, key.ct_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_ct, key.ct_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_ct, key.ct_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup Kyber
 * @brief Return the size of the Kyber shared secret.
 *
 * @param [in] kyber_type Kyber type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int lc_kyber_ss_size(enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_ss, key.ss_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_ss, key.ss_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_ss, key.ss_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup Kyber
 * @brief Load a Kyber secret key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] sk Secret key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_kyber_sk_load(struct lc_kyber_sk *sk,
				   const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (src_key_len == lc_kyber_sk_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_sk *_sk = &sk->key.sk_1024;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (src_key_len == lc_kyber_sk_size(LC_KYBER_768)) {
		struct lc_kyber_768_sk *_sk = &sk->key.sk_768;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (src_key_len == lc_kyber_sk_size(LC_KYBER_512)) {
		struct lc_kyber_512_sk *_sk = &sk->key.sk_512;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup Kyber
 * @brief Load a Kyber public key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] pk Public key to be filled (the caller must have it allocated)
 * @param [in] src_key Buffer that holds the key to be imported
 * @param [in] src_key_len Buffer length that holds the key to be imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_kyber_pk_load(struct lc_kyber_pk *pk,
				   const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (src_key_len == lc_kyber_pk_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_pk *_pk = &pk->key.pk_1024;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (src_key_len == lc_kyber_pk_size(LC_KYBER_768)) {
		struct lc_kyber_768_pk *_pk = &pk->key.pk_768;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (src_key_len == lc_kyber_pk_size(LC_KYBER_512)) {
		struct lc_kyber_512_pk *_pk = &pk->key.pk_512;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup Kyber
 * @brief Load a Kyber ciphertext key provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] ct Kyber ciphertext to be filled (the caller must have it
 *		   allocated)
 * @param [in] src_key Buffer that holds the ciphertext to be imported
 * @param [in] src_key_len Buffer length that holds the ciphertext to be
 *			   imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_kyber_ct_load(struct lc_kyber_ct *ct,
				   const uint8_t *src_key, size_t src_key_len)
{
	if (!ct || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (src_key_len == lc_kyber_ct_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_ct *_ct = &ct->key.ct_1024;

		memcpy(_ct->ct, src_key, src_key_len);
		ct->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (src_key_len == lc_kyber_ct_size(LC_KYBER_768)) {
		struct lc_kyber_768_ct *_ct = &ct->key.ct_768;

		memcpy(_ct->ct, src_key, src_key_len);
		ct->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (src_key_len == lc_kyber_ct_size(LC_KYBER_512)) {
		struct lc_kyber_512_ct *_ct = &ct->key.ct_512;

		memcpy(_ct->ct, src_key, src_key_len);
		ct->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup Kyber
 * @brief Load a Kyber shared secret provided with a buffer into the leancrypto
 *	  data structure.
 *
 * @param [out] ss Kyber shared secret to be filled (the caller must have it
 *		   allocated)
 * @param [in] src_key Buffer that holds the shared secret to be imported
 * @param [in] src_key_len Buffer length that holds the shared secret to be
 *			   imported
 *
 * @return 0 on success or < 0 on error
 */
static inline int lc_kyber_ss_load(struct lc_kyber_ss *ss,
				   const uint8_t *src_key, size_t src_key_len)
{
	if (!ss || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (src_key_len == lc_kyber_ss_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_ss *_ss = &ss->key.ss_1024;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (src_key_len == lc_kyber_ss_size(LC_KYBER_768)) {
		struct lc_kyber_768_ss *_ss = &ss->key.ss_768;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (src_key_len == lc_kyber_ss_size(LC_KYBER_512)) {
		struct lc_kyber_512_ss *_ss = &ss->key.ss_512;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @brief Pairwise consistency check as per FIPS 203 section 7.1
 *
 * This call should be invoked when importing an encapsulation and decapsulation
 * key pair.
 *
 * @param [in] pk Public key (ek)
 * @param [in] sk Secret key (dk)
 *
 * @return 0 on success, < 0 on error
 */
int lc_kyber_pct(const struct lc_kyber_pk *pk, const struct lc_kyber_sk *sk);

/**
 * @ingroup Kyber
 * @brief Obtain the reference to the Kyber key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] kyber_key Kyber key pointer
 * @param [out] kyber_key_len Length of the key buffer
 * @param [in] sk Kyber secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_kyber_sk_ptr(uint8_t **kyber_key, size_t *kyber_key_len,
				  struct lc_kyber_sk *sk)
{
	if (!sk || !kyber_key || !kyber_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (sk->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_sk *_sk = &sk->key.sk_1024;

		*kyber_key = _sk->sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (sk->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_sk *_sk = &sk->key.sk_768;

		*kyber_key = _sk->sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (sk->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_sk *_sk = &sk->key.sk_512;

		*kyber_key = _sk->sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup Kyber
 * @brief Obtain the reference to the Kyber key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] kyber_key Kyber key pointer
 * @param [out] kyber_key_len Length of the key buffer
 * @param [in] pk Kyber public key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_kyber_pk_ptr(uint8_t **kyber_key, size_t *kyber_key_len,
				  struct lc_kyber_pk *pk)
{
	if (!pk || !kyber_key || !kyber_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (pk->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_pk *_pk = &pk->key.pk_1024;

		*kyber_key = _pk->pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (pk->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_pk *_pk = &pk->key.pk_768;

		*kyber_key = _pk->pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (pk->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_pk *_pk = &pk->key.pk_512;

		*kyber_key = _pk->pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup Kyber
 * @brief Obtain the reference to the Kyber ciphertext and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto ciphertext,
 * too.
 *
 * @param [out] kyber_ct Kyber ciphertext pointer
 * @param [out] kyber_ct_len Length of the ciphertext buffer
 * @param [in] ct Kyber ciphertext from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_kyber_ct_ptr(uint8_t **kyber_ct, size_t *kyber_ct_len,
				  struct lc_kyber_ct *ct)
{
	if (!ct || !kyber_ct || !kyber_ct_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (ct->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_ct *_ct = &ct->key.ct_1024;

		*kyber_ct = _ct->ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (ct->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_ct *_ct = &ct->key.ct_768;

		*kyber_ct = _ct->ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (ct->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_ct *_ct = &ct->key.ct_512;

		*kyber_ct = _ct->ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup Kyber
 * @brief Obtain the reference to the Kyber shared secret and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto shared secret,
 * too.
 *
 * @param [out] kyber_ss Kyber shared secret pointer
 * @param [out] kyber_ss_len Length of the shared secret buffer
 * @param [in] ss Kyber shared secret from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_kyber_ss_ptr(uint8_t **kyber_ss, size_t *kyber_ss_len,
				  struct lc_kyber_ss *ss)
{
	if (!ss || !kyber_ss || !kyber_ss_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (ss->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_ss *_ss = &ss->key.ss_1024;

		*kyber_ss = _ss->ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (ss->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_ss *_ss = &ss->key.ss_768;

		*kyber_ss = _ss->ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (ss->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_ss *_ss = &ss->key.ss_512;

		*kyber_ss = _ss->ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup Kyber
 * @brief Generates public and private key for IND-CCA2-secure Kyber key
 *        encapsulation mechanism
 *
 * @param [out] pk pointer to already allocated output public key
 * @param [out] sk pointer to already allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] kyber_type type of the Kyber key to generate
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kyber_keypair(struct lc_kyber_pk *pk,
				   struct lc_kyber_sk *sk,
				   struct lc_rng_ctx *rng_ctx,
				   enum lc_kyber_type kyber_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_1024_keypair(&pk->key.pk_1024, &sk->key.sk_1024,
					     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_768_keypair(&pk->key.pk_768, &sk->key.sk_768,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_512_keypair(&pk->key.pk_512, &sk->key.sk_512,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup Kyber
 * @brief Generates Kyber public and private key from a given seed.
 *
 * The idea of the function is the allowance of FIPS 203 to maintain the seed
 * used to generate a key pair in lieu of maintaining a private key or the
 * key pair (which used much more memory). The seed must be treated equally
 * sensitive as a private key.
 *
 * The seed is generated by simply obtaining 64 bytes from a properly seeded
 * DRNG, i.e. the same way as a symmetric key would be generated.
 *
 * Compliant to the notation of FIPS 203 the following definition applies:
 *	seed = d || z
 *
 * @param [out] pk pointer to allocated output public key
 * @param [out] sk pointer to allocated output private key
 * @param [in] seed buffer with the seed data which must be exactly 64 bytes
 *		    in size
 * @param [in] seedlen length of the seed buffer
 * @param [in] kyber_type type of the Kyber key to generate
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kyber_keypair_from_seed(struct lc_kyber_pk *pk,
					     struct lc_kyber_sk *sk,
					     const uint8_t *seed,
					     size_t seedlen,
					     enum lc_kyber_type kyber_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_1024_keypair_from_seed(
			&pk->key.pk_1024, &sk->key.sk_1024, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_768_keypair_from_seed(
			&pk->key.pk_768, &sk->key.sk_768, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_512_keypair_from_seed(
			&pk->key.pk_512, &sk->key.sk_512, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup Kyber
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
static inline int lc_kyber_enc(struct lc_kyber_ct *ct, struct lc_kyber_ss *ss,
			       const struct lc_kyber_pk *pk)
{
	if (!ct || !ss || !pk)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		ss->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_enc(&ct->key.ct_1024, &ss->key.ss_1024,
					 &pk->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		ss->kyber_type = LC_KYBER_768;
		return lc_kyber_768_enc(&ct->key.ct_768, &ss->key.ss_768,
					&pk->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		ss->kyber_type = LC_KYBER_512;
		return lc_kyber_512_enc(&ct->key.ct_512, &ss->key.ss_512,
					&pk->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup Kyber
 * @brief Key encapsulation with KDF applied to shared secret
 *
 * Generates cipher text and shared secret for given public key. The shared
 * secret is derived from the Kyber SS using the KDF derived from the round 3
 * definition of Kyber:
 *
 *	SS <- KMAC256(K = Kyber-SS, X = Kyber-CT, L = requested SS length,
 *		      S = "Kyber KEM SS")
 *
 * @param [out] ct pointer to output cipher text to used for decapsulation
 * @param [out] ss pointer to output shared secret that will be also produced
 *		   during decapsulation
 * @param [in] ss_len length of shared secret to be generated
 * @param [in] pk pointer to input public key
 *
 * Returns 0 (success) or < 0 on error
 */
static inline int lc_kyber_enc_kdf(struct lc_kyber_ct *ct, uint8_t *ss,
				   size_t ss_len, const struct lc_kyber_pk *pk)
{
	if (!ct || !pk)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_enc_kdf(&ct->key.ct_1024, ss, ss_len,
					     &pk->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_enc_kdf(&ct->key.ct_768, ss, ss_len,
					    &pk->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_enc_kdf(&ct->key.ct_512, ss, ss_len,
					    &pk->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup Kyber
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
static inline int lc_kyber_dec(struct lc_kyber_ss *ss,
			       const struct lc_kyber_ct *ct,
			       const struct lc_kyber_sk *sk)
{
	if (!ss || !ct || !sk || ct->kyber_type != sk->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ss->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_dec(&ss->key.ss_1024, &ct->key.ct_1024,
					 &sk->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ss->kyber_type = LC_KYBER_768;
		return lc_kyber_768_dec(&ss->key.ss_768, &ct->key.ct_768,
					&sk->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ss->kyber_type = LC_KYBER_512;
		return lc_kyber_512_dec(&ss->key.ss_512, &ct->key.ct_512,
					&sk->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup Kyber
 * @brief Key decapsulation with KDF applied to shared secret
 *
 * Generates cipher text and shared secret for given private key. The shared
 * secret is derived from the Kyber SS using the KDF derived from the round 3
 * definition of Kyber:
 *
 *	SS <- KMAC256(K = Kyber-SS, X = Kyber-CT, L = requested SS length,
 *		      S = "Kyber KEM SS")
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
static inline int lc_kyber_dec_kdf(uint8_t *ss, size_t ss_len,
				   const struct lc_kyber_ct *ct,
				   const struct lc_kyber_sk *sk)
{
	if (!ct || !sk || ct->kyber_type != sk->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_dec_kdf(ss, ss_len, &ct->key.ct_1024,
					     &sk->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_dec_kdf(ss, ss_len, &ct->key.ct_768,
					    &sk->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_dec_kdf(ss, ss_len, &ct->key.ct_512,
					    &sk->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/************************************* KEX ************************************/

/** @defgroup KyberKEXUAKE ML-KEM / CRYSTALS-Kyber used in Unilaterally Authenticated Key Exchange Mechanism
 *
 * Unilaterally authenticated key exchange
 *
 * The key exchange provides a shared secret between two communication parties.
 * Only the initiator authenticates the key exchange with his private key.
 *
 * The idea is that the pk_r/sk_r key pair is a static key pair that is
 * generated and exchanged before the KEX handshake. For the unilaterally
 * authenticated key exchange, only the initiator uses the responder's public
 * key which implies that the initiator authenticates the responder.
 *```
 * 		Alice (initiator)		Bob (responder)
 *
 * Step 1					generate static keypair
 *						Result:
 *							public key pk_r
 *							secret key sk_r
 *
 * Step 2					send public key
 * 		pk_r <-------------------------	pk_r
 *
 * Step 3	initiate key exchange
 *		Result:
 *			Public key pk_e_i
 *			Cipher text ct_e_i
 *			KEM shared secret tk
 *			Secret key sk_e
 *
 * Step 4	send kex data
 *		Public key pk_e_i ------------>	Public key pk_e_i
 *		Cipher text ct_e_i ----------->	Cipher text ct_e_i
 *
 * Step 5					calculate shared secret
 *						Result:
 *							Cipher text ct_e_r
 *							Shared secret SS
 *
 * Step 6					send kex data
 *		Cipher text ct_e_r <-----------	Cipher text ct_e_r
 *
 * Step 7	calculate shared secret
 *		Result:
 * 			Shared secret SS
 *```
 */

/**
 * @ingroup KyberKEXUAKE
 * @brief Initialize unilaterally authenticated key exchange
 *
 * @param [out] pk_e_i initiator's ephemeral public key to be sent to the
 *		       responder
 * @param [out] ct_e_i initiator's ephemeral cipher text to be sent to the
 *		       responder
 * @param [out] tk KEM shared secret data to be used for the initiator's shared
 *		   secret generation
 * @param [out] sk_e initiator's ephemeral secret key to be used for the
 *		     initiator's shared secret generation
 * @param [in] pk_r responder's public key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kex_uake_initiator_init(struct lc_kyber_pk *pk_e_i,
					     struct lc_kyber_ct *ct_e_i,
					     struct lc_kyber_ss *tk,
					     struct lc_kyber_sk *sk_e,
					     const struct lc_kyber_pk *pk_r)
{
	if (!pk_e_i || !ct_e_i || !tk || !sk_e || !pk_r)
		return -EINVAL;

	switch (pk_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk_e_i->kyber_type = LC_KYBER_1024;
		ct_e_i->kyber_type = LC_KYBER_1024;
		tk->kyber_type = LC_KYBER_1024;
		sk_e->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_uake_initiator_init(&pk_e_i->key.pk_1024,
						       &ct_e_i->key.ct_1024,
						       &tk->key.ss_1024,
						       &sk_e->key.sk_1024,
						       &pk_r->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk_e_i->kyber_type = LC_KYBER_768;
		ct_e_i->kyber_type = LC_KYBER_768;
		tk->kyber_type = LC_KYBER_768;
		sk_e->kyber_type = LC_KYBER_768;
		return lc_kex_768_uake_initiator_init(
			&pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&tk->key.ss_768, &sk_e->key.sk_768, &pk_r->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk_e_i->kyber_type = LC_KYBER_512;
		ct_e_i->kyber_type = LC_KYBER_512;
		tk->kyber_type = LC_KYBER_512;
		sk_e->kyber_type = LC_KYBER_512;
		return lc_kex_512_uake_initiator_init(
			&pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&tk->key.ss_512, &sk_e->key.sk_512, &pk_r->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup KyberKEXUAKE
 * @brief Initiator's shared secret generation
 *
 * @param [out] ct_e_r responder's ephemeral cipher text to be sent to the
 *		       initiator
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] pk_e_i initiator's ephemeral public key
 * @param [in] ct_e_i initiator's ephemeral cipher text
 * @param [in] sk_r responder's secret key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int
lc_kex_uake_responder_ss(struct lc_kyber_ct *ct_e_r, uint8_t *shared_secret,
			 size_t shared_secret_len, const uint8_t *kdf_nonce,
			 size_t kdf_nonce_len, const struct lc_kyber_pk *pk_e_i,
			 const struct lc_kyber_ct *ct_e_i,
			 const struct lc_kyber_sk *sk_r)
{
	if (!ct_e_r || !pk_e_i || !ct_e_i || !sk_r ||
	    pk_e_i->kyber_type != ct_e_i->kyber_type ||
	    pk_e_i->kyber_type != sk_r->kyber_type)
		return -EINVAL;

	switch (pk_e_i->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct_e_r->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_uake_responder_ss(
			&ct_e_r->key.ct_1024, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_1024,
			&ct_e_i->key.ct_1024, &sk_r->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct_e_r->kyber_type = LC_KYBER_768;
		return lc_kex_768_uake_responder_ss(
			&ct_e_r->key.ct_768, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_768,
			&ct_e_i->key.ct_768, &sk_r->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct_e_r->kyber_type = LC_KYBER_512;
		return lc_kex_512_uake_responder_ss(
			&ct_e_r->key.ct_512, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_512,
			&ct_e_i->key.ct_512, &sk_r->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup KyberKEXUAKE
 * @brief Responder's shared secret generation
 *
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] ct_e_r responder's ephemeral cipher text
 * @param [in] tk KEM shared secret data that was generated during the
 *		  initiator's initialization
 * @param [in] sk_e initiator's ephemeral secret that was generated during the
 *		    initiator's initialization
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kex_uake_initiator_ss(uint8_t *shared_secret,
					   size_t shared_secret_len,
					   const uint8_t *kdf_nonce,
					   size_t kdf_nonce_len,
					   const struct lc_kyber_ct *ct_e_r,
					   const struct lc_kyber_ss *tk,
					   const struct lc_kyber_sk *sk_e)
{
	if (!ct_e_r || !tk || !sk_e || ct_e_r->kyber_type != tk->kyber_type ||
	    ct_e_r->kyber_type != sk_e->kyber_type)
		return -EINVAL;

	switch (ct_e_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kex_1024_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_1024, &tk->key.ss_1024,
			&sk_e->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kex_768_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_768, &tk->key.ss_768,
			&sk_e->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kex_512_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_512, &tk->key.ss_512,
			&sk_e->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/** @defgroup KyberKEXAKE ML-KEM / CRYSTALS-Kyber used in Authenticated Key Exchange Mechanism
 *
 * The key exchange provides a shared secret between two communication parties.
 * The initiator and responder authenticates the key exchange with their private
 * keys.
 *
 * The idea is that the pk_i/sk_i and pk_r/sk_r key pairs are static key pairs
 * that are generated and exchanged before the KEX handshake. For the
 * authenticated key exchange, both sides use the respective peer's public key
 * which implies either side authenticates the other end.
 *```
 * 		Alice (initiator)		Bob (responder)
 *
 * Step 1	generate static keypair		generate static keypair
 *		Result:				Result:
 *			public key pk_i			public key pk_r
 *			secret key sk_i			secret key sk_r
 *
 * Step 2	send public key			send public key
 * 		pk_r <-------------------------	pk_r
 *		pk_i -------------------------> pk_i
 *
 * Step 3	initiate key exchange
 *		Result:
 *			Public key pk_e_i
 *			Cipher text ct_e_i
 *			KEM shared secret tk
 *			Secret key sk_e
 *
 * Step 4	send kex data
 *		Public key pk_e_i ------------>	Public key pk_e_i
 *		Cipher text ct_e_i ----------->	Cipher text ct_e_i
 *
 * Step 5					calculate shared secret
 *						Result:
 *							Cipher text ct_e_r_1
 *							Cipher text ct_e_r_2
 *							Shared secret SS
 *
 * Step 6					send kex data
 *		Cipher text ct_e_r_1 <---------	Cipher text ct_e_r_1
 *		Cipher text ct_e_r_2 <---------	Cipher text ct_e_r_2
 *
 * Step 7	calculate shared secret
 *		Result:
 * 			Shared secret SS
 *```
 */

/**
 * @ingroup KyberKEXAKE
 * @brief Initialize authenticated key exchange
 *
 * @param [out] pk_e_i initiator's ephemeral public key to be sent to the
 *		       responder
 * @param [out] ct_e_i initiator's ephemeral cipher text to be sent to the
 *		       responder
 * @param [out] tk KEM shared secret data to be used for the initiator's shared
 *		   secret generation
 * @param [out] sk_e initiator's ephemeral secret key to be used for the
 *		     initiator's shared secret generation
 * @param [in] pk_r responder's public key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kex_ake_initiator_init(struct lc_kyber_pk *pk_e_i,
					    struct lc_kyber_ct *ct_e_i,
					    struct lc_kyber_ss *tk,
					    struct lc_kyber_sk *sk_e,
					    const struct lc_kyber_pk *pk_r)
{
	if (!pk_e_i || !ct_e_i || !tk || !sk_e || !pk_r)
		return -EINVAL;

	switch (pk_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk_e_i->kyber_type = LC_KYBER_1024;
		ct_e_i->kyber_type = LC_KYBER_1024;
		tk->kyber_type = LC_KYBER_1024;
		sk_e->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_ake_initiator_init(&pk_e_i->key.pk_1024,
						      &ct_e_i->key.ct_1024,
						      &tk->key.ss_1024,
						      &sk_e->key.sk_1024,
						      &pk_r->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk_e_i->kyber_type = LC_KYBER_768;
		ct_e_i->kyber_type = LC_KYBER_768;
		tk->kyber_type = LC_KYBER_768;
		sk_e->kyber_type = LC_KYBER_768;
		return lc_kex_768_ake_initiator_init(
			&pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&tk->key.ss_768, &sk_e->key.sk_768, &pk_r->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk_e_i->kyber_type = LC_KYBER_512;
		ct_e_i->kyber_type = LC_KYBER_512;
		tk->kyber_type = LC_KYBER_512;
		sk_e->kyber_type = LC_KYBER_512;
		return lc_kex_512_ake_initiator_init(
			&pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&tk->key.ss_512, &sk_e->key.sk_512, &pk_r->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup KyberKEXAKE
 * @brief Initiator's shared secret generation
 *
 * @param [out] ct_e_r_1 responder's ephemeral cipher text to be sent to the
 *			 initator
 * @param [out] ct_e_r_2 responder's ephemeral cipher text to be sent to the
 *			 initator
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] pk_e_i initator's ephemeral public key
 * @param [in] ct_e_i initator's ephemeral cipher text
 * @param [in] sk_r responder's secret key
 * @param [in] pk_i initator's public key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kex_ake_responder_ss(
	struct lc_kyber_ct *ct_e_r_1, struct lc_kyber_ct *ct_e_r_2,
	uint8_t *shared_secret, size_t shared_secret_len,
	const uint8_t *kdf_nonce, size_t kdf_nonce_len,
	const struct lc_kyber_pk *pk_e_i, const struct lc_kyber_ct *ct_e_i,
	const struct lc_kyber_sk *sk_r, const struct lc_kyber_pk *pk_i)
{
	if (!ct_e_r_1 || !ct_e_r_2 || !pk_e_i || !ct_e_i || !sk_r || !pk_i ||
	    pk_e_i->kyber_type != ct_e_i->kyber_type ||
	    pk_e_i->kyber_type != sk_r->kyber_type ||
	    pk_e_i->kyber_type != pk_i->kyber_type)
		return -EINVAL;

	switch (pk_e_i->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_1024;
		ct_e_r_2->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_ake_responder_ss(
			&ct_e_r_1->key.ct_1024, &ct_e_r_2->key.ct_1024,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_1024,
			&ct_e_i->key.ct_1024, &sk_r->key.sk_1024,
			&pk_i->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_768;
		ct_e_r_2->kyber_type = LC_KYBER_768;
		return lc_kex_768_ake_responder_ss(
			&ct_e_r_1->key.ct_768, &ct_e_r_2->key.ct_768,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&sk_r->key.sk_768, &pk_i->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_512;
		ct_e_r_2->kyber_type = LC_KYBER_512;
		return lc_kex_512_ake_responder_ss(
			&ct_e_r_1->key.ct_512, &ct_e_r_2->key.ct_512,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&sk_r->key.sk_512, &pk_i->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup KyberKEXAKE
 * @brief Responder's shared secret generation
 *
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] ct_e_r_1 responder's ephemeral cipher text
 * @param [in] ct_e_r_2 responder's ephemeral cipher text
 * @param [in] tk KEM shared secret data that was generated during the
 *		  initator's initialization
 * @param [in] sk_e initator's ephemeral secret that was generated during the
 *		    initator's initialization
 * @param [in] sk_i initator's secret key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kex_ake_initiator_ss(
	uint8_t *shared_secret, size_t shared_secret_len,
	const uint8_t *kdf_nonce, size_t kdf_nonce_len,
	const struct lc_kyber_ct *ct_e_r_1, const struct lc_kyber_ct *ct_e_r_2,
	const struct lc_kyber_ss *tk, const struct lc_kyber_sk *sk_e,
	const struct lc_kyber_sk *sk_i)
{
	if (!ct_e_r_1 || !ct_e_r_2 || !tk || !sk_e || !sk_i ||
	    ct_e_r_1->kyber_type != ct_e_r_2->kyber_type ||
	    ct_e_r_1->kyber_type != tk->kyber_type ||
	    ct_e_r_1->kyber_type != sk_e->kyber_type ||
	    ct_e_r_1->kyber_type != sk_i->kyber_type)
		return -EINVAL;

	switch (ct_e_r_1->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kex_1024_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_1024,
			&ct_e_r_2->key.ct_1024, &tk->key.ss_1024,
			&sk_e->key.sk_1024, &sk_i->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kex_768_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_768,
			&ct_e_r_2->key.ct_768, &tk->key.ss_768,
			&sk_e->key.sk_768, &sk_i->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kex_512_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_512,
			&ct_e_r_2->key.ct_512, &tk->key.ss_512,
			&sk_e->key.sk_512, &sk_i->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/************************************* IES ************************************/

/** @defgroup KyberIES ML-KEM / CRYSTALS-Kyber used in Integrated Encryption Schema
 *
 * Kyber Integrated Encryption Schema
 *
 * This mechanism uses Kyber to encrypt arbitrary data. See
 * [KyberIES](https://leancrypto.org/papers/KyberIES_specification.pdf) for
 * the associated documentation.
 */

/**
 * @ingroup KyberIES
 * @brief KyberIES encryption oneshot
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] pk Kyber public key of data owner
 * @param [out] ct Kyber ciphertext to be sent to the decryption operation
 * @param [in] plaintext Plaintext data to be encrypted
 * @param [out] ciphertext Buffer of equal size as plaintext that will be filled
 *			   with the encryption result
 * @param [in] datalen Length of the plaintext buffer
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [out] tag Buffer that will be filled with the authentication tag
 * @param [in] taglen Length of the tag buffer
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 *
 * @return 0 on success, < 0 on error
 */
static inline int
lc_kyber_ies_enc(const struct lc_kyber_pk *pk, struct lc_kyber_ct *ct,
		 const uint8_t *plaintext, uint8_t *ciphertext, size_t datalen,
		 const uint8_t *aad, size_t aadlen, uint8_t *tag, size_t taglen,
		 struct lc_aead_ctx *aead)
{
	if (!pk || !ct)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_ies_enc(&pk->key.pk_1024, &ct->key.ct_1024,
					     plaintext, ciphertext, datalen,
					     aad, aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_ies_enc(&pk->key.pk_768, &ct->key.ct_768,
					    plaintext, ciphertext, datalen, aad,
					    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_ies_enc(&pk->key.pk_512, &ct->key.ct_512,
					    plaintext, ciphertext, datalen, aad,
					    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup KyberIES
 * @brief KyberIES encryption stream operation initialization
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * The aead context is initialized such that it can be used with
 * lc_kyber_ies_enc_[update|final].
 *
 * @param [out] aead Allocated AEAD algorithm - the caller only needs to provide
 *		     an allocated but otherwise unused instance of an AEAD
 *		     algorithm. This allows the caller to define the AEAD
 *		     algorithm type. The caller must zeroize and release the
 *		     context after completion.
 * @param [in] pk Kyber public key of data owner
 * @param [out] ct Kyber ciphertext to be sent to the decryption operation
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_ies_enc_init(struct lc_aead_ctx *aead,
					const struct lc_kyber_pk *pk,
					struct lc_kyber_ct *ct,
					const uint8_t *aad, size_t aadlen)
{
	if (!pk || !ct)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_ies_enc_init(
			aead, &pk->key.pk_1024, &ct->key.ct_1024, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_ies_enc_init(aead, &pk->key.pk_768,
						 &ct->key.ct_768, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_ies_enc_init(aead, &pk->key.pk_512,
						 &ct->key.ct_512, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup KyberIES
 * @brief KyberIES encryption stream operation add more data
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] plaintext Plaintext data to be encrypted
 * @param [out] ciphertext Buffer of equal size as plaintext that will be filled
 *			   with the encryption result
 * @param [in] datalen Length of the plaintext buffer
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_ies_enc_update(struct lc_aead_ctx *aead,
					  const uint8_t *plaintext,
					  uint8_t *ciphertext, size_t datalen)
{
	return lc_aead_enc_update(aead, plaintext, ciphertext, datalen);
}

/**
 * @ingroup KyberIES
 * @brief KyberIES encryption stream operation finalization / integrity test
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [out] tag Buffer that will be filled with the authentication tag
 * @param [in] taglen Length of the tag buffer
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_ies_enc_final(struct lc_aead_ctx *aead, uint8_t *tag,
					 size_t taglen)
{
	return lc_aead_enc_final(aead, tag, taglen);
}

/**
 * @ingroup KyberIES
 * @brief KyberIES decryption oneshot
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] sk Kyber secret key of data owner
 * @param [in] ct Kyber ciphertext received from the encryption operation
 * @param [in] ciphertext Ciphertext data to be encrypted
 * @param [out] plaintext Buffer of equal size as ciphertext that will be
 *			   filled with the decryption result
 * @param [in] datalen Length of the ciphertext buffer
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [in] tag Buffer with the authentication tag
 * @param [in] taglen Length of the tag buffer
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @return 0 on success, < 0 on error (-EBADMSG on integrity error)
 */
static inline int
lc_kyber_ies_dec(const struct lc_kyber_sk *sk, const struct lc_kyber_ct *ct,
		 const uint8_t *ciphertext, uint8_t *plaintext, size_t datalen,
		 const uint8_t *aad, size_t aadlen, const uint8_t *tag,
		 size_t taglen, struct lc_aead_ctx *aead)
{
	if (!sk || !ct || sk->kyber_type != ct->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_ies_dec(&sk->key.sk_1024, &ct->key.ct_1024,
					     ciphertext, plaintext, datalen,
					     aad, aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_ies_dec(&sk->key.sk_768, &ct->key.ct_768,
					    ciphertext, plaintext, datalen, aad,
					    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_ies_dec(&sk->key.sk_512, &ct->key.ct_512,
					    ciphertext, plaintext, datalen, aad,
					    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup KyberIES
 * @brief KyberIES decryption stream operation initialization
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * The aead context is initialized such that it can be used with
 * lc_kyber_ies_dec_[update|final].
 *
 * @param [out] aead Allocated AEAD algorithm - the caller only needs to provide
 *		     an allocated but otherwise unused instance of an AEAD
 *		     algorithm. This allows the caller to define the AEAD
 *		     algorithm type. The caller must zeroize and release the
 *		     context after completion.
 * @param [in] sk Kyber secret key of data owner
 * @param [in] ct Kyber ciphertext received from the encryption operation
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_ies_dec_init(struct lc_aead_ctx *aead,
					const struct lc_kyber_sk *sk,
					const struct lc_kyber_ct *ct,
					const uint8_t *aad, size_t aadlen)
{
	if (!sk || !ct || sk->kyber_type != ct->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_ies_dec_init(
			aead, &sk->key.sk_1024, &ct->key.ct_1024, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_ies_dec_init(aead, &sk->key.sk_768,
						 &ct->key.ct_768, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_ies_dec_init(aead, &sk->key.sk_512,
						 &ct->key.ct_512, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup KyberIES
 * @brief KyberIES decryption stream operation add more data
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] ciphertext Ciphertext data to be encrypted
 * @param [out] plaintext Buffer of equal size as ciphertext that will be
 *			   filled with the decryption result
 * @param [in] datalen Length of the ciphertext buffer
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_ies_dec_update(struct lc_aead_ctx *aead,
					  const uint8_t *ciphertext,
					  uint8_t *plaintext, size_t datalen)
{
	return lc_aead_dec_update(aead, ciphertext, plaintext, datalen);
}

/**
 * @ingroup KyberIES
 * @brief KyberIES decryption stream operation finalization / integrity test
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] tag Buffer with the authentication tag
 * @param [in] taglen Length of the tag buffer
 *
 * @return 0 on success, < 0 on error (-EBADMSG on integrity error)
 */
static inline int lc_kyber_ies_dec_final(struct lc_aead_ctx *aead,
					 const uint8_t *tag, size_t taglen)
{
	return lc_aead_dec_final(aead, tag, taglen);
}

/****************************** Kyber X25510 KEM ******************************/

#ifdef LC_KYBER_X25519_KEM

/** @defgroup HybridKyber ML-KEM / CRYSTALS-Kyber Hybrid Mechanism
 *
 * The hybrid KEM implements Kyber KEM together with the X25519 elliptic curve
 * KEX. The use is identical as the Kyber KEM. The only difference is that
 * the transmitted pk and ct has a different content.
 *
 * The API offered for the hybrid Kyber support can be used as a drop-in
 * replacement. The exception are the API calls to get the pointers to the
 * key members, Kyber ciphertext or shared secret data.
 *
 * See also the [separate Hybrid Kyber](https://leancrypto.org/papers/HybridKEM_algorithm.pdf)
 * documentation providing a mathematical specification.
 */

/**
 * @brief Kyber secret key
 */
struct lc_kyber_x25519_sk {
	enum lc_kyber_type kyber_type;
	union {
#ifdef LC_KYBER_1024_ENABLED
		struct lc_kyber_1024_x25519_sk sk_1024;
#endif
#ifdef LC_KYBER_768_ENABLED
		struct lc_kyber_768_x25519_sk sk_768;
#endif
#ifdef LC_KYBER_512_ENABLED
		struct lc_kyber_512_x25519_sk sk_512;
#endif
	} key;
};

/**
 * @brief Kyber public key
 */
struct lc_kyber_x25519_pk {
	enum lc_kyber_type kyber_type;
	union {
#ifdef LC_KYBER_1024_ENABLED
		struct lc_kyber_1024_x25519_pk pk_1024;
#endif
#ifdef LC_KYBER_768_ENABLED
		struct lc_kyber_768_x25519_pk pk_768;
#endif
#ifdef LC_KYBER_512_ENABLED
		struct lc_kyber_512_x25519_pk pk_512;
#endif
	} key;
};

/**
 * @brief Kyber ciphertext
 */
struct lc_kyber_x25519_ct {
	enum lc_kyber_type kyber_type;
	union {
#ifdef LC_KYBER_1024_ENABLED
		struct lc_kyber_1024_x25519_ct ct_1024;
#endif
#ifdef LC_KYBER_768_ENABLED
		struct lc_kyber_768_x25519_ct ct_768;
#endif
#ifdef LC_KYBER_512_ENABLED
		struct lc_kyber_512_x25519_ct ct_512;
#endif
	} key;
};

/**
 * @brief Kyber shared secret
 */
struct lc_kyber_x25519_ss {
	enum lc_kyber_type kyber_type;
	union {
#ifdef LC_KYBER_1024_ENABLED
		struct lc_kyber_1024_x25519_ss ss_1024;
#endif
#ifdef LC_KYBER_768_ENABLED
		struct lc_kyber_768_x25519_ss ss_768;
#endif
#ifdef LC_KYBER_512_ENABLED
		struct lc_kyber_512_x25519_ss ss_512;
#endif
	} key;
};

/**
 * @ingroup HybridKyber
 * @brief Obtain Kyber type from secret key
 *
 * @param [in] sk Secret key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_kyber_type
lc_kyber_x25519_sk_type(const struct lc_kyber_x25519_sk *sk)
{
	if (!sk)
		return LC_KYBER_UNKNOWN;
	return sk->kyber_type;
}

/**
 * @ingroup HybridKyber
 * @brief Obtain Kyber type from public key
 *
 * @param [in] pk Public key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_kyber_type
lc_kyber_x25519_pk_type(const struct lc_kyber_x25519_pk *pk)
{
	if (!pk)
		return LC_KYBER_UNKNOWN;
	return pk->kyber_type;
}

/**
 * @ingroup HybridKyber
 * @brief Obtain Kyber type from Kyber ciphertext
 *
 * @param [in] ct Ciphertext from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_kyber_type
lc_kyber_x25519_ct_type(const struct lc_kyber_x25519_ct *ct)
{
	if (!ct)
		return LC_KYBER_UNKNOWN;
	return ct->kyber_type;
}

/**
 * @ingroup HybridKyber
 * @brief Obtain Kyber type from shared secret
 *
 * @param [in] ss Shared secret key from which the type is to be obtained
 *
 * @return key type
 */
static inline enum lc_kyber_type
lc_kyber_x25519_ss_type(const struct lc_kyber_x25519_ss *ss)
{
	if (!ss)
		return LC_KYBER_UNKNOWN;
	return ss->kyber_type;
}

/**
 * @ingroup HybridKyber
 * @brief Return the size of the Kyber secret key.
 *
 * @param [in] kyber_type Kyber type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_kyber_x25519_sk_size(enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_x25519_sk, key.sk_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_x25519_sk, key.sk_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_x25519_sk, key.sk_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Return the size of the Kyber public key.
 *
 * @param [in] kyber_type Kyber type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_kyber_x25519_pk_size(enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_x25519_pk, key.pk_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_x25519_pk, key.pk_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_x25519_pk, key.pk_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Return the size of the Kyber ciphertext.
 *
 * @param [in] kyber_type Kyber type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_kyber_x25519_ct_size(enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ct, key.ct_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ct, key.ct_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ct, key.ct_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Return the size of the Kyber shared secret.
 *
 * @param [in] kyber_type Kyber type for which the size is requested
 *
 * @return requested size
 */
LC_PURE
static inline unsigned int
lc_kyber_x25519_ss_size(enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ss, key.ss_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ss, key.ss_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ss, key.ss_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

static inline int lc_kyber_x25519_sk_load(struct lc_kyber_x25519_sk *sk,
					  const uint8_t *kyber_src_key,
					  size_t kyber_src_key_len,
					  const uint8_t *x25519_src_key,
					  size_t x25519_src_key_len)
{
	if (!sk || !kyber_src_key_len || !x25519_src_key_len ||
	    kyber_src_key_len == 0 ||
	    x25519_src_key_len != LC_X25519_SECRETKEYBYTES) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (kyber_src_key_len == lc_kyber_sk_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_x25519_sk *_sk = &sk->key.sk_1024;

		memcpy(_sk->sk.sk, kyber_src_key, kyber_src_key_len);
		memcpy(_sk->sk_x25519.sk, x25519_src_key, x25519_src_key_len);
		sk->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (kyber_src_key_len == lc_kyber_sk_size(LC_KYBER_768)) {
		struct lc_kyber_768_x25519_sk *_sk = &sk->key.sk_768;

		memcpy(_sk->sk.sk, kyber_src_key, kyber_src_key_len);
		memcpy(_sk->sk_x25519.sk, x25519_src_key, x25519_src_key_len);
		sk->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (kyber_src_key_len == lc_kyber_sk_size(LC_KYBER_512)) {
		struct lc_kyber_512_x25519_sk *_sk = &sk->key.sk_512;

		memcpy(_sk->sk.sk, kyber_src_key, kyber_src_key_len);
		memcpy(_sk->sk_x25519.sk, x25519_src_key, x25519_src_key_len);
		sk->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

static inline int lc_kyber_x25519_pk_load(struct lc_kyber_x25519_pk *pk,
					  const uint8_t *kyber_src_key,
					  size_t kyber_src_key_len,
					  const uint8_t *x25519_src_key,
					  size_t x25519_src_key_len)
{
	if (!pk || !kyber_src_key_len || !x25519_src_key_len ||
	    kyber_src_key_len == 0 ||
	    x25519_src_key_len != LC_X25519_PUBLICKEYBYTES) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (kyber_src_key_len == lc_kyber_pk_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_x25519_pk *_pk = &pk->key.pk_1024;

		memcpy(_pk->pk.pk, kyber_src_key, kyber_src_key_len);
		memcpy(_pk->pk_x25519.pk, x25519_src_key, x25519_src_key_len);
		pk->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (kyber_src_key_len == lc_kyber_pk_size(LC_KYBER_768)) {
		struct lc_kyber_768_x25519_pk *_pk = &pk->key.pk_768;

		memcpy(_pk->pk.pk, kyber_src_key, kyber_src_key_len);
		memcpy(_pk->pk_x25519.pk, x25519_src_key, x25519_src_key_len);
		pk->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (kyber_src_key_len == lc_kyber_pk_size(LC_KYBER_512)) {
		struct lc_kyber_512_x25519_pk *_pk = &pk->key.pk_512;

		memcpy(_pk->pk.pk, kyber_src_key, kyber_src_key_len);
		memcpy(_pk->pk_x25519.pk, x25519_src_key, x25519_src_key_len);
		pk->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

static inline int lc_kyber_x25519_ct_load(struct lc_kyber_x25519_ct *ct,
					  const uint8_t *kyber_src_ct,
					  size_t kyber_src_ct_len,
					  const uint8_t *x25519_rem_pub_key,
					  size_t x25519_rem_pub_len)
{
	if (!ct || !kyber_src_ct_len || !x25519_rem_pub_len ||
	    kyber_src_ct_len == 0 ||
	    x25519_rem_pub_len != LC_X25519_PUBLICKEYBYTES) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (kyber_src_ct_len == lc_kyber_ct_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_x25519_ct *_ct = &ct->key.ct_1024;

		memcpy(_ct->ct.ct, kyber_src_ct, kyber_src_ct_len);
		memcpy(_ct->pk_x25519.pk, x25519_rem_pub_key,
		       x25519_rem_pub_len);
		ct->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (kyber_src_ct_len == lc_kyber_ct_size(LC_KYBER_768)) {
		struct lc_kyber_768_x25519_ct *_ct = &ct->key.ct_768;

		memcpy(_ct->ct.ct, kyber_src_ct, kyber_src_ct_len);
		memcpy(_ct->pk_x25519.pk, x25519_rem_pub_key,
		       x25519_rem_pub_len);
		ct->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (kyber_src_ct_len == lc_kyber_ct_size(LC_KYBER_512)) {
		struct lc_kyber_512_x25519_ct *_ct = &ct->key.ct_512;

		memcpy(_ct->ct.ct, kyber_src_ct, kyber_src_ct_len);
		memcpy(_ct->pk_x25519.pk, x25519_rem_pub_key,
		       x25519_rem_pub_len);
		ct->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

static inline int lc_kyber_x25519_ss_load(struct lc_kyber_x25519_ss *ss,
					  const uint8_t *kyber_src_ss,
					  size_t kyber_src_ss_len,
					  const uint8_t *x25519_ss,
					  size_t x25519_ss_len)
{
	if (!ss || !kyber_src_ss_len || !x25519_ss_len ||
	    kyber_src_ss_len == 0 || x25519_ss_len != LC_X25519_SSBYTES) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (kyber_src_ss_len == lc_kyber_ss_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_x25519_ss *_ss = &ss->key.ss_1024;

		memcpy(_ss->ss.ss, kyber_src_ss, kyber_src_ss_len);
		memcpy(_ss->ss_x25519.ss, x25519_ss, x25519_ss_len);
		ss->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (kyber_src_ss_len == lc_kyber_ss_size(LC_KYBER_768)) {
		struct lc_kyber_768_x25519_ss *_ss = &ss->key.ss_768;

		memcpy(_ss->ss.ss, kyber_src_ss, kyber_src_ss_len);
		memcpy(_ss->ss_x25519.ss, x25519_ss, x25519_ss_len);
		ss->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (kyber_src_ss_len == lc_kyber_ss_size(LC_KYBER_512)) {
		struct lc_kyber_512_x25519_ss *_ss = &ss->key.ss_512;

		memcpy(_ss->ss.ss, kyber_src_ss, kyber_src_ss_len);
		memcpy(_ss->ss_x25519.ss, x25519_ss, x25519_ss_len);
		ss->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Obtain the reference to the Kyber key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] kyber_key Kyber key pointer
 * @param [out] kyber_key_len Length of the key buffer
 * @param [out] x25519_key X25519 key pointer
 * @param [out] x25519_key_len X25519 of the key buffer
 * @param [in] sk Hybrid secret key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_kyber_x25519_sk_ptr(uint8_t **kyber_key,
					 size_t *kyber_key_len,
					 uint8_t **x25519_key,
					 size_t *x25519_key_len,
					 struct lc_kyber_x25519_sk *sk)
{
	if (!sk || !kyber_key || !kyber_key_len || !x25519_key ||
	    !x25519_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (sk->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_x25519_sk *_sk = &sk->key.sk_1024;

		*kyber_key = _sk->sk.sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		*x25519_key = _sk->sk_x25519.sk;
		*x25519_key_len = LC_X25519_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (sk->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_x25519_sk *_sk = &sk->key.sk_768;

		*kyber_key = _sk->sk.sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		*x25519_key = _sk->sk_x25519.sk;
		*x25519_key_len = LC_X25519_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (sk->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_x25519_sk *_sk = &sk->key.sk_512;

		*kyber_key = _sk->sk.sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		*x25519_key = _sk->sk_x25519.sk;
		*x25519_key_len = LC_X25519_SECRETKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Obtain the reference to the Kyber key and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto key, too.
 *
 * @param [out] kyber_key Kyber key pointer
 * @param [out] kyber_key_len Length of the key buffer
 * @param [out] x25519_key X25519 key pointer
 * @param [out] x25519_key_len X25519 of the key buffer
 * @param [in] pk Hybrid public key from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_kyber_x25519_pk_ptr(uint8_t **kyber_key,
					 size_t *kyber_key_len,
					 uint8_t **x25519_key,
					 size_t *x25519_key_len,
					 struct lc_kyber_x25519_pk *pk)
{
	if (!pk || !kyber_key || !kyber_key_len || !x25519_key ||
	    !x25519_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (pk->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_x25519_pk *_pk = &pk->key.pk_1024;

		*kyber_key = _pk->pk.pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		*x25519_key = _pk->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (pk->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_x25519_pk *_pk = &pk->key.pk_768;

		*kyber_key = _pk->pk.pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		*x25519_key = _pk->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (pk->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_x25519_pk *_pk = &pk->key.pk_512;

		*kyber_key = _pk->pk.pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		*x25519_key = _pk->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Obtain the reference to the Kyber ciphertext and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto ciphertext,
 * too.
 *
 * @param [out] kyber_ct Kyber ciphertext pointer
 * @param [out] kyber_ct_len Length of the ciphertext buffer
 * @param [out] x25519_key X25519 ephermeral public key pointer
 * @param [out] x25519_key_len X25519 of the key buffer
 * @param [in] ct Hybrid ciphertext from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_kyber_x25519_ct_ptr(uint8_t **kyber_ct,
					 size_t *kyber_ct_len,
					 uint8_t **x25519_key,
					 size_t *x25519_key_len,
					 struct lc_kyber_x25519_ct *ct)
{
	if (!ct || !kyber_ct || !kyber_ct_len || !x25519_key ||
	    !x25519_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (ct->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_x25519_ct *_ct = &ct->key.ct_1024;

		*kyber_ct = _ct->ct.ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		*x25519_key = _ct->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (ct->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_x25519_ct *_ct = &ct->key.ct_768;

		*kyber_ct = _ct->ct.ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		*x25519_key = _ct->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (ct->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_x25519_ct *_ct = &ct->key.ct_512;

		*kyber_ct = _ct->ct.ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		*x25519_key = _ct->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Obtain the reference to the Kyber shared secret and its length
 *
 * NOTE: Only pointer references into the leancrypto data structure are returned
 * which implies that any modification will modify the leancrypto shared secret,
 * too.
 *
 * @param [out] kyber_ss Kyber shared secret pointer
 * @param [out] kyber_ss_len Length of the shared secret buffer
 * @param [out] x25519_ss X25519 shared secret pointer
 * @param [out] x25519_ss_len X25519 of the shared secret buffer
 * @param [in] ss Hybrid shared secret from which the references are obtained
 *
 * @return 0 on success, != 0 on error
 */
static inline int lc_kyber_x25519_ss_ptr(uint8_t **kyber_ss,
					 size_t *kyber_ss_len,
					 uint8_t **x25519_ss,
					 size_t *x25519_ss_len,
					 struct lc_kyber_x25519_ss *ss)
{
	if (!ss || !kyber_ss || !kyber_ss_len || !x25519_ss || !x25519_ss_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (ss->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_x25519_ss *_ss = &ss->key.ss_1024;

		*kyber_ss = _ss->ss.ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		*x25519_ss = _ss->ss_x25519.ss;
		*x25519_ss_len = LC_X25519_SSBYTES;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (ss->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_x25519_ss *_ss = &ss->key.ss_768;

		*kyber_ss = _ss->ss.ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		*x25519_ss = _ss->ss_x25519.ss;
		*x25519_ss_len = LC_X25519_SSBYTES;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (ss->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_x25519_ss *_ss = &ss->key.ss_512;

		*kyber_ss = _ss->ss.ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		*x25519_ss = _ss->ss_x25519.ss;
		*x25519_ss_len = LC_X25519_SSBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Generates public and private key for IND-CCA2-secure Kyber key
 *	  encapsulation mechanism
 *
 * @param [out] pk pointer to already allocated output public key
 * @param [out] sk pointer to already allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 * @param [in] kyber_type type of the Kyber key to generate
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kyber_x25519_keypair(struct lc_kyber_x25519_pk *pk,
					  struct lc_kyber_x25519_sk *sk,
					  struct lc_rng_ctx *rng_ctx,
					  enum lc_kyber_type kyber_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_1024_x25519_keypair(&pk->key.pk_1024,
						    &sk->key.sk_1024, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_768_x25519_keypair(&pk->key.pk_768,
						   &sk->key.sk_768, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_512_x25519_keypair(&pk->key.pk_512,
						   &sk->key.sk_512, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Key encapsulation with KDF applied to shared secret
 *
 * Generates cipher text and shared secret for given public key. The shared
 * secret is derived from the Kyber SS using the KDF derived from the round 3
 * definition of Kyber:
 *
 *	SS <- KMAC256(K = Kyber-SS || X25519-SS, X = Kyber-CT,
 *		      L = requested SS length, S = "Kyber KEM Double SS")
 *
 * NOTE: The concatenatino of Kyber-SS || ECC-SS complies with SP800-56C rev 2
 * chapter 2 defining the hybrid shared secret of the form Z' = Z || T where
 * Z is the "standard shared secret" from Kyber followed by the auxiliary
 * shared secret T that has been generated by some other method.
 *
 * @param [out] ct pointer to output cipher text to used for decapsulation
 * @param [out] ss pointer to output shared secret that will be also produced
 *		   during decapsulation
 * @param [in] ss_len length of shared secret to be generated
 * @param [in] pk pointer to input public key
 *
 * Returns 0 (success) or < 0 on error
 */
static inline int lc_kyber_x25519_enc_kdf(struct lc_kyber_x25519_ct *ct,
					  uint8_t *ss, size_t ss_len,
					  const struct lc_kyber_x25519_pk *pk)
{
	if (!ct || !pk)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_x25519_enc_kdf(&ct->key.ct_1024, ss,
						    ss_len, &pk->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_x25519_enc_kdf(&ct->key.ct_768, ss, ss_len,
						   &pk->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_x25519_enc_kdf(&ct->key.ct_512, ss, ss_len,
						   &pk->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Key decapsulation with KDF applied to shared secret
 *
 * Generates cipher text and shared secret for given private key. The shared
 * secret is derived from the Kyber SS using the KDF derived from the round 3
 * definition of Kyber:
 *
 *	SS <- KMAC256(K = Kyber-SS || X25519-SS, X = Kyber-CT,
 *		      L = requested SS length, S = "Kyber KEM Double SS")
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
static inline int lc_kyber_x25519_dec_kdf(uint8_t *ss, size_t ss_len,
					  const struct lc_kyber_x25519_ct *ct,
					  const struct lc_kyber_x25519_sk *sk)
{
	if (!ct || !sk || ct->kyber_type != sk->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_x25519_dec_kdf(
			ss, ss_len, &ct->key.ct_1024, &sk->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_x25519_dec_kdf(ss, ss_len, &ct->key.ct_768,
						   &sk->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_x25519_dec_kdf(ss, ss_len, &ct->key.ct_512,
						   &sk->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/****************************** Kyber X25510 KEX ******************************/

/**
 * @ingroup HybridKyber
 * @brief Initialize unilaterally authenticated key exchange
 *
 * @param [out] pk_e_i initiator's ephemeral public key to be sent to the
 *		       responder
 * @param [out] ct_e_i initiator's ephemeral cipher text to be sent to the
 *		       responder
 * @param [out] tk KEM shared secret data to be used for the initiator's shared
 *		   secret generation
 * @param [out] sk_e initiator's ephemeral secret key to be used for the
 *		     initiator's shared secret generation
 * @param [in] pk_r responder's public key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kex_x25519_uake_initiator_init(
	struct lc_kyber_x25519_pk *pk_e_i, struct lc_kyber_x25519_ct *ct_e_i,
	struct lc_kyber_x25519_ss *tk, struct lc_kyber_x25519_sk *sk_e,
	const struct lc_kyber_x25519_pk *pk_r)
{
	if (!pk_e_i || !ct_e_i || !tk || !sk_e || !pk_r)
		return -EINVAL;

	switch (pk_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk_e_i->kyber_type = LC_KYBER_1024;
		ct_e_i->kyber_type = LC_KYBER_1024;
		tk->kyber_type = LC_KYBER_1024;
		sk_e->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_x25519_uake_initiator_init(
			&pk_e_i->key.pk_1024, &ct_e_i->key.ct_1024,
			&tk->key.ss_1024, &sk_e->key.sk_1024,
			&pk_r->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk_e_i->kyber_type = LC_KYBER_768;
		ct_e_i->kyber_type = LC_KYBER_768;
		tk->kyber_type = LC_KYBER_768;
		sk_e->kyber_type = LC_KYBER_768;
		return lc_kex_768_x25519_uake_initiator_init(
			&pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&tk->key.ss_768, &sk_e->key.sk_768, &pk_r->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk_e_i->kyber_type = LC_KYBER_512;
		ct_e_i->kyber_type = LC_KYBER_512;
		tk->kyber_type = LC_KYBER_512;
		sk_e->kyber_type = LC_KYBER_512;
		return lc_kex_512_x25519_uake_initiator_init(
			&pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&tk->key.ss_512, &sk_e->key.sk_512, &pk_r->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Initiator's shared secret generation
 *
 * @param [out] ct_e_r responder's ephemeral cipher text to be sent to the
 *		       initiator
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] pk_e_i initiator's ephemeral public key
 * @param [in] ct_e_i initiator's ephemeral cipher text
 * @param [in] sk_r responder's secret key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kex_x25519_uake_responder_ss(
	struct lc_kyber_x25519_ct *ct_e_r, uint8_t *shared_secret,
	size_t shared_secret_len, const uint8_t *kdf_nonce,
	size_t kdf_nonce_len, const struct lc_kyber_x25519_pk *pk_e_i,
	const struct lc_kyber_x25519_ct *ct_e_i,
	const struct lc_kyber_x25519_sk *sk_r)
{
	if (!ct_e_r || !pk_e_i || !ct_e_i || !sk_r ||
	    pk_e_i->kyber_type != ct_e_i->kyber_type ||
	    pk_e_i->kyber_type != sk_r->kyber_type)
		return -EINVAL;

	switch (pk_e_i->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct_e_r->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_x25519_uake_responder_ss(
			&ct_e_r->key.ct_1024, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_1024,
			&ct_e_i->key.ct_1024, &sk_r->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct_e_r->kyber_type = LC_KYBER_768;
		return lc_kex_768_x25519_uake_responder_ss(
			&ct_e_r->key.ct_768, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_768,
			&ct_e_i->key.ct_768, &sk_r->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct_e_r->kyber_type = LC_KYBER_512;
		return lc_kex_512_x25519_uake_responder_ss(
			&ct_e_r->key.ct_512, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_512,
			&ct_e_i->key.ct_512, &sk_r->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Responder's shared secret generation
 *
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] ct_e_r responder's ephemeral cipher text
 * @param [in] tk KEM shared secret data that was generated during the
 *		  initiator's initialization
 * @param [in] sk_e initiator's ephemeral secret that was generated during the
 *		    initiator's initialization
 *
 * @return 0 (success) or < 0 on error
 */
static inline int
lc_kex_x25519_uake_initiator_ss(uint8_t *shared_secret,
				size_t shared_secret_len,
				const uint8_t *kdf_nonce, size_t kdf_nonce_len,
				const struct lc_kyber_x25519_ct *ct_e_r,
				const struct lc_kyber_x25519_ss *tk,
				const struct lc_kyber_x25519_sk *sk_e)
{
	if (!ct_e_r || !tk || !sk_e || ct_e_r->kyber_type != tk->kyber_type ||
	    ct_e_r->kyber_type != sk_e->kyber_type)
		return -EINVAL;

	switch (ct_e_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kex_1024_x25519_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_1024, &tk->key.ss_1024,
			&sk_e->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kex_768_x25519_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_768, &tk->key.ss_768,
			&sk_e->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kex_512_x25519_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_512, &tk->key.ss_512,
			&sk_e->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Initialize authenticated key exchange
 *
 * @param [out] pk_e_i initiator's ephemeral public key to be sent to the
 *		       responder
 * @param [out] ct_e_i initiator's ephemeral cipher text to be sent to the
 *		       responder
 * @param [out] tk KEM shared secret data to be used for the initiator's shared
 *		   secret generation
 * @param [out] sk_e initiator's ephemeral secret key to be used for the
 *		     initiator's shared secret generation
 * @param [in] pk_r responder's public key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int lc_kex_x25519_ake_initiator_init(
	struct lc_kyber_x25519_pk *pk_e_i, struct lc_kyber_x25519_ct *ct_e_i,
	struct lc_kyber_x25519_ss *tk, struct lc_kyber_x25519_sk *sk_e,
	const struct lc_kyber_x25519_pk *pk_r)
{
	if (!pk_e_i || !ct_e_i || !tk || !sk_e || !pk_r)
		return -EINVAL;

	switch (pk_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk_e_i->kyber_type = LC_KYBER_1024;
		ct_e_i->kyber_type = LC_KYBER_1024;
		tk->kyber_type = LC_KYBER_1024;
		sk_e->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_x25519_ake_initiator_init(
			&pk_e_i->key.pk_1024, &ct_e_i->key.ct_1024,
			&tk->key.ss_1024, &sk_e->key.sk_1024,
			&pk_r->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk_e_i->kyber_type = LC_KYBER_768;
		ct_e_i->kyber_type = LC_KYBER_768;
		tk->kyber_type = LC_KYBER_768;
		sk_e->kyber_type = LC_KYBER_768;
		return lc_kex_768_x25519_ake_initiator_init(
			&pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&tk->key.ss_768, &sk_e->key.sk_768, &pk_r->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk_e_i->kyber_type = LC_KYBER_512;
		ct_e_i->kyber_type = LC_KYBER_512;
		tk->kyber_type = LC_KYBER_512;
		sk_e->kyber_type = LC_KYBER_512;
		return lc_kex_512_x25519_ake_initiator_init(
			&pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&tk->key.ss_512, &sk_e->key.sk_512, &pk_r->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Initiator's shared secret generation
 *
 * @param [out] ct_e_r_1 responder's ephemeral cipher text to be sent to the
 *			 initator
 * @param [out] ct_e_r_2 responder's ephemeral cipher text to be sent to the
 *			 initator
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] pk_e_i initator's ephemeral public key
 * @param [in] ct_e_i initator's ephemeral cipher text
 * @param [in] sk_r responder's secret key
 * @param [in] pk_i initator's public key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int
lc_kex_x25519_ake_responder_ss(struct lc_kyber_x25519_ct *ct_e_r_1,
			       struct lc_kyber_x25519_ct *ct_e_r_2,
			       uint8_t *shared_secret, size_t shared_secret_len,
			       const uint8_t *kdf_nonce, size_t kdf_nonce_len,
			       const struct lc_kyber_x25519_pk *pk_e_i,
			       const struct lc_kyber_x25519_ct *ct_e_i,
			       const struct lc_kyber_x25519_sk *sk_r,
			       const struct lc_kyber_x25519_pk *pk_i)
{
	if (!ct_e_r_1 || !ct_e_r_2 || !pk_e_i || !ct_e_i || !sk_r || !pk_i ||
	    pk_e_i->kyber_type != ct_e_i->kyber_type ||
	    pk_e_i->kyber_type != sk_r->kyber_type ||
	    pk_e_i->kyber_type != pk_i->kyber_type)
		return -EINVAL;

	switch (pk_e_i->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_1024;
		ct_e_r_2->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_x25519_ake_responder_ss(
			&ct_e_r_1->key.ct_1024, &ct_e_r_2->key.ct_1024,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_1024,
			&ct_e_i->key.ct_1024, &sk_r->key.sk_1024,
			&pk_i->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_768;
		ct_e_r_2->kyber_type = LC_KYBER_768;
		return lc_kex_768_x25519_ake_responder_ss(
			&ct_e_r_1->key.ct_768, &ct_e_r_2->key.ct_768,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&sk_r->key.sk_768, &pk_i->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_512;
		ct_e_r_2->kyber_type = LC_KYBER_512;
		return lc_kex_512_x25519_ake_responder_ss(
			&ct_e_r_1->key.ct_512, &ct_e_r_2->key.ct_512,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&sk_r->key.sk_512, &pk_i->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief Responder's shared secret generation
 *
 * @param [out] shared_secret Shared secret between initiator and responder
 * @param [in] shared_secret_len Requested size of the shared secret
 * @param [in] kdf_nonce An optional nonce that is concatenated at the end of
 *			 the Kyber KEX-generated data to be inserted into
 *			 the KDF. If not required, use NULL.
 * @param [in] kdf_nonce_len Length of the kdf_nonce.
 * @param [in] ct_e_r_1 responder's ephemeral cipher text
 * @param [in] ct_e_r_2 responder's ephemeral cipher text
 * @param [in] tk KEM shared secret data that was generated during the
 *		  initator's initialization
 * @param [in] sk_e initator's ephemeral secret that was generated during the
 *		    initator's initialization
 * @param [in] sk_i initator's secret key
 *
 * @return 0 (success) or < 0 on error
 */
static inline int
lc_kex_x25519_ake_initiator_ss(uint8_t *shared_secret, size_t shared_secret_len,
			       const uint8_t *kdf_nonce, size_t kdf_nonce_len,
			       const struct lc_kyber_x25519_ct *ct_e_r_1,
			       const struct lc_kyber_x25519_ct *ct_e_r_2,
			       const struct lc_kyber_x25519_ss *tk,
			       const struct lc_kyber_x25519_sk *sk_e,
			       const struct lc_kyber_x25519_sk *sk_i)
{
	if (!ct_e_r_1 || !ct_e_r_2 || !tk || !sk_e || !sk_i ||
	    ct_e_r_1->kyber_type != ct_e_r_2->kyber_type ||
	    ct_e_r_1->kyber_type != tk->kyber_type ||
	    ct_e_r_1->kyber_type != sk_e->kyber_type ||
	    ct_e_r_1->kyber_type != sk_i->kyber_type)
		return -EINVAL;

	switch (ct_e_r_1->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kex_1024_x25519_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_1024,
			&ct_e_r_2->key.ct_1024, &tk->key.ss_1024,
			&sk_e->key.sk_1024, &sk_i->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kex_768_x25519_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_768,
			&ct_e_r_2->key.ct_768, &tk->key.ss_768,
			&sk_e->key.sk_768, &sk_i->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kex_512_x25519_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_512,
			&ct_e_r_2->key.ct_512, &tk->key.ss_512,
			&sk_e->key.sk_512, &sk_i->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/****************************** Kyber X25519 IES ******************************/
/**
 * @ingroup HybridKyber
 * @brief KyberIES encryption oneshot
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] pk Kyber public key of data owner
 * @param [out] ct Kyber ciphertext to be sent to the decryption operation
 * @param [in] plaintext Plaintext data to be encrypted
 * @param [out] ciphertext Buffer of equal size as plaintext that will be filled
 *			   with the encryption result
 * @param [in] datalen Length of the plaintext buffer
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [out] tag Buffer that will be filled with the authentication tag
 * @param [in] taglen Length of the tag buffer
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_x25519_ies_enc(const struct lc_kyber_x25519_pk *pk,
					  struct lc_kyber_x25519_ct *ct,
					  const uint8_t *plaintext,
					  uint8_t *ciphertext, size_t datalen,
					  const uint8_t *aad, size_t aadlen,
					  uint8_t *tag, size_t taglen,
					  struct lc_aead_ctx *aead)
{
	if (!pk || !ct)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_x25519_ies_enc(&pk->key.pk_1024,
						    &ct->key.ct_1024, plaintext,
						    ciphertext, datalen, aad,
						    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_x25519_ies_enc(&pk->key.pk_768,
						   &ct->key.ct_768, plaintext,
						   ciphertext, datalen, aad,
						   aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_x25519_ies_enc(&pk->key.pk_512,
						   &ct->key.ct_512, plaintext,
						   ciphertext, datalen, aad,
						   aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief KyberIES encryption stream operation initialization
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * The aead context is initialized such that it can be used with
 * lc_kyber_x25519_ies_enc_[update|final].
 *
 * @param [out] aead Allocated AEAD algorithm - the caller only needs to provide
 *		     an allocated but otherwise unused instance of an AEAD
 *		     algorithm. This allows the caller to define the AEAD
 *		     algorithm type. The caller must zeroize and release the
 *		     context after completion.
 * @param [in] pk Kyber public key of data owner
 * @param [out] ct Kyber ciphertext to be sent to the decryption operation
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_x25519_ies_enc_init(
	struct lc_aead_ctx *aead, const struct lc_kyber_x25519_pk *pk,
	struct lc_kyber_x25519_ct *ct, const uint8_t *aad, size_t aadlen)
{
	if (!pk || !ct)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_x25519_ies_enc_init(
			aead, &pk->key.pk_1024, &ct->key.ct_1024, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_x25519_ies_enc_init(
			aead, &pk->key.pk_768, &ct->key.ct_768, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_x25519_ies_enc_init(
			aead, &pk->key.pk_512, &ct->key.ct_512, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief KyberIES encryption stream operation add more data
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] plaintext Plaintext data to be encrypted
 * @param [out] ciphertext Buffer of equal size as plaintext that will be filled
 *			   with the encryption result
 * @param [in] datalen Length of the plaintext buffer
 */
static inline int lc_kyber_x25519_ies_enc_update(struct lc_aead_ctx *aead,
						 const uint8_t *plaintext,
						 uint8_t *ciphertext,
						 size_t datalen)
{
	return lc_aead_enc_update(aead, plaintext, ciphertext, datalen);
}

/**
 * @ingroup HybridKyber
 * @brief KyberIES encryption stream operation finalization / integrity test
 *
 * The implementation supports an in-place data encryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [out] tag Buffer that will be filled with the authentication tag
 * @param [in] taglen Length of the tag buffer
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_x25519_ies_enc_final(struct lc_aead_ctx *aead,
						uint8_t *tag, size_t taglen)
{
	return lc_aead_enc_final(aead, tag, taglen);
}

/**
 * @ingroup HybridKyber
 * @brief KyberIES decryption oneshot
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] sk Kyber secret key of data owner
 * @param [in] ct Kyber ciphertext received from the encryption operation
 * @param [in] ciphertext Ciphertext data to be encrypted
 * @param [out] plaintext Buffer of equal size as ciphertext that will be
 *			   filled with the decryption result
 * @param [in] datalen Length of the ciphertext buffer
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [in] tag Buffer with the authentication tag
 * @param [in] taglen Length of the tag buffer
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 *
 * @return 0 on success, < 0 on error (-EBADMSG on integrity error)
 */
static inline int lc_kyber_x25519_ies_dec(const struct lc_kyber_x25519_sk *sk,
					  const struct lc_kyber_x25519_ct *ct,
					  const uint8_t *ciphertext,
					  uint8_t *plaintext, size_t datalen,
					  const uint8_t *aad, size_t aadlen,
					  const uint8_t *tag, size_t taglen,
					  struct lc_aead_ctx *aead)
{
	if (!sk || !ct || sk->kyber_type != ct->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_x25519_ies_dec(
			&sk->key.sk_1024, &ct->key.ct_1024, ciphertext,
			plaintext, datalen, aad, aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_x25519_ies_dec(&sk->key.sk_768,
						   &ct->key.ct_768, ciphertext,
						   plaintext, datalen, aad,
						   aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_x25519_ies_dec(&sk->key.sk_512,
						   &ct->key.ct_512, ciphertext,
						   plaintext, datalen, aad,
						   aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief KyberIES decryption stream operation initialization
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * The aead context is initialized such that it can be used with
 * lc_kyber_x25519_ies_dec_[update|final].
 *
 * @param [out] aead Allocated AEAD algorithm - the caller only needs to provide
 *		     an allocated but otherwise unused instance of an AEAD
 *		     algorithm. This allows the caller to define the AEAD
 *		     algorithm type. The caller must zeroize and release the
 *		     context after completion.
 * @param [in] sk Kyber secret key of data owner
 * @param [in] ct Kyber ciphertext received from the encryption operation
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_x25519_ies_dec_init(
	struct lc_aead_ctx *aead, const struct lc_kyber_x25519_sk *sk,
	const struct lc_kyber_x25519_ct *ct, const uint8_t *aad, size_t aadlen)
{
	if (!sk || !ct || sk->kyber_type != ct->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_x25519_ies_dec_init(
			aead, &sk->key.sk_1024, &ct->key.ct_1024, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_x25519_ies_dec_init(
			aead, &sk->key.sk_768, &ct->key.ct_768, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_x25519_ies_dec_init(
			aead, &sk->key.sk_512, &ct->key.ct_512, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * @ingroup HybridKyber
 * @brief KyberIES decryption stream operation add more data
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] ciphertext Ciphertext data to be encrypted
 * @param [out] plaintext Buffer of equal size as ciphertext that will be
 *			   filled with the decryption result
 * @param [in] datalen Length of the ciphertext buffer
 *
 * @return 0 on success, < 0 on error
 */
static inline int lc_kyber_x25519_ies_dec_update(struct lc_aead_ctx *aead,
						 const uint8_t *ciphertext,
						 uint8_t *plaintext,
						 size_t datalen)
{
	return lc_aead_dec_update(aead, ciphertext, plaintext, datalen);
}

/**
 * @ingroup HybridKyber
 * @brief KyberIES decryption stream operation finalization / integrity test
 *
 * The implementation supports an in-place data decryption where the
 * plaintext and ciphertext buffer pointers refer to the same memory location.
 *
 * The function entirely operates on stack memory.
 *
 * @param [in] aead Allocated AEAD algorithm - the caller only needs to provide
 *		    an allocated but otherwise unused instance of an AEAD
 *		    algorithm. This allows the caller to define the AEAD
 *		    algorithm type. The caller must zeroize and release the
 *		    context after completion.
 * @param [in] tag Buffer with the authentication tag
 * @param [in] taglen Length of the tag buffer
 *
 * @return 0 on success, < 0 on error (-EBADMSG on integrity error)
 */
static inline int lc_kyber_x25519_ies_dec_final(struct lc_aead_ctx *aead,
						const uint8_t *tag,
						size_t taglen)
{
	return lc_aead_dec_final(aead, tag, taglen);
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* LC_KYBER_H */
