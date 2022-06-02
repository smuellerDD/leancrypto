/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_KMAC_CRYPT_H
#define LC_KMAC_CRYPT_H

#include <stdint.h>
#include <sys/types.h>

/*
 * This is the KMAC crypt cipher operation using the KMAC output as keystream
 */
#include "lc_kmac.h"
#include "memset_secure.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_kc_cryptor {
	struct lc_kmac_ctx kmac;
	struct lc_kmac_ctx auth_ctx;
	size_t keystream_ptr;
	uint8_t *keystream;
};

/*
 * The block size of the algorithm for generating the key stream. It must be
 * a multiple of the cSHAKE block size.
 */
#define LC_KC_KEYSTREAM_BLOCK	LC_SHA3_256_SIZE_BLOCK

#define LC_KC_STATE_SIZE(x)	(2 * LC_KMAC_STATE_SIZE(x) +		       \
				 LC_KC_KEYSTREAM_BLOCK)
#define LC_KC_CTX_SIZE(x)	(sizeof(struct lc_kc_cryptor) +		       \
				 LC_KC_STATE_SIZE(x))

#define LC_KC_SET_CTX(name, hashname)					       \
	_LC_KMAC_SET_CTX((&name->kmac), hashname, name,			       \
			 (sizeof(struct lc_kc_cryptor)));		       \
	_LC_KMAC_SET_CTX((&name->auth_ctx), hashname, name,		       \
			 (sizeof(struct lc_kc_cryptor) +		       \
			 LC_KMAC_STATE_SIZE(hashname)));		       \
	name->keystream = (uint8_t *)((uint8_t *)name +			       \
				      (sizeof(struct lc_kc_cryptor) +	       \
				      2 * LC_KMAC_STATE_SIZE(hashname)))

void lc_kc_crypt(struct lc_kc_cryptor *kc, const uint8_t *in, uint8_t *out,
		 size_t len);

/**
 * @brief Set the key for the encyption or decryption operation
 *
 * @param key [in] Buffer with key
 * @param keylen [in] Length of key buffer
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 */
void lc_kc_setkey(struct lc_kc_cryptor *kc,
		  const uint8_t *key, const size_t keylen);

/**
 * @brief KMAC-encrypt data
 *
 * @param hc [in] KMAC cryptor context handle
 * @param plaintext [in] Plaintext data to be encrypted
 * @param ciphertext [out] Ciphertext data buffer to be filled
 * @param datalen [in] Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 *
 * @return amount of processed bytes on success, < 0 on error
 */
static inline void
lc_kc_encrypt(struct lc_kc_cryptor *kc,
	      const uint8_t *plaintext, uint8_t *ciphertext, size_t datalen)
{
	struct lc_kmac_ctx *auth_ctx = &kc->auth_ctx;

	lc_kc_crypt(kc, plaintext, ciphertext, datalen);

	/*
	 * Calculate the authentication MAC over the ciphertext
	 * Perform an Encrypt-Then-MAC operation.
	 */
	lc_kmac_update(auth_ctx, ciphertext, datalen);
}

/**
 * @brief Obtain the authentication tag from the encryption operation
 *
 * @param hc [in] KMAC cryptor context handle
 * @param aad [in] Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param aadlen [in] Length of the AAD buffer
 * @param tag [out] Buffer to be filled with tag
 * @param taglen [in] Length of tag buffer. The full tag size hc_get_tagsize().
 *		      If the buffer is smaller, a truncated tag value is
 *		      returned.
 */
void lc_kc_encrypt_tag(struct lc_kc_cryptor *kc,
		       const uint8_t *aad, size_t aadlen,
		       uint8_t *tag, size_t taglen);

/**
 * @brief KMAC-decrypt data
 *
 * @param hc [in] KMAC cryptor context handle
 * @param ciphertext [in] Ciphertext data to be decrypted
 * @param plaintext [out] Plaintext data buffer to be filled
 * @param datalen [in] Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 *
 * @return amount of processed bytes on success, < 0 on error
 */
static inline void
lc_kc_decrypt(struct lc_kc_cryptor *kc,
	      const uint8_t *ciphertext, uint8_t *plaintext, size_t datalen)
{
	struct lc_kmac_ctx *auth_ctx = &kc->auth_ctx;

	/*
	 * Calculate the authentication tag over the ciphertext
	 * Perform the reverse of an Encrypt-Then-MAC operation.
	 */
	lc_kmac_update(auth_ctx, ciphertext, datalen);
	lc_kc_crypt(kc, ciphertext, plaintext, datalen);
}

/**
 * @brief Authenticate the decryption
 *
 * @param hc [in] KMAC cryptor context handle
 * @param aad [in] Additional authenticate data to be processed - this is data
 *		   which is not decrypted, but considered as part of the
 *		   authentication.
 * @param aadlen [in] Length of the AAD buffer
 * @param tag [in] Authentication tag generated by encryption operation
 * @param taglen [in] Length of tag buffer.
 *
 * @return 0 on successful authentication, < 0 on error
 *	  (EBADMSG means authentication error)
 */
int lc_kc_decrypt_authenticate(struct lc_kc_cryptor *kc,
			       const uint8_t *aad, size_t aadlen,
			       const uint8_t *tag, size_t taglen);

/**
 * @brief Hash-encrypt data in one call.
 *
 * @param hc [in] Hash cryptor context handle
 * @param plaintext [in] Plaintext data to be encrypted
 * @param ciphertext [out] Ciphertext data buffer to be filled
 * @param datalen [in] Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 * @param aad [in] Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param aadlen [in] Length of the AAD buffer
 * @param tag [out] Buffer to be filled with tag
 * @param taglen [in] Length of tag buffer. The full tag size hc_get_tagsize().
 *		      If the buffer is smaller, a truncated tag value is
 *		      returned.
 */
static inline void
lc_kc_encrypt_oneshot(struct lc_kc_cryptor *kc,
		      const uint8_t *plaintext, uint8_t *ciphertext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      uint8_t *tag, size_t taglen)
{
	/* Confidentiality protection: Encrypt data */
	lc_kc_encrypt(kc, plaintext, ciphertext, datalen);

	/* Integrity protection: KMAC data */
	lc_kc_encrypt_tag(kc, aad, aadlen, tag, taglen);
}

/**
 * @brief Hash-decrypt data in one call
 *
 * @param hc [in] Hash cryptor context handle
 * @param ciphertext [in] Ciphertext data to be decrypted
 * @param plaintext [out] Plaintext data buffer to be filled
 * @param datalen [in] Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 * @param aad [in] Additional authenticate data to be processed - this is data
 *		   which is not decrypted, but considered as part of the
 *		   authentication.
 * @param aadlen [in] Length of the AAD buffer
 * @param tag [in] Authentication tag generated by encryption operation
 * @param taglen [in] Length of tag buffer.
 *
 *
 * @return 0 on successful authentication, < 0 on error
 *	   (EBADMSG means authentication error)
 */
static inline int
lc_kc_decrypt_oneshot(struct lc_kc_cryptor *kc,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      const uint8_t *tag, size_t taglen)
{
	/* Confidentiality protection: Encrypt data */
	lc_kc_decrypt(kc, ciphertext, plaintext, datalen);

	/* Integrity protection: verify MAC of data */
	return lc_kc_decrypt_authenticate(kc, aad, aadlen, tag, taglen);
}

/**
 * @brief Allocate Hash cryptor context on heap
 *
 * NOTE: This is defined for lc_cshake256 as of now.
 *
 * @param hash [in] Hash implementation of type struct hash used for the HMAC
 *		    authentication
 * @param hc [out] Allocated hash cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_kc_alloc(const struct lc_hash *hash, struct lc_kc_cryptor **kc);

/**
 * @brief Hash cryptor deallocation and properly zeroization function to
 *	  frees all buffers and the cipher handle
 *
 * @param hc [in] Hash cryptor context handle
 */
void lc_kc_zero_free(struct lc_kc_cryptor *hc);

/**
 * @brief Zeroize hash cryptor context allocated with either HC_CTX_ON_STACK or
 *	  hc_alloc
 *
 * @param hc [in] Hash cryptor context to be zeroized
 */
static inline void lc_kc_zero(struct lc_kc_cryptor *kc)
{
	struct lc_kmac_ctx *kmac = &kc->kmac;
	struct lc_hash_ctx *hash_ctx = &kmac->hash_ctx;
	const struct lc_hash *hash = hash_ctx->hash;

	memset_secure((uint8_t *)kc + sizeof(struct lc_kc_cryptor), 0,
		      LC_KC_STATE_SIZE(hash));
}

/**
 * @brief Allocate stack memory for the hash cryptor context
 *
 * NOTE: This is defined for lc_cshake256 as of now.
 *
 * @param name [in] Name of the stack variable
 * @param hash [in] Hash implementation of type struct hash used for the HMAC
 *		    authentication
 */
#define LC_KC_CTX_ON_STACK(name, hash)			      		       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_KC_CTX_SIZE(hash), uint64_t);   \
	struct lc_kc_cryptor *name = (struct lc_kc_cryptor *) name ## _ctx_buf;\
	LC_KC_SET_CTX(name, hash)
	/* invocation of lc_kc_zero_free(name); not needed */

#ifdef __cplusplus
}
#endif

#endif /* LC_KMAC_CRYPT_H */
