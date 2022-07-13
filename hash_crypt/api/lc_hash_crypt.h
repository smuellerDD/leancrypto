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

#ifndef LC_HASH_CRYPT_H
#define LC_HASH_CRYPT_H

/*
 * This is the hash crypt cipher operation using the Hash DRBG with SHA-512
 * core as input.
 */
#include "lc_hash_drbg_sha512.h"
#include "lc_hmac.h"
#include "memset_secure.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_hc_cryptor {
	struct lc_drbg_hash_state drbg;
	struct lc_hmac_ctx auth_ctx;
	size_t keystream_ptr;
	uint8_t *keystream;
};

/*
 * The block size of the algorithm for generating the key stream. The min DRBG
 * generate size is larger. This implies that there is no DRBG update operation
 * while the key stream for one block is generated.
 */
#define LC_HC_KEYSTREAM_BLOCK	64

#define LC_HC_STATE_SIZE(x)	(LC_DRBG_HASH_STATE_SIZE(x) +		       \
				LC_HMAC_STATE_SIZE(x) +			       \
				LC_HC_KEYSTREAM_BLOCK)
#define LC_HC_CTX_SIZE(x)	(sizeof(struct lc_hc_cryptor) +		       \
				LC_HC_STATE_SIZE(x))

#define LC_HC_SET_CTX(name, hashname)					       \
	name->keystream = (uint8_t *)((uint8_t *)name +			       \
				      (sizeof(struct lc_hc_cryptor)));	       \
	_LC_DRBG_HASH_SET_CTX((&name->drbg), name,			       \
			      (sizeof(struct lc_hc_cryptor) +		       \
			       LC_HC_KEYSTREAM_BLOCK));			       \
	_LC_HMAC_SET_CTX((&name->auth_ctx), hashname, name,		       \
			(sizeof(struct lc_hc_cryptor) + LC_HC_KEYSTREAM_BLOCK +\
			 LC_DRBG_HASH_STATE_SIZE(hashname)))

ssize_t lc_hc_crypt(struct lc_hc_cryptor *hc, const uint8_t *in, uint8_t *out,
		    size_t len);

/**
 * @brief Set the key for the encyption or decryption operation
 *
 * @param key [in] Buffer with key
 * @param keylen [in] Length of key buffer
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 *
 * @return 0 on success, < 0 on error
 */
int lc_hc_setkey(struct lc_hc_cryptor *hc,
		 const uint8_t *key, const size_t keylen);

/**
 * @brief Hash-encrypt data
 *
 * @param hc [in] Hash cryptor context handle
 * @param plaintext [in] Plaintext data to be encrypted
 * @param ciphertext [out] Ciphertext data buffer to be filled
 * @param datalen [in] Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 *
 * @return amount of processed bytes on success, < 0 on error
 */
static inline ssize_t
lc_hc_encrypt(struct lc_hc_cryptor *hc,
	      const uint8_t *plaintext, uint8_t *ciphertext, size_t datalen)
{
	struct lc_hmac_ctx *auth_ctx = &hc->auth_ctx;
	ssize_t ret = lc_hc_crypt(hc, plaintext, ciphertext, datalen);

	/*
	 * Calculate the authentication MAC over the ciphertext
	 * Perform an Encrypt-Then-MAC operation.
	 */
	if (ret >= 0)
		lc_hmac_update(auth_ctx, ciphertext, datalen);

	return ret;
}

/**
 * @brief Obtain the authentication tag from the encryption operation
 *
 * @param hc [in] Hash cryptor context handle
 * @param aad [in] Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param aadlen [in] Length of the AAD buffer
 * @param tag [out] Buffer to be filled with tag
 * @param taglen [in] Length of tag buffer. The full tag size hc_get_tagsize().
 *		      If the buffer is smaller, a truncated tag value is
 *		      returned.
 *
 * @return generated tag length, < 0 on error
 */
ssize_t lc_hc_encrypt_tag(struct lc_hc_cryptor *hc,
			  const uint8_t *aad, size_t aadlen,
			  uint8_t *tag, size_t taglen);

/**
 * @brief Hash-decrypt data
 *
 * @param hc [in] Hash cryptor context handle
 * @param ciphertext [in] Ciphertext data to be decrypted
 * @param plaintext [out] Plaintext data buffer to be filled
 * @param datalen [in] Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 *
 * @return amount of processed bytes on success, < 0 on error
 */
static inline ssize_t
lc_hc_decrypt(struct lc_hc_cryptor *hc,
	      const uint8_t *ciphertext, uint8_t *plaintext, size_t datalen)
{
	struct lc_hmac_ctx *auth_ctx = &hc->auth_ctx;

	/*
	 * Calculate the authentication tag over the ciphertext
	 * Perform the reverse of an Encrypt-Then-MAC operation.
	 */
	   lc_hmac_update(auth_ctx, ciphertext, datalen);
	return lc_hc_crypt(hc, ciphertext, plaintext, datalen);
}

/**
 * @brief Authenticate the decryption
 *
 * @param hc [in] Hash cryptor context handle
 * @param aad [in] Additional authenticate data to be processed - this is data
 *		   which is not decrypted, but considered as part of the
 *		   authentication.
 * @param aadlen [in] Length of the AAD buffer
 * @param tag [in] Authentication tag generated by encryption operation
 * @param taglen [in] Length of tag buffer.
 *
 * @return 0 on success, < 0 on error
 */
int lc_hc_decrypt_authenticate(struct lc_hc_cryptor *hc,
			       const uint8_t *aad, size_t aadlen,
			       const uint8_t *tag, size_t taglen);

/**
 * @brief Return maximum size of authentication tag
 *
 * @param hc [in] Hash cryptor context handle
 *
 * @return size of tag
 */
static inline size_t lc_hc_get_tagsize(struct lc_hc_cryptor *hc)
{
	struct lc_hmac_ctx *auth_ctx = &hc->auth_ctx;

	return lc_hmac_macsize(auth_ctx);
}

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
 *
 * @return amount of processed bytes on success, < 0 on error (-EBADMSG refers
 *	   to authentication error)
 */
ssize_t
lc_hc_encrypt_oneshot(struct lc_hc_cryptor *hc,
		      const uint8_t *plaintext, uint8_t *ciphertext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      uint8_t *tag, size_t taglen);

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
 * @return amount of processed bytes on success, < 0 on error (-EBADMSG refers
 *	   to authentication error)
 */
ssize_t
lc_hc_decrypt_oneshot(struct lc_hc_cryptor *hc,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      const uint8_t *tag, size_t taglen);

/**
 * @brief Allocate Hash cryptor context on heap
 *
 * @param hash [in] Hash implementation of type struct hash used for the HMAC
 *		    authentication
 * @param hc [out] Allocated hash cryptor context
 *
 * @return 0 on success, < 0 on error
 */
int lc_hc_alloc(const struct lc_hash *hash, struct lc_hc_cryptor **hc);

/**
 * @brief Hash cryptor deallocation and properly zeroization function to
 *	  frees all buffers and the cipher handle
 *
 * @param hc [in] Hash cryptor context handle
 */
void lc_hc_zero_free(struct lc_hc_cryptor *hc);

/**
 * @brief Zeroize hash cryptor context allocated with either HC_CTX_ON_STACK or
 *	  hc_alloc
 *
 * @param hc [in] Hash cryptor context to be zeroized
 */
static inline void lc_hc_zero(struct lc_hc_cryptor *hc)
{
	struct lc_drbg_hash_state *drbg = &hc->drbg;
	struct lc_hash_ctx *hash_ctx = &drbg->hash_ctx;
	const struct lc_hash *hash = hash_ctx->hash;

	drbg->reseed_ctr = 0;
	drbg->seeded = 0;
	memset_secure((uint8_t *)hc + sizeof(struct lc_hc_cryptor), 0,
		      LC_HC_STATE_SIZE(hash));
}

/**
 * @brief Allocate stack memory for the hash cryptor context
 *
 * @param name [in] Name of the stack variable
 * @param hash [in] Hash implementation of type struct hash used for the HMAC
 *		    authentication
 */
#define LC_HC_CTX_ON_STACK(name, hash)			      		       \
	LC_ALIGNED_BUFFER(name ## _ctx_buf, LC_HC_CTX_SIZE(hash), uint64_t);   \
	struct lc_hc_cryptor *name = (struct lc_hc_cryptor *) name ## _ctx_buf;\
	LC_HC_SET_CTX(name, hash);					       \
	lc_hc_zero(name)

#ifdef __cplusplus
}
#endif

#endif /* LC_HASH_CRYPT_H */
