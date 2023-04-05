/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_AEAD_H
#define LC_AEAD_H

#include "lc_memory_support.h"

#ifdef __cplusplus
extern "C"
{
#endif

struct lc_aead {
	int (*setkey)(void *state,
		      const uint8_t *key, const size_t keylen,
		      const uint8_t *iv, size_t ivlen);
	void (*encrypt)(void *state,
		        const uint8_t *plaintext, uint8_t *ciphertext,
		        size_t datalen,
		        const uint8_t *aad, size_t aadlen,
		        uint8_t *tag, size_t taglen);
	void (*enc_update)(void *state,
			   const uint8_t *plaintext, uint8_t *ciphertext,
			   size_t datalen);
	void (*enc_final)(void *state,
			  const uint8_t *aad, size_t aadlen,
			  uint8_t *tag, size_t taglen);
	int (*decrypt)(void *state,
		       const uint8_t *ciphertext, uint8_t *plaintext,
		       size_t datalen,
		       const uint8_t *aad, size_t aadlen,
		       const uint8_t *tag, size_t taglen);
	void(*dec_update)(void *state,
			 const uint8_t *ciphertext, uint8_t *plaintext,
			 size_t datalen);
	int(*dec_final)(void *state,
			const uint8_t *aad, size_t aadlen,
			const uint8_t *tag, size_t taglen);
	void (*zero)(void *state);
};

struct lc_aead_ctx {
	const struct lc_aead *aead;
	void *aead_state;
};

#define LC_AEAD_CTX(name, cb)						       \
	name->aead = cb;						       \
	name->aead_state = (uint8_t *)(name) + sizeof(struct lc_aead_ctx)

/**
 * Concept of AEAD algorithms in leancrypto
 *
 * All RNGs can be used with the API calls documented below. However,
 * the allocation part is AEAD-algorhtm-specific. Thus, perform the following
 * steps
 *
 * 1. Allocation: Use the stack or heap allocation functions documented in
 *    lc_cshake_crypt.h, lc_kmac_crypt.h, lc_hash_crypt.h.
 *
 * 2. Use the returned cipher handle with the API calls below.
 */

/**
 * @brief Zeroize AEAD context
 *
 * @param [in] ctx AEAD context to be zeroized
 */
static inline void lc_aead_zero(struct lc_aead_ctx *ctx)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return;

	aead->zero(aead_state);
}

/**
 * @brief Zeroize and free AEAD context
 *
 * @param [in] ctx AEAD context to be zeroized and freed
 */
static inline void lc_aead_zero_free(struct lc_aead_ctx *ctx)
{
	if (!ctx)
		return;

	lc_aead_zero(ctx);
	lc_free(ctx);
}

/**
 * @brief Set the key for the AEAD encyption or decryption operation
 *
 * @param [in] ctx AEAD context handle
 * @param [in] key Buffer with key
 * @param [in] keylen Length of key buffer
 * @param [in] iv initialization vector to be used
 * @param [in] ivlen length of initialization vector
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 *
 * @return 0 upon success; < 0 on error
 */
static inline int
lc_aead_setkey(struct lc_aead_ctx *ctx,
	       const uint8_t *key, const size_t keylen,
	       const uint8_t *iv, size_t ivlen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return -EINVAL;

	return aead->setkey(aead_state, key, keylen, iv, ivlen);
}

/**
 * @brief AEAD-encrypt data
 *
 * @param [in] ctx AEAD context handle with key set / IV
 * @param [in] plaintext Plaintext data to be encrypted
 * @param [out] ciphertext Ciphertext data buffer to be filled
 * @param [in] datalen Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [out] tag Buffer to be filled with tag
 * @param [in] taglen Length of tag buffer. The full tag size hc_get_tagsize().
 *		      If the buffer is smaller, a truncated tag value is
 *		      returned.
 */
static inline void
lc_aead_encrypt(struct lc_aead_ctx *ctx,
		const uint8_t *plaintext, uint8_t *ciphertext,
		size_t datalen,
		const uint8_t *aad, size_t aadlen,
		uint8_t *tag, size_t taglen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return;

	aead->encrypt(aead_state, plaintext, ciphertext, datalen,
		      aad, aadlen, tag, taglen);
}

/**
 * @brief AEAD-encrypt data - send partial data
 *
 * NOTE: This operation can be invoked multiple times and must be completed
 * with a call to lc_aead_enc_final.
 *
 * @param [in] ctx AEAD context handle with key set / IV
 * @param [in] plaintext Plaintext data to be encrypted
 * @param [out] ciphertext Ciphertext data buffer to be filled
 * @param [in] datalen Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 *
 * @return amount of processed bytes on success, < 0 on error
 */
static inline void
lc_aead_enc_update(struct lc_aead_ctx *ctx,
		   const uint8_t *plaintext, uint8_t *ciphertext,
		   size_t datalen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return;

	aead->enc_update(aead_state, plaintext, ciphertext, datalen);
}

/**
 * @brief Complete AEAD encryption - Obtain the authentication tag from the
 *	  encryption operation
 *
 * @param [in] ctx AEAD context handle with key set / IV
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not encrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [out] tag Buffer to be filled with tag
 * @param [in] taglen Length of tag buffer. The full tag size hc_get_tagsize().
 *		      If the buffer is smaller, a truncated tag value is
 *		      returned.
 */
static inline void
lc_aead_enc_final(struct lc_aead_ctx *ctx,
		  const uint8_t *aad, size_t aadlen,
		  uint8_t *tag, size_t taglen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return;

	aead->enc_final(aead_state, aad, aadlen, tag, taglen);
}

/**
 * @brief AEAD-decrypt data in one call
 *
 * @param [in] ctx AEAD context handle with key set / IV
 * @param [in] ciphertext Ciphertext data to be decrypted
 * @param [out] plaintext Plaintext data buffer to be filled
 * @param [in] datalen Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not decrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [in] tag Authentication tag generated by encryption operation
 * @param [in] taglen Length of tag buffer.
 *
 *
 * @return 0 on successful authentication, < 0 on error
 *	   (-EBADMSG means authentication error)
 */
static inline int
lc_aead_decrypt(struct lc_aead_ctx *ctx,
		const uint8_t *ciphertext, uint8_t *plaintext,
		size_t datalen,
		const uint8_t *aad, size_t aadlen,
		const uint8_t *tag, size_t taglen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return -EINVAL;

	return aead->decrypt(aead_state, ciphertext, plaintext, datalen,
			     aad, aadlen, tag, taglen);
}

/**
 * @brief AEAD-decrypt data - send partial data
 *
 * NOTE: This operation can be invoked multiple times and must be completed
 * with a call to lc_aead_dec_final.
 *
 * @param [in] ctx AEAD context handle with key set / IV
 * @param [in] ciphertext Ciphertext data to be decrypted
 * @param [out] plaintext Plaintext data buffer to be filled
 * @param [in] datalen Length of the plaintext and ciphertext data buffers
 *		       NOTE: the encryption operation is symmetric and
 *			     generates as much output as input.
 */
static inline void
lc_aead_dec_update(struct lc_aead_ctx *ctx,
		   const uint8_t *ciphertext, uint8_t *plaintext,
		   size_t datalen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return;

	aead->dec_update(aead_state, ciphertext, plaintext, datalen);
}

/**
 * @brief AEAD-decrypt data - Perform authentication
 *
 * @param [in] ctx AEAD context handle with key set / IV
 * @param [in] aad Additional authenticate data to be processed - this is data
 *		   which is not decrypted, but considered as part of the
 *		   authentication.
 * @param [in] aadlen Length of the AAD buffer
 * @param [in] tag Authentication tag generated by encryption operation
 * @param [in] taglen Length of tag buffer.
 *
 *
 * @return 0 on successful authentication, < 0 on error
 *	   (-EBADMSG means authentication error)
 */
static inline int
lc_aead_dec_final(struct lc_aead_ctx *ctx,
		  const uint8_t *aad, size_t aadlen,
		  const uint8_t *tag, size_t taglen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return -EINVAL;

	return aead->dec_final(aead_state, aad, aadlen, tag, taglen);
}

#ifdef __cplusplus
}
#endif

#endif /* LC_AEAD_H */
