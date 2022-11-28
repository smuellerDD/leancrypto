/* Symmetric stream AEAD cipher based on hashes
 *
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

#include "alignment.h"
#include "build_bug_on.h"
#include "lc_hash_crypt.h"
#include "math_helper.h"
#include "memcmp_secure.h"
#include "memory_support.h"
#include "visibility.h"
#include "xor.h"

static int
lc_hc_setkey(void *state,
	     const uint8_t *key, size_t keylen,
	     const uint8_t *iv, size_t ivlen)
{
	struct lc_hc_cryptor *hc = state;
	struct lc_rng_ctx *drbg;
	struct lc_hmac_ctx *auth_ctx;
	int ret;

	drbg = &hc->drbg;
	auth_ctx = &hc->auth_ctx;

	BUILD_BUG_ON(LC_SHA_MAX_SIZE_DIGEST > LC_HC_KEYSTREAM_BLOCK);

	if (!key || !keylen)
		return -EINVAL;

	ret = lc_rng_seed(drbg, key, keylen, iv, ivlen);
	if (ret)
		return ret;

	/*
	 * Generate key for HMAC authentication - we simply use two different
	 * keys for the DRBG keystream generator and the HMAC authenticator.
	 */
	ret = lc_rng_generate(drbg, NULL, 0, hc->keystream,
			      LC_SHA_MAX_SIZE_DIGEST);
	if (ret)
		return ret;

	lc_hmac_init(auth_ctx, hc->keystream, LC_SHA_MAX_SIZE_DIGEST);

	/* Generate first keystream */
	ret = lc_rng_generate(drbg, NULL, 0, hc->keystream,
			      LC_HC_KEYSTREAM_BLOCK);
	if (ret)
		return ret;

	hc->keystream_ptr = 0;

	return 0;
}

static void
lc_hc_crypt(struct lc_hc_cryptor *hc, const uint8_t *in, uint8_t *out,
	    size_t len)
{
	struct lc_rng_ctx *drbg;

	if (len > SSIZE_MAX)
		return;

	drbg = &hc->drbg;

	while (len) {
		size_t todo = min_t(size_t, len, LC_HC_KEYSTREAM_BLOCK);

		/* Generate a new keystream block */
		if (hc->keystream_ptr >= LC_HC_KEYSTREAM_BLOCK) {
			int ret = lc_rng_generate(drbg, NULL, 0, hc->keystream,
						  LC_HC_KEYSTREAM_BLOCK);

			if (ret)
				return;

			hc->keystream_ptr = 0;
		}

		todo = min_t(size_t, todo,
			     LC_HC_KEYSTREAM_BLOCK - hc->keystream_ptr);

		if (in != out)
			memcpy(out, in, todo);

		/* Perform the encryption operation */
		xor_64(out, hc->keystream + hc->keystream_ptr, todo);

		len -= todo;
		in += todo;
		out += todo;
		hc->keystream_ptr += todo;
	}
}

#define LC_SHA_MAX_SIZE_DIGEST	64

static void
lc_hc_encrypt_tag(void *state,
		  const uint8_t *aad, size_t aadlen,
		  uint8_t *tag, size_t taglen)
{
	struct lc_hc_cryptor *hc = state;
	struct lc_hmac_ctx *auth_ctx;
	size_t digestsize;

	auth_ctx = &hc->auth_ctx;
	digestsize = lc_hc_get_tagsize(hc);
	/* Guard against programming error. */
	if (LC_SHA_MAX_SIZE_DIGEST < digestsize)
		return;

	/* Add the AAD data into the HMAC context */
	lc_hmac_update(auth_ctx, aad, aadlen);

	/* Generate authentication tag */
	if (taglen < digestsize) {
		uint8_t tmp[LC_SHA_MAX_SIZE_DIGEST];

		lc_hmac_final(auth_ctx, tmp);
		memcpy(tag, tmp, taglen);
		memset_secure(tmp, 0, sizeof(tmp));
	} else {
		lc_hmac_final(auth_ctx, tag);
	}
}

static void
lc_hc_encrypt(void *state,
	      const uint8_t *plaintext, uint8_t *ciphertext, size_t datalen)
{
	struct lc_hc_cryptor *hc = state;
	struct lc_hmac_ctx *auth_ctx = &hc->auth_ctx;

	lc_hc_crypt(hc, plaintext, ciphertext, datalen);

	/*
	 * Calculate the authentication MAC over the ciphertext
	 * Perform an Encrypt-Then-MAC operation.
	 */
	lc_hmac_update(auth_ctx, ciphertext, datalen);
}

static void
lc_hc_decrypt(void *state,
	      const uint8_t *ciphertext, uint8_t *plaintext, size_t datalen)
{
	struct lc_hc_cryptor *hc = state;
	struct lc_hmac_ctx *auth_ctx = &hc->auth_ctx;

	/*
	 * Calculate the authentication tag over the ciphertext
	 * Perform the reverse of an Encrypt-Then-MAC operation.
	 */
	lc_hmac_update(auth_ctx, ciphertext, datalen);
	lc_hc_crypt(hc, ciphertext, plaintext, datalen);
}

static void
lc_hc_encrypt_oneshot(void *state,
		      const uint8_t *plaintext, uint8_t *ciphertext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      uint8_t *tag, size_t taglen)
{
	struct lc_hc_cryptor *hc = state;

	/* Confidentiality protection: Encrypt data */
	lc_hc_encrypt(hc, plaintext, ciphertext, datalen);

	/* Integrity protection: MAC data */
	lc_hc_encrypt_tag(hc, aad, aadlen, tag, taglen);
}

static  int
lc_hc_decrypt_authenticate(void *state,
			   const uint8_t *aad, size_t aadlen,
			   const uint8_t *tag, size_t taglen)
{
	struct lc_hc_cryptor *hc = state;
	uint8_t calctag[LC_SHA_MAX_SIZE_DIGEST] __align(sizeof(uint64_t));
	int ret;

	if (taglen > sizeof(calctag))
		return -EINVAL;

	/*
	 * Calculate the authentication tag for the processed. We do not need
	 * to check the return code as we use the maximum tag size.
	 */
	lc_hc_encrypt_tag(hc, aad, aadlen, calctag, taglen);
	ret = (memcmp_secure(calctag, taglen, tag, taglen) ? -EBADMSG : 0);
	memset_secure(calctag, 0, taglen);

	return ret;
}

static int
lc_hc_decrypt_oneshot(void *state,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      const uint8_t *tag, size_t taglen)
{
	struct lc_hc_cryptor *hc = state;

	/*
	 * To ensure constant time between passing and failing decryption,
	 * this code first performs the decryption. The decryption results
	 * will need to be discarded if there is an authentication error. Yet,
	 * in case of an authentication error, an attacker cannot deduct
	 * that there is such an error from the timing analysis of this
	 * function.
	 */

	/* Confidentiality protection: decrypt data */
	lc_hc_decrypt(hc, ciphertext, plaintext, datalen);

	/* Integrity protection: verify MAC of data */
	return lc_hc_decrypt_authenticate(hc, aad, aadlen, tag, taglen);
}

static void lc_hc_zero(void *state)
{
	struct lc_hc_cryptor *hc = state;
	struct lc_rng_ctx *drbg = &hc->drbg;
	struct lc_hmac_ctx *hmac_ctx = &hc->auth_ctx;
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	const struct lc_hash *hash = hash_ctx->hash;

	lc_rng_zero(drbg);
	hc->keystream_ptr = 0;
	memset(hc->keystream, 0, sizeof(hc->keystream));
	memset_secure((uint8_t *)hc + sizeof(struct lc_hc_cryptor), 0,
		      LC_HMAC_STATE_SIZE(hash));
}

LC_INTERFACE_FUNCTION(
int, lc_hc_alloc, const struct lc_hash *hash, struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	int ret = lc_alloc_aligned((void *)&tmp, LC_HASH_COMMON_ALIGNMENT,
				   LC_HC_CTX_SIZE(hash));

	if (ret)
		return -ret;
	memset(tmp, 0, LC_HC_CTX_SIZE(hash));

	LC_HC_SET_CTX(tmp, hash);

	*ctx = tmp;

	return 0;
}

struct lc_aead _lc_hash_aead = {
	.setkey		= lc_hc_setkey,
	.encrypt	= lc_hc_encrypt_oneshot,
	.enc_update	= lc_hc_encrypt,
	.enc_final	= lc_hc_encrypt_tag,
	.decrypt	= lc_hc_decrypt_oneshot,
	.dec_update	= lc_hc_decrypt,
	.dec_final	= lc_hc_decrypt_authenticate,
	.zero		= lc_hc_zero
};

LC_INTERFACE_SYMBOL(const struct lc_aead *, lc_hash_aead) = &_lc_hash_aead;
