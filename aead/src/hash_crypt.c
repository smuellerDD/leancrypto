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

#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <limits.h>
#include <stdlib.h>

#include "build_bug_on.h"
#include "lc_hash_crypt.h"
#include "math_helper.h"
#include "memcmp_secure.h"
#include "visibility.h"
#include "xor.h"

DSO_PUBLIC
int lc_hc_setkey(struct lc_hc_cryptor *hc,
		 const uint8_t *key, size_t keylen,
		 const uint8_t *iv, size_t ivlen)
{
	struct lc_rng_ctx *drbg;
	struct lc_hmac_ctx *auth_ctx;
	int ret;

	if (!hc)
		return -EINVAL;
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

DSO_PUBLIC
ssize_t lc_hc_crypt(struct lc_hc_cryptor *hc, const uint8_t *in, uint8_t *out,
		    size_t len)
{
	struct lc_rng_ctx *drbg;
	size_t processed = 0;

	if (len > SSIZE_MAX || !hc)
		return -EINVAL;

	drbg = &hc->drbg;

	while (len) {
		size_t todo = min_t(size_t, len, LC_HC_KEYSTREAM_BLOCK);

		/* Generate a new keystream block */
		if (hc->keystream_ptr >= LC_HC_KEYSTREAM_BLOCK) {
			int ret = lc_rng_generate(drbg, NULL, 0, hc->keystream,
						  LC_HC_KEYSTREAM_BLOCK);

			if (ret)
				return ret;

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
		processed += todo;
		hc->keystream_ptr += todo;
	}

	return (ssize_t)processed;
}

#define LC_SHA_MAX_SIZE_DIGEST	64

DSO_PUBLIC
ssize_t lc_hc_encrypt_tag(struct lc_hc_cryptor *hc,
			  const uint8_t *aad, size_t aadlen,
			  uint8_t *tag, size_t taglen)
{
	struct lc_hmac_ctx *auth_ctx;
	size_t digestsize;

	if (!hc)
		return -EINVAL;
	auth_ctx = &hc->auth_ctx;
	digestsize = lc_hc_get_tagsize(hc);

	/* Add the AAD data into the HMAC context */
	lc_hmac_update(auth_ctx, aad, aadlen);

	/* Generate authentication tag */
	if (taglen < digestsize) {
		uint8_t tmp[LC_SHA_MAX_SIZE_DIGEST];

		/* Guard against programming error. */
		if (sizeof(tmp) < digestsize)
			return -EFAULT;

		lc_hmac_final(auth_ctx, tmp);
		memcpy(tag, tmp, taglen);
		memset_secure(tmp, 0, sizeof(tmp));

		return (ssize_t)taglen;
	}

	lc_hmac_final(auth_ctx, tag);

	return (ssize_t)digestsize;
}

DSO_PUBLIC
ssize_t lc_hc_encrypt_oneshot(struct lc_hc_cryptor *hc,
			      const uint8_t *plaintext, uint8_t *ciphertext,
			      size_t datalen,
			      const uint8_t *aad, size_t aadlen,
			      uint8_t *tag, size_t taglen)
{
	ssize_t ret_enc, ret_tag, res;

	if (!hc)
		return -EINVAL;

	/* Confidentiality protection: Encrypt data */
	ret_enc = lc_hc_encrypt(hc, plaintext, ciphertext, datalen);
	if (ret_enc < 0)
		return ret_enc;

	/* Integrity protection: MAC data */
	ret_tag = lc_hc_encrypt_tag(hc, aad, aadlen, tag, taglen);
	if (ret_tag < 0)
		return ret_tag;

	res = ret_enc + ret_tag;

	/* Guard against overflow */
	if (res < ret_enc || res < ret_enc)
		return -EINVAL;

	return res;
}

DSO_PUBLIC
int lc_hc_decrypt_authenticate(struct lc_hc_cryptor *hc,
			       const uint8_t *aad, size_t aadlen,
			       const uint8_t *tag, size_t taglen)
{
	uint8_t calctag[LC_SHA_MAX_SIZE_DIGEST]
				__attribute__((aligned(sizeof(uint64_t))));
	int ret;

	if (!hc || taglen > sizeof(calctag))
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

DSO_PUBLIC ssize_t
lc_hc_decrypt_oneshot(struct lc_hc_cryptor *hc,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen,
		      const uint8_t *aad, size_t aadlen,
		      const uint8_t *tag, size_t taglen)
{
	ssize_t ret_dec, ret_tag;

	/*
	 * To ensure constant time between passing and failing decryption,
	 * this code first performs the decryption. The decryption results
	 * will need to be discarded if there is an authentication error. Yet,
	 * in case of an authentication error, an attacker cannot deduct
	 * that there is such an error from the timing analysis of this
	 * function.
	 */

	/* Confidentiality protection: Encrypt data */
	ret_dec = lc_hc_decrypt(hc, ciphertext, plaintext, datalen);
	if (ret_dec < 0)
		return ret_dec;

	/* Integrity protection: verify MAC of data */
	ret_tag = lc_hc_decrypt_authenticate(hc, aad, aadlen, tag, taglen);
	if (ret_tag < 0)
		return ret_tag;

	return ret_dec;
}

DSO_PUBLIC
void lc_hc_zero_free(struct lc_hc_cryptor *hc)
{
	if (!hc)
		return;

	lc_hc_zero(hc);

	free(hc);
}

DSO_PUBLIC
int lc_hc_alloc(const struct lc_hash *hash, struct lc_hc_cryptor **hc)
{
	struct lc_hc_cryptor *tmp;
	int ret = posix_memalign((void *)&tmp, sizeof(uint64_t),
				 LC_HC_CTX_SIZE(hash));

	if (ret)
		return -ret;
	memset(tmp, 0, LC_HC_CTX_SIZE(hash));

	LC_HC_SET_CTX(tmp, hash);

	*hc = tmp;

	return 0;
}
