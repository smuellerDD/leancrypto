/* Symmetric stream AEAD cipher based on hashes
 *
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

#include "alignment.h"
#include "build_bug_on.h"
#include "compare.h"
#include "lc_hash_crypt.h"
#include "lc_memcmp_secure.h"
#include "math_helper.h"
#include "visibility.h"
#include "xor.h"

static void lc_hc_selftest(int *tested, const char *impl)
{
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	};
	static const uint8_t exp_ct[] = {
		0x5d, 0xe0, 0xac, 0xbc, 0xca, 0x5e, 0xb7, 0x7c, 0x8b, 0x4e,
		0xf0, 0x3a, 0xcc, 0x46, 0xe1, 0x8b, 0x9e, 0x8c, 0x12, 0x8e,
		0xd0, 0xbe, 0x61, 0xd7, 0xe7, 0xeb, 0x55, 0x5b, 0x1c, 0x96,
		0xbe, 0xd5, 0xe4, 0x2e, 0x4f, 0xd4, 0x42, 0x9d, 0xa0, 0x73,
		0x63, 0x0f, 0x05, 0x5b, 0x90, 0x21, 0x89, 0xb7, 0x1b, 0x97,
		0xde, 0x93, 0x38, 0x41, 0x17, 0xe9, 0xc7, 0x52, 0xb5, 0x84,
		0x1c, 0x71, 0x01, 0x0c
	};
	static const uint8_t exp_tag[] = {
		0x2b, 0x2c, 0x91, 0x5a, 0x2a, 0xf0, 0xe5, 0xee, 0xbb, 0xf3,
		0x0b, 0x13, 0x9e, 0x67, 0x2c, 0xd4, 0x80, 0x3e, 0x8a, 0xd0,
		0x63, 0x50, 0xb7, 0x66, 0xb2, 0x79, 0xd3, 0xaf, 0xd5, 0x54,
		0x32, 0x9f, 0xe1, 0xdb, 0x97, 0xc8, 0x9e, 0x7f, 0x65, 0xab,
		0xaa, 0xb0, 0xe7, 0xae, 0x3f, 0x79, 0x2b, 0xea, 0x11, 0x4a,
		0x69, 0x35, 0x89, 0x8a, 0xfa, 0xac, 0x7b, 0xbc, 0xf0, 0x25,
		0x1d, 0x2d, 0x80, 0xfa
	};
	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));
	char status[25];

	LC_SELFTEST_RUN(tested);

	LC_HC_CTX_ON_STACK(hc, lc_sha512);

	lc_aead_setkey(hc, in, sizeof(in), NULL, 0);
	lc_aead_encrypt(hc, in, act_ct, sizeof(in), in, sizeof(in), act_tag,
			sizeof(act_tag));
	snprintf(status, sizeof(status), "%s encrypt", impl);
	lc_compare_selftest(act_ct, exp_ct, sizeof(exp_ct), status);
	lc_aead_zero(hc);

	lc_aead_setkey(hc, in, sizeof(in), NULL, 0);
	lc_aead_decrypt(hc, act_ct, act_ct, sizeof(act_ct), in, sizeof(in),
			act_tag, sizeof(act_tag));
	snprintf(status, sizeof(status), "%s decrypt", impl);
	lc_compare_selftest(act_ct, in, sizeof(in), status);
	lc_aead_zero(hc);
}

static int lc_hc_setkey(void *state, const uint8_t *key, size_t keylen,
			const uint8_t *iv, size_t ivlen)
{
	struct lc_hc_cryptor *hc = state;
	struct lc_rng_ctx *drbg = &hc->drbg;
	struct lc_hmac_ctx *auth_ctx = &hc->auth_ctx;
	static int tested = 0;
	int ret;

	lc_hc_selftest(&tested, "Hash AEAD");

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

static void lc_hc_crypt(struct lc_hc_cryptor *hc, const uint8_t *in,
			uint8_t *out, size_t len)
{
	struct lc_rng_ctx *drbg;

	drbg = &hc->drbg;

	while (len) {
		size_t todo = min_size(len, LC_HC_KEYSTREAM_BLOCK);

		/* Generate a new keystream block */
		if (hc->keystream_ptr >= LC_HC_KEYSTREAM_BLOCK) {
			int ret = lc_rng_generate(drbg, NULL, 0, hc->keystream,
						  LC_HC_KEYSTREAM_BLOCK);

			if (ret)
				return;

			hc->keystream_ptr = 0;
		}

		todo = min_size(todo,
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

#define LC_SHA_MAX_SIZE_DIGEST 64

static void lc_hc_encrypt_tag(void *state, const uint8_t *aad, size_t aadlen,
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
		lc_memset_secure(tmp, 0, sizeof(tmp));
	} else {
		lc_hmac_final(auth_ctx, tag);
	}
}

static void lc_hc_encrypt(void *state, const uint8_t *plaintext,
			  uint8_t *ciphertext, size_t datalen)
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

static void lc_hc_decrypt(void *state, const uint8_t *ciphertext,
			  uint8_t *plaintext, size_t datalen)
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

static void lc_hc_encrypt_oneshot(void *state, const uint8_t *plaintext,
				  uint8_t *ciphertext, size_t datalen,
				  const uint8_t *aad, size_t aadlen,
				  uint8_t *tag, size_t taglen)
{
	struct lc_hc_cryptor *hc = state;

	/* Confidentiality protection: Encrypt data */
	lc_hc_encrypt(hc, plaintext, ciphertext, datalen);

	/* Integrity protection: MAC data */
	lc_hc_encrypt_tag(hc, aad, aadlen, tag, taglen);
}

static int lc_hc_decrypt_authenticate(void *state, const uint8_t *aad,
				      size_t aadlen, const uint8_t *tag,
				      size_t taglen)
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
	ret = (lc_memcmp_secure(calctag, taglen, tag, taglen) ? -EBADMSG : 0);
	lc_memset_secure(calctag, 0, taglen);

	return ret;
}

static int lc_hc_decrypt_oneshot(void *state, const uint8_t *ciphertext,
				 uint8_t *plaintext, size_t datalen,
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
	lc_memset_secure((uint8_t *)hc + sizeof(struct lc_hc_cryptor), 0,
			 LC_HMAC_STATE_SIZE(hash));
}

LC_INTERFACE_FUNCTION(int, lc_hc_alloc, const struct lc_hash *hash,
		      struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	int ret = lc_alloc_aligned((void **)&tmp, LC_MEM_COMMON_ALIGNMENT,
				   LC_HC_CTX_SIZE(hash));

	if (ret)
		return -ret;
	memset(tmp, 0, LC_HC_CTX_SIZE(hash));

	LC_HC_SET_CTX(tmp, hash);

	*ctx = tmp;

	return 0;
}

struct lc_aead _lc_hash_aead = { .setkey = lc_hc_setkey,
				 .encrypt = lc_hc_encrypt_oneshot,
				 .enc_update = lc_hc_encrypt,
				 .enc_final = lc_hc_encrypt_tag,
				 .decrypt = lc_hc_decrypt_oneshot,
				 .dec_update = lc_hc_decrypt,
				 .dec_final = lc_hc_decrypt_authenticate,
				 .zero = lc_hc_zero };

LC_INTERFACE_SYMBOL(const struct lc_aead *, lc_hash_aead) = &_lc_hash_aead;
