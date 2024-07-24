/* AEAD cipher based on arbitrary symmetric algorithm and KMAC
 *
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "compare.h"
#include "lc_aes.h"
#include "lc_kmac.h"
#include "lc_memcmp_secure.h"
#include "lc_symkmac.h"
#include "math_helper.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

static void lc_kh_selftest(int *tested, const char *impl)
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
	static const uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	};
	static const uint8_t exp_ct[] = {
		0xe1, 0xe3, 0x2f, 0x24, 0xee, 0x4c, 0x9b, 0x47, 0xa1, 0x31,
		0xb5, 0xbd, 0xc6, 0x36, 0x0f, 0x2a, 0x72, 0x6e, 0xc0, 0x43,
		0x89, 0xf7, 0x91, 0xba, 0x34, 0x87, 0xce, 0x1d, 0xe1, 0x38,
		0x91, 0x61, 0x40, 0x2a, 0x2c, 0xb7, 0xe9, 0x76, 0x80, 0xc3,
		0xc4, 0x40, 0x45, 0x16, 0x2e, 0xbd, 0xd2, 0x69, 0x15, 0x59,
		0xba, 0x9c, 0xd4, 0xae, 0x00, 0x59, 0x49, 0x27, 0x2d, 0x50,
		0xd9, 0xd8, 0x04, 0xeb
	};
	static const uint8_t exp_tag[] = {
		0xfa, 0x3c, 0xc4, 0x08, 0x17, 0xa4, 0x61, 0xfa, 0xa3, 0x78,
		0x63, 0x58, 0xef, 0x1e, 0xe0, 0x92, 0xf8, 0xf4, 0xe3, 0xfc,
		0xb6, 0xf7, 0xa1, 0xa1, 0x90, 0xc6, 0x33, 0xf0, 0x49, 0x0a,
		0x64, 0x58, 0x56, 0x51, 0x72, 0x58, 0x94, 0xf6, 0xc5, 0xb3,
		0x0d, 0x08, 0x2d, 0xc5, 0x97, 0x99, 0xd5, 0x52, 0x8a, 0x2a,
		0x9d, 0xd4, 0x0d, 0x00, 0x06, 0xcd, 0x72, 0x39, 0x8c, 0x03,
		0xb2, 0xeb, 0x6a, 0xa4
	};
	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));
	char status[25];

	LC_SELFTEST_RUN(tested);

	LC_KH_CTX_ON_STACK(sh, lc_aes_cbc, lc_cshake256);

	lc_aead_setkey(sh, key, sizeof(key), in, 16);
	lc_aead_encrypt(sh, in, act_ct, sizeof(in), in, sizeof(in), act_tag,
			sizeof(act_tag));
	snprintf(status, sizeof(status), "%s encrypt", impl);
	lc_compare_selftest(act_ct, exp_ct, sizeof(exp_ct), status);
	lc_compare_selftest(act_tag, exp_tag, sizeof(exp_tag), status);
	lc_aead_zero(sh);

	lc_aead_setkey(sh, key, sizeof(key), in, 16);
	lc_aead_decrypt(sh, act_ct, act_ct, sizeof(act_ct), in, sizeof(in),
			act_tag, sizeof(act_tag));
	snprintf(status, sizeof(status), "%s decrypt", impl);
	lc_compare_selftest(act_ct, in, sizeof(in), status);
	lc_aead_zero(sh);
}

/**
 * @brief Set the key for the encryption or decryption operation
 *
 * @param kh [in] symmetric/KMAC crypt cipher handle
 * @param key [in] Buffer with key
 * @param keylen [in] Length of key buffer
 * @param iv [in] initialization vector to be used - only the IV size of the
 *		  underlying symmetric algorithm is supported
 * @param ivlen [in] length of initialization vector
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 */
static int lc_kh_setkey(void *state, const uint8_t *key, size_t keylen,
			const uint8_t *iv, size_t ivlen)
{
	struct lc_kh_cryptor *kh = state;
	struct lc_sym_ctx *sym = &kh->sym;
	struct lc_kmac_ctx *auth_ctx = &kh->auth_ctx;
	struct lc_hash_ctx *hash_ctx = &auth_ctx->hash_ctx;
	const struct lc_hash *hash_algo = hash_ctx->hash;
	uint8_t keystream[(256 / 8) * 2];
	static int tested = 0;
	int ret;

	lc_kh_selftest(&tested, "Sym/KMAC AEAD");

	lc_kmac_xof(hash_algo, key, keylen, NULL, 0, NULL, 0, keystream,
		    sizeof(keystream));

	/* Initialize the symmetric algorithm */
	lc_sym_init(sym);
	CKINT(lc_sym_setkey(sym, keystream, sizeof(keystream) / 2));
	CKINT(lc_sym_setiv(sym, iv, ivlen));

	/* Initialize the authentication algorithm */
	lc_kmac_init(auth_ctx, keystream + sizeof(keystream) / 2,
		     sizeof(keystream) / 2, NULL, 0);

out:
	lc_memset_secure(keystream, 0, sizeof(keystream));
	return ret;
}

static void lc_kh_add_aad(void *state, const uint8_t *aad, size_t aadlen)
{
	struct lc_kh_cryptor *kh = state;
	struct lc_kmac_ctx *auth_ctx = &kh->auth_ctx;

	/* Add the AAD data into the CSHAKE context */
	lc_kmac_update(auth_ctx, aad, aadlen);
}

static void lc_kh_encrypt_tag(void *state, uint8_t *tag, size_t taglen)
{
	struct lc_kh_cryptor *kh = state;
	struct lc_kmac_ctx *auth_ctx = &kh->auth_ctx;

	/* Generate authentication tag */
	lc_kmac_final_xof(auth_ctx, tag, taglen);
}

static int lc_kh_decrypt_authenticate(void *state, const uint8_t *tag,
				      size_t taglen)
{
	struct lc_kh_cryptor *kh = state;
	uint8_t calctag[128] __align(sizeof(uint64_t));
	int ret;

	taglen = min_size(taglen, sizeof(calctag));

	/*
	 * Calculate the authentication tag for the processed. We do not need
	 * to check the return code as we use the maximum tag size.
	 */
	lc_kh_encrypt_tag(kh, calctag, taglen);

	ret = (lc_memcmp_secure(calctag, taglen, tag, taglen) ? -EBADMSG : 0);
	lc_memset_secure(calctag, 0, taglen);

	return ret;
}

static void lc_kh_encrypt(void *state, const uint8_t *plaintext,
			  uint8_t *ciphertext, size_t datalen)
{
	struct lc_kh_cryptor *kh = state;
	struct lc_kmac_ctx *auth_ctx = &kh->auth_ctx;
	struct lc_sym_ctx *sym = &kh->sym;
	const struct lc_sym *sym_algo = sym->sym;
	size_t trailing_bytes = datalen % sym_algo->blocksize;

	lc_sym_encrypt(sym, plaintext, ciphertext, datalen);

	/* Safety-measure to avoid leaking data */
	if (trailing_bytes) {
		memset(ciphertext + datalen - trailing_bytes, 0,
		       trailing_bytes);
	}

	/*
	 * Calculate the authentication MAC over the ciphertext
	 * Perform an Encrypt-Then-MAC operation.
	 */
	lc_kmac_update(auth_ctx, ciphertext, datalen);
}

static void lc_kh_decrypt(void *state, const uint8_t *ciphertext,
			  uint8_t *plaintext, size_t datalen)
{
	struct lc_kh_cryptor *kh = state;
	struct lc_kmac_ctx *auth_ctx = &kh->auth_ctx;
	struct lc_sym_ctx *sym = &kh->sym;
	const struct lc_sym *sym_algo = sym->sym;
	size_t trailing_bytes = datalen % sym_algo->blocksize;

	/*
	 * Calculate the authentication tag over the ciphertext
	 * Perform the reverse of an Encrypt-Then-MAC operation.
	 */
	lc_kmac_update(auth_ctx, ciphertext, datalen);
	lc_sym_decrypt(sym, ciphertext, plaintext, datalen);

	/* Safety-measure to avoid leaking data */
	if (trailing_bytes)
		memset(plaintext + datalen - trailing_bytes, 0, trailing_bytes);
}

static void lc_kh_encrypt_oneshot(void *state, const uint8_t *plaintext,
				  uint8_t *ciphertext, size_t datalen,
				  const uint8_t *aad, size_t aadlen,
				  uint8_t *tag, size_t taglen)
{
	struct lc_kh_cryptor *kh = state;

	/* Insert the AAD */
	lc_kh_add_aad(state, aad, aadlen);

	/* Confidentiality protection: Encrypt data */
	lc_kh_encrypt(kh, plaintext, ciphertext, datalen);

	/* Integrity protection: KMAC data */
	lc_kh_encrypt_tag(kh, tag, taglen);
}

static int lc_kh_decrypt_oneshot(void *state, const uint8_t *ciphertext,
				 uint8_t *plaintext, size_t datalen,
				 const uint8_t *aad, size_t aadlen,
				 const uint8_t *tag, size_t taglen)
{
	struct lc_kh_cryptor *kh = state;

	/* Insert the AAD */
	lc_kh_add_aad(state, aad, aadlen);

	/*
	 * To ensure constant time between passing and failing decryption,
	 * this code first performs the decryption. The decryption results
	 * will need to be discarded if there is an authentication error. Yet,
	 * in case of an authentication error, an attacker cannot deduct that
	 * there is such an error from the timing analysis of this function.
	 */
	/* Confidentiality protection: decrypt data */
	lc_kh_decrypt(kh, ciphertext, plaintext, datalen);

	/* Integrity protection: verify MAC of data */
	return lc_kh_decrypt_authenticate(kh, tag, taglen);
}

LC_INTERFACE_FUNCTION(int, lc_kh_alloc, const struct lc_sym *sym,
		      const struct lc_hash *hash, struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_MEM_COMMON_ALIGNMENT,
			       LC_KH_CTX_SIZE(sym, hash));
	if (ret)
		return -ret;

	LC_KH_SET_CTX(tmp, sym, hash);

	*ctx = tmp;

	return 0;
}

static void lc_kh_zero(void *state)
{
	struct lc_kh_cryptor *kh = state;
	struct lc_kmac_ctx *auth_ctx = &kh->auth_ctx;
	struct lc_hash_ctx *hash_ctx = &auth_ctx->hash_ctx;
	struct lc_sym_ctx *sym = &kh->sym;
	const struct lc_sym *sym_algo = sym->sym;
	const struct lc_hash *hash_algo = hash_ctx->hash;

	lc_memset_secure((uint8_t *)state + sizeof(struct lc_kh_cryptor), 0,
			 LC_KH_STATE_SIZE(sym_algo, hash_algo));
}

struct lc_aead _lc_symkmac_aead = { .setkey = lc_kh_setkey,
				    .encrypt = lc_kh_encrypt_oneshot,
				    .enc_init = lc_kh_add_aad,
				    .enc_update = lc_kh_encrypt,
				    .enc_final = lc_kh_encrypt_tag,
				    .decrypt = lc_kh_decrypt_oneshot,
				    .dec_init = lc_kh_add_aad,
				    .dec_update = lc_kh_decrypt,
				    .dec_final = lc_kh_decrypt_authenticate,
				    .zero = lc_kh_zero };
LC_INTERFACE_SYMBOL(const struct lc_aead *,
		    lc_symkmac_aead) = &_lc_symkmac_aead;
