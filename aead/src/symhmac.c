/* AEAD cipher based on arbitrary symmetric algorithm and HMAC
 *
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "lc_hkdf.h"
#include "lc_memcmp_secure.h"
#include "lc_symhmac.h"
#include "lc_sha512.h"
#include "math_helper.h"
#include "ret_checkers.h"
#include "visibility.h"

static int lc_sh_setkey_nocheck(void *state, const uint8_t *key, size_t keylen,
				const uint8_t *iv, size_t ivlen);
static void lc_sh_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f,
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_ct[] = {
		0xf8, 0xf6, 0xf0, 0x2d, 0x2f, 0xb6, 0xee, 0x57, 0x92, 0x49,
		0xb8, 0xa2, 0xe7, 0xc1, 0xe0, 0x48, 0x6a, 0x0e, 0x0a, 0x46,
		0x24, 0x11, 0xef, 0x3b, 0x6a, 0x0b, 0xc9, 0x2a, 0xb8, 0x94,
		0xd5, 0xac, 0x3f, 0x0a, 0x22, 0x21, 0x61, 0x23, 0x81, 0x40,
		0x22, 0x3d, 0x72, 0x94, 0xe6, 0x4a, 0x05, 0x6c, 0x55, 0x9a,
		0x0d, 0x7d, 0x6c, 0x6a, 0xb3, 0x58, 0x69, 0x8d, 0xaa, 0x6c,
		0x9b, 0x53, 0xa1, 0x67
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_tag[] = {
		0xa9, 0xd1, 0x8a, 0x72, 0xed, 0xc2, 0x30, 0x26, 0xef, 0x4c,
		0x69, 0x1e, 0xf9, 0x67, 0x1b, 0x7c, 0xaf, 0x40, 0x59, 0x59,
		0x90, 0x63, 0xd5, 0x64, 0x5f, 0x19, 0x4a, 0x98, 0xf6, 0x4d,
		0x72, 0x2e, 0xf5, 0xc7, 0xcb, 0x67, 0x1d, 0x1a, 0x34, 0xf8,
		0x79, 0xd8, 0xc3, 0x36, 0x59, 0xbf, 0x9a, 0xcb, 0xb3, 0x58,
		0x62, 0xac, 0xc4, 0x83, 0x91, 0x97, 0x31, 0x19, 0x56, 0x8d,
		0x32, 0xbe, 0xf1, 0x30,
	};
	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));

	LC_SELFTEST_RUN(LC_ALG_STATUS_SYM_HMAC);

	LC_SH_CTX_ON_STACK(sh, lc_aes_cbc, lc_sha512);

	lc_sh_setkey_nocheck(sh->aead_state, key, sizeof(key), in, 16);
	lc_aead_encrypt(sh, in, act_ct, sizeof(in), in, sizeof(in), act_tag,
			sizeof(act_tag));
	if (lc_compare_selftest(LC_ALG_STATUS_SYM_HMAC, act_ct, exp_ct, sizeof(exp_ct), "Sym/HMAC AEAD encrypt"))
		goto out;
	if (lc_compare_selftest(LC_ALG_STATUS_SYM_HMAC, act_tag, exp_tag, sizeof(exp_tag), "Sym/HMAC AEAD tag"))
		goto out;
	lc_aead_zero(sh);

	lc_sh_setkey_nocheck(sh->aead_state, key, sizeof(key), in, 16);
	lc_aead_decrypt(sh, act_ct, act_ct, sizeof(act_ct), in, sizeof(in),
			act_tag, sizeof(act_tag));
	lc_compare_selftest(LC_ALG_STATUS_SYM_HMAC, act_ct, in, sizeof(in), "Sym/HMAC AEAD decrypt");

out:
	lc_aead_zero(sh);
}

/**
 * @brief Set the key for the encryption or decryption operation
 *
 * @param [in] state symmetric/HMAC crypt cipher handle
 * @param [in] key Buffer with key
 * @param [in] keylen Length of key buffer
 * @param [in] iv initialization vector to be used - only the IV size of the
 *		  underlying symmetric algorithm is supported
 * @param [in] ivlen length of initialization vector
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 *
 * @return 0 on success; < 0 on error
 */
static int lc_sh_setkey_nocheck(void *state, const uint8_t *key, size_t keylen,
				const uint8_t *iv, size_t ivlen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_sym_ctx *sym = &sh->sym;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	uint8_t keystream[(256 / 8) * 2];
	int ret;

	CKINT(lc_hkdf(lc_sha512, key, keylen, NULL, 0, NULL, 0, keystream,
		      sizeof(keystream)));

	/* Initialize the symmetric algorithm */
	CKINT(lc_sym_init(sym));
	CKINT(lc_sym_setkey(sym, keystream, sizeof(keystream) / 2));
	CKINT(lc_sym_setiv(sym, iv, ivlen));

	/* Initialize the authentication algorithm */
	CKINT(lc_hmac_init(auth_ctx, keystream + sizeof(keystream) / 2,
			   sizeof(keystream) / 2));

out:
	lc_memset_secure(keystream, 0, sizeof(keystream));
	return ret;
}

static int lc_sh_setkey(void *state, const uint8_t *key, size_t keylen,
			const uint8_t *iv, size_t ivlen)
{
	lc_sh_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SYM_HMAC);

	return lc_sh_setkey_nocheck(state, key, keylen, iv, ivlen);
}

static void lc_sh_add_aad(void *state, const uint8_t *aad, size_t aadlen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;

	/* Add the AAD data into the CSHAKE context */
	lc_hmac_update(auth_ctx, aad, aadlen);
}

static void lc_sh_encrypt_tag(void *state, uint8_t *tag, size_t taglen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	size_t maxtaglen = lc_hmac_macsize(auth_ctx);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
	uint8_t tmptag[maxtaglen];
#pragma GCC diagnostic pop

	/* Generate authentication tag */
	lc_hmac_final(auth_ctx, tmptag);

	if (taglen < maxtaglen)
		memcpy(tag, tmptag, taglen);
	else
		memcpy(tag, tmptag, maxtaglen);

	lc_memset_secure(tmptag, 0, sizeof(tmptag));
}

static int lc_sh_decrypt_authenticate(void *state, const uint8_t *tag,
				      size_t taglen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	size_t maxtaglen = lc_hmac_macsize(auth_ctx);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
	uint8_t calctag[maxtaglen] __align(sizeof(uint64_t));
#pragma GCC diagnostic pop
	int ret;

	taglen = min_size(taglen, maxtaglen);

	/*
	 * Calculate the authentication tag for the processed. We do not need
	 * to check the return code as we use the maximum tag size.
	 */
	lc_sh_encrypt_tag(sh, calctag, taglen);

	ret = (lc_memcmp_secure(calctag, taglen, tag, taglen) ? -EBADMSG : 0);
	lc_memset_secure(calctag, 0, taglen);

	return ret;
}

static void lc_sh_encrypt(void *state, const uint8_t *plaintext,
			  uint8_t *ciphertext, size_t datalen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	struct lc_sym_ctx *sym = &sh->sym;
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
	lc_hmac_update(auth_ctx, ciphertext, datalen);
}

static void lc_sh_decrypt(void *state, const uint8_t *ciphertext,
			  uint8_t *plaintext, size_t datalen)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	struct lc_sym_ctx *sym = &sh->sym;
	const struct lc_sym *sym_algo = sym->sym;
	size_t trailing_bytes = datalen % sym_algo->blocksize;

	/*
	 * Calculate the authentication tag over the ciphertext
	 * Perform the reverse of an Encrypt-Then-MAC operation.
	 */
	lc_hmac_update(auth_ctx, ciphertext, datalen);
	lc_sym_decrypt(sym, ciphertext, plaintext, datalen);

	/* Safety-measure to avoid leaking data */
	if (trailing_bytes) {
		memset(plaintext + datalen - trailing_bytes, 0, trailing_bytes);
	}
}

static void lc_sh_encrypt_oneshot(void *state, const uint8_t *plaintext,
				  uint8_t *ciphertext, size_t datalen,
				  const uint8_t *aad, size_t aadlen,
				  uint8_t *tag, size_t taglen)
{
	struct lc_sh_cryptor *sh = state;

	/* Insert the AAD */
	lc_sh_add_aad(state, aad, aadlen);

	/* Confidentiality protection: Encrypt data */
	lc_sh_encrypt(sh, plaintext, ciphertext, datalen);

	/* Integrity protection: HMAC data */
	lc_sh_encrypt_tag(sh, tag, taglen);
}

static int lc_sh_decrypt_oneshot(void *state, const uint8_t *ciphertext,
				 uint8_t *plaintext, size_t datalen,
				 const uint8_t *aad, size_t aadlen,
				 const uint8_t *tag, size_t taglen)
{
	struct lc_sh_cryptor *sh = state;

	/* Insert the AAD */
	lc_sh_add_aad(state, aad, aadlen);

	/*
	 * To ensure constant time between passing and failing decryption,
	 * this code first performs the decryption. The decryption results
	 * will need to be discarded if there is an authentication error. Yet,
	 * in case of an authentication error, an attacker cannot deduct
	 * that there is such an error from the timing analysis of this
	 * function.
	 */
	/* Confidentiality protection: decrypt data */
	lc_sh_decrypt(sh, ciphertext, plaintext, datalen);

	/* Integrity protection: verify MAC of data */
	return lc_sh_decrypt_authenticate(sh, tag, taglen);
}

LC_INTERFACE_FUNCTION(int, lc_sh_alloc, const struct lc_sym *sym,
		      const struct lc_hash *hash, struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_MEM_COMMON_ALIGNMENT,
			       LC_SH_CTX_SIZE(sym, hash));
	if (ret)
		return -ret;

	LC_SH_SET_CTX(tmp, sym, hash);

	*ctx = tmp;

	return 0;
}

static void lc_sh_zero(void *state)
{
	struct lc_sh_cryptor *sh = state;
	struct lc_hmac_ctx *auth_ctx = &sh->auth_ctx;
	struct lc_hash_ctx *hash_ctx = &auth_ctx->hash_ctx;
	struct lc_sym_ctx *sym = &sh->sym;
	const struct lc_sym *sym_algo = sym->sym;
	const struct lc_hash *hash_algo = hash_ctx->hash;

	lc_memset_secure((uint8_t *)state + sizeof(struct lc_sh_cryptor), 0,
			 LC_SH_STATE_SIZE(sym_algo, hash_algo));
}

struct lc_aead _lc_symhmac_aead = { .setkey = lc_sh_setkey,
				    .encrypt = lc_sh_encrypt_oneshot,
				    .enc_init = lc_sh_add_aad,
				    .enc_update = lc_sh_encrypt,
				    .enc_final = lc_sh_encrypt_tag,
				    .decrypt = lc_sh_decrypt_oneshot,
				    .dec_init = lc_sh_add_aad,
				    .dec_update = lc_sh_decrypt,
				    .dec_final = lc_sh_decrypt_authenticate,
				    .zero = lc_sh_zero };
LC_INTERFACE_SYMBOL(const struct lc_aead *,
		    lc_symhmac_aead) = &_lc_symhmac_aead;
