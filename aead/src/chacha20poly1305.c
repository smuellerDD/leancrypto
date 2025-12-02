/* RFC 7539: ChaCha20 Poly1305 AEAD cipher
 *
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
#include "bitshift_le.h"
#include "build_bug_on.h"
#include "conv_be_le.h"
#include "compare.h"
#include "fips_mode.h"
#include "lc_chacha20_private.h"
#include "lc_chacha20_poly1305.h"
#include "lc_memcmp_secure.h"
#include "null_buffer.h"
#include "poly1305_internal.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

static int lc_chacha20_poly1305_setkey_nocheck(void *state, const uint8_t *key,
					       size_t keylen, const uint8_t *iv,
					       size_t ivlen);
static void lc_chacha20_poly1305_selftest(void)
{
	/* Test vector from RFC7539 */
	LC_FIPS_RODATA_SECTION
	static const uint8_t aad[] = { FIPS140_MOD(0x50),
				       0x51,
				       0x52,
				       0x53,
				       0xc0,
				       0xc1,
				       0xc2,
				       0xc3,
				       0xc4,
				       0xc5,
				       0xc6,
				       0xc7 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t in[] = {
		0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64,
		0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e,
		0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
		0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
		0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75,
		0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
		0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
		0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
		0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65,
		0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65,
		0x20, 0x69, 0x74, 0x2e
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t key[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
				       0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
				       0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
				       0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
				       0x9c, 0x9d, 0x9e, 0x9f };
	LC_FIPS_RODATA_SECTION
	static const uint8_t iv[] = { 0x40, 0x41, 0x42, 0x43,
				      0x44, 0x45, 0x46, 0x47 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_ct[] = {
		0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86,
		0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51,
		0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
		0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
		0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71,
		0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
		0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
		0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
		0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
		0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0,
		0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce,
		0xc6, 0x4b, 0x61, 0x16
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_tag[] = { 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09,
					   0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb,
					   0xd0, 0x60, 0x06, 0x91 };
	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));
	LC_FIPS_RODATA_SECTION
	static const uint8_t f[] = {
		0xde,
		0xad,
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t p[] = { 0xaf, 0xfe };
	int ret;

	LC_SELFTEST_RUN(lc_chacha20_poly1305_aead->algorithm_type);

	LC_CHACHA20_POLY1305_CTX_ON_STACK(cc20p1305);

	lc_chacha20_poly1305_setkey_nocheck(cc20p1305->aead_state, key,
					    sizeof(key), iv, sizeof(iv));
	lc_aead_encrypt(cc20p1305, in, act_ct, sizeof(in), aad, sizeof(aad),
			act_tag, sizeof(act_tag));
	unpoison(act_ct, sizeof(act_ct));
	if (lc_compare_selftest(lc_chacha20_poly1305_aead->algorithm_type,
				act_ct, exp_ct, sizeof(exp_ct),
				"ChaCha20 Poly1305 AEAD encrypt ciphertext"))
		goto out;
	if (lc_compare_selftest(lc_chacha20_poly1305_aead->algorithm_type,
				act_tag, exp_tag, sizeof(exp_tag),
				"ChaCha20 Poly1305 AEAD encrypt tag"))
		goto out;
	lc_aead_zero(cc20p1305);

	lc_chacha20_poly1305_setkey_nocheck(cc20p1305->aead_state, key,
					    sizeof(key), iv, sizeof(iv));
	ret = lc_aead_decrypt(cc20p1305, act_ct, act_ct, sizeof(act_ct), aad,
			      sizeof(aad), act_tag, sizeof(act_tag));
	if (ret) {
		if (lc_compare_selftest(
			    lc_chacha20_poly1305_aead->algorithm_type, f, p,
			    sizeof(f),
			    "ChaCha20 Poly1305 AEAD decrypt authentication"))
			goto out;
	}
	unpoison(act_ct, sizeof(act_ct));

out:
	lc_compare_selftest(lc_chacha20_poly1305_aead->algorithm_type, act_ct,
			    in, sizeof(in), "ChaCha20 Poly1305 AEAD decrypt");
	lc_aead_zero(cc20p1305);
}

static int cc20p1305_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			   size_t ivlen)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t constant[] = { 0x07, 0x00, 0x00, 0x00 };

	switch (ivlen) {
	case 8:
		ctx->counter[1] = ptr_to_le32(constant);
		ctx->counter[2] = ptr_to_le32(iv);
		ctx->counter[3] = ptr_to_le32(iv + sizeof(uint32_t));
		break;
	case 12:
		ctx->counter[1] = ptr_to_le32(iv);
		ctx->counter[2] = ptr_to_le32(iv + sizeof(uint32_t));
		ctx->counter[3] = ptr_to_le32(iv + sizeof(uint32_t) * 2);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/*
 * @brief Set the key for the encryption or decryption operation
 *
 * @param [in] state symmetric/HMAC crypt cipher handle
 * @param [in] key Buffer with key
 * @param [in] keylen Length of key buffer
 */
static int lc_chacha20_poly1305_setkey_internal(void *state, const uint8_t *key,
					       size_t keylen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;
	struct lc_sym_ctx *chacha20 = &cc20p1305->chacha20;
	struct lc_sym_state *chacha20_ctx = chacha20->sym_state;
	int ret;

	/* If no key is present, do not set anything. */
	CKNULL(key, 0);

	cc20_init_constants(chacha20_ctx);
	CKINT(lc_sym_setkey(chacha20, key, keylen));

out:
	return ret;
}

/*
 * @brief Set the IV for the encryption or decryption operation and derive the
 * Poly1305 subkey
 *
 * @param [in] state symmetric/HMAC crypt cipher handle
 * @param [in] iv initialization vector to be used - only the IV size of the
 *		  underlying symmetric algorithm is supported
 * @param [in] ivlen length of initialization vector
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 */
static int lc_chacha20_poly1305_setiv_internal(void *state, const uint8_t *iv,
					       size_t ivlen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;
	struct lc_sym_ctx *chacha20 = &cc20p1305->chacha20;
	struct lc_sym_state *chacha20_ctx = chacha20->sym_state;
	struct lc_poly1305_context *poly1305 = &cc20p1305->poly1305_ctx;
	uint32_t subkey[LC_CC20_BLOCK_SIZE_WORDS];
	int ret;

	BUILD_BUG_ON(sizeof(subkey) != 32 + 32);

	/* If no IV is present, do not set anything. */
	CKNULL(iv, 0);

	/* Derive the ChaCha20 and Poly1305 keys */
	chacha20_ctx->counter[0] = 0;
	CKINT(cc20p1305_setiv(chacha20->sym_state, iv, ivlen));
	cc20_block(chacha20->sym_state, subkey);

	/* ChaCha20 algorithm is in a state ready to use */

	/* Initialize the Poly1305 algorithm */
	lc_poly1305_init(poly1305, (uint8_t *)subkey);

	cc20p1305->aadlen = 0;
	cc20p1305->datalen = 0;

	cc20_resetkey(chacha20->sym_state);

out:
	lc_memset_secure(subkey, 0, sizeof(subkey));
	return ret;
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
 */
static int lc_chacha20_poly1305_setkey_nocheck(void *state, const uint8_t *key,
					       size_t keylen, const uint8_t *iv,
					       size_t ivlen)
{
	int ret;

	CKINT(lc_chacha20_poly1305_setkey_internal(state, key, keylen));
	CKINT(lc_chacha20_poly1305_setiv_internal(state, iv, ivlen));

out:
	return ret;
}

static int lc_chacha20_poly1305_setkey(void *state, const uint8_t *key,
				       size_t keylen, const uint8_t *iv,
				       size_t ivlen)
{
	lc_chacha20_poly1305_selftest();
	LC_SELFTEST_COMPLETED(lc_chacha20_poly1305_aead->algorithm_type);

	return lc_chacha20_poly1305_setkey_nocheck(state, key, keylen, iv,
						   ivlen);
}

static void lc_chacha20_poly1305_add_aad(void *state, const uint8_t *aad,
					 size_t aadlen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;
	struct lc_poly1305_context *poly1305 = &cc20p1305->poly1305_ctx;

	/* Add the AAD data into the Poly1305 context */
	lc_poly1305_update(poly1305, aad, aadlen);

	cc20p1305->aadlen += aadlen;
}

static inline void
lc_chacha20_poly1305_aad_pad(struct lc_chacha20_poly1305_cryptor *cc20p1305)
{
	struct lc_poly1305_context *poly1305 = &cc20p1305->poly1305_ctx;
	size_t padlen;

	if (cc20p1305->datalen || !cc20p1305->aadlen)
		return;

	/*
	 * Finish the lc_chacha20_poly1305_add_aad operation which requires the
	 * addition of the padding.
	 */
	padlen = 16 - (cc20p1305->aadlen % 16);

	lc_poly1305_update(poly1305, null_buffer, padlen);
}

static void lc_chacha20_poly1305_encrypt_tag(void *state, uint8_t *tag,
					     size_t taglen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;
	struct lc_poly1305_context *poly1305 = &cc20p1305->poly1305_ctx;
	size_t padlen = 16 - (cc20p1305->datalen % 16);
	uint8_t length[8];

	lc_poly1305_update(poly1305, null_buffer, padlen);

	le64_to_ptr(length, (uint64_t)cc20p1305->aadlen);
	lc_poly1305_update(poly1305, length, sizeof(length));

	le64_to_ptr(length, (uint64_t)cc20p1305->datalen);
	lc_poly1305_update(poly1305, length, sizeof(length));

	/* Generate authentication tag */
	if (taglen < LC_POLY1305_TAGSIZE) {
		uint8_t tmptag[LC_POLY1305_TAGSIZE];

		lc_poly1305_final(poly1305, tmptag);
		memcpy(tag, tmptag, taglen);
		unpoison(tag, taglen);
		lc_memset_secure(tmptag, 0, sizeof(tmptag));
	} else {
		lc_poly1305_final(poly1305, tag);
		unpoison(tag, LC_POLY1305_TAGSIZE);
	}
}

static int lc_chacha20_poly1305_decrypt_authenticate(void *state,
						     const uint8_t *tag,
						     size_t taglen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;
	uint8_t calctag[LC_POLY1305_TAGSIZE] __align(sizeof(uint64_t));
	int ret;

	if (taglen > sizeof(calctag))
		taglen = sizeof(calctag);

	/*
	 * Calculate the authentication tag for the processed. We do not need
	 * to check the return code as we use the maximum tag size.
	 */
	lc_chacha20_poly1305_encrypt_tag(cc20p1305, calctag, sizeof(calctag));
	ret = (lc_memcmp_secure(calctag, taglen, tag, taglen) ? -EBADMSG : 0);
	lc_memset_secure(calctag, 0, taglen);

	return ret;
}

static void lc_chacha20_poly1305_encrypt(void *state, const uint8_t *plaintext,
					 uint8_t *ciphertext, size_t datalen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;
	struct lc_poly1305_context *poly1305 = &cc20p1305->poly1305_ctx;
	struct lc_sym_ctx *chacha20 = &cc20p1305->chacha20;

	lc_chacha20_poly1305_aad_pad(cc20p1305);

	lc_sym_encrypt(chacha20, plaintext, ciphertext, datalen);
	cc20p1305->datalen += datalen;

	/*
	 * Calculate the authentication MAC over the ciphertext
	 * Perform an Encrypt-Then-MAC operation.
	 */
	lc_poly1305_update(poly1305, ciphertext, datalen);
}

static void lc_chacha20_poly1305_decrypt(void *state, const uint8_t *ciphertext,
					 uint8_t *plaintext, size_t datalen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;
	struct lc_poly1305_context *poly1305 = &cc20p1305->poly1305_ctx;
	struct lc_sym_ctx *chacha20 = &cc20p1305->chacha20;

	lc_chacha20_poly1305_aad_pad(cc20p1305);

	/*
	 * Calculate the authentication tag over the ciphertext
	 * Perform the reverse of an Encrypt-Then-MAC operation.
	 */
	lc_poly1305_update(poly1305, ciphertext, datalen);
	lc_sym_decrypt(chacha20, ciphertext, plaintext, datalen);
	cc20p1305->datalen += datalen;
}

static void
lc_chacha20_poly1305_encrypt_oneshot(void *state, const uint8_t *plaintext,
				     uint8_t *ciphertext, size_t datalen,
				     const uint8_t *aad, size_t aadlen,
				     uint8_t *tag, size_t taglen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;

	/* Insert the AAD */
	lc_chacha20_poly1305_add_aad(state, aad, aadlen);

	/* Confidentiality protection: Encrypt data */
	lc_chacha20_poly1305_encrypt(cc20p1305, plaintext, ciphertext, datalen);

	/* Integrity protection: Poly1305 tag */
	lc_chacha20_poly1305_encrypt_tag(cc20p1305, tag, taglen);
}

static int
lc_chacha20_poly1305_decrypt_oneshot(void *state, const uint8_t *ciphertext,
				     uint8_t *plaintext, size_t datalen,
				     const uint8_t *aad, size_t aadlen,
				     const uint8_t *tag, size_t taglen)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;

	/* Insert the AAD */
	lc_chacha20_poly1305_add_aad(state, aad, aadlen);

	/*
	 * To ensure constant time between passing and failing decryption,
	 * this code first performs the decryption. The decryption results
	 * will need to be discarded if there is an authentication error. Yet,
	 * in case of an authentication error, an attacker cannot deduct
	 * that there is such an error from the timing analysis of this
	 * function.
	 */
	/* Confidentiality protection: decrypt data */
	lc_chacha20_poly1305_decrypt(cc20p1305, ciphertext, plaintext, datalen);

	/* Integrity protection: verify MAC of data */
	return lc_chacha20_poly1305_decrypt_authenticate(cc20p1305, tag,
							 taglen);
}

LC_INTERFACE_FUNCTION(int, lc_chacha20_poly1305_alloc, struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_MEM_COMMON_ALIGNMENT,
			       LC_CHACHA20_POLY1305_CTX_SIZE);
	if (ret)
		return -ret;

	LC_CHACHA20_POLY1305_SET_CTX(tmp);

	*ctx = tmp;

	return 0;
}

static void lc_chacha20_poly1305_zero(void *state)
{
	struct lc_chacha20_poly1305_cryptor *cc20p1305 = state;
	struct lc_sym_ctx *chacha20 = &cc20p1305->chacha20;

	lc_sym_zero(chacha20);
	lc_memset_secure(&cc20p1305->poly1305_ctx, 0,
			 sizeof(struct lc_poly1305_context));
	cc20p1305->aadlen = 0;
	cc20p1305->datalen = 0;
}

static const struct lc_aead _lc_chacha20_poly1305_aead = {
	.setkey = lc_chacha20_poly1305_setkey,
	.encrypt = lc_chacha20_poly1305_encrypt_oneshot,
	.enc_init = lc_chacha20_poly1305_add_aad,
	.enc_update = lc_chacha20_poly1305_encrypt,
	.enc_final = lc_chacha20_poly1305_encrypt_tag,
	.decrypt = lc_chacha20_poly1305_decrypt_oneshot,
	.dec_init = lc_chacha20_poly1305_add_aad,
	.dec_update = lc_chacha20_poly1305_decrypt,
	.dec_final = lc_chacha20_poly1305_decrypt_authenticate,
	.zero = lc_chacha20_poly1305_zero,
	.algorithm_type = LC_ALG_STATUS_CHACHA20_POLY1305
};
LC_INTERFACE_SYMBOL(const struct lc_aead *,
		    lc_chacha20_poly1305_aead) = &_lc_chacha20_poly1305_aead;
