/*
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

#include "compare.h"
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "lc_hkdf.h"
#include "lc_hmac.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "lc_symhmac.h"
#include "test_helper_common.h"
#include "visibility.h"

static int sh_tester_one(const struct lc_sym *sym, const struct lc_hash *hash,
			 const uint8_t *pt, size_t ptlen, const uint8_t *aad,
			 size_t aadlen, const uint8_t *key, size_t keylen,
			 const uint8_t *iv, size_t ivlen, const uint8_t *exp_ct,
			 const uint8_t *exp_tag, size_t exp_tag_len)
{
	struct lc_aead_ctx *sh_heap = NULL;
	ssize_t ret;
	int ret_checked = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
	uint8_t out_enc[ptlen];
	uint8_t out_dec[ptlen];
	uint8_t out_compare[ptlen];
	uint8_t tag[exp_tag_len];
#pragma GCC diagnostic pop
	uint8_t tag_compare[64];
	uint8_t keystream[(256 / 8) * 2];
	LC_SH_CTX_ON_STACK(sh, sym, hash);
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);
	LC_SYM_CTX_ON_STACK(aes_cbc, sym);

	/* One shot encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(sh, key, keylen, iv, ivlen))
		return 1;

	lc_aead_encrypt(sh, pt, out_enc, ptlen, aad, aadlen, tag, exp_tag_len);

	if (exp_ct) {
		ret_checked += lc_compare(out_enc, exp_ct, ptlen,
					  "SymHMAC: Encryption, ciphertext");
	}

	if (exp_tag) {
		ret_checked += lc_compare(tag, exp_tag, exp_tag_len,
					  "SymHMAC: Encryption, tag");
	}

	//bin2print(out_enc, ptlen, stderr, "out_enc");
	//bin2print(tag, exp_tag_len, stderr, "tag");

	lc_aead_zero(sh);

	/* Compare with CBC */
	if (lc_hkdf(lc_sha512, key, keylen, NULL, 0, NULL, 0, keystream,
		    sizeof(keystream)))
		return 1;
	if (lc_sym_init(aes_cbc))
		return 1;
	if (lc_sym_setkey(aes_cbc, keystream, sizeof(keystream) / 2))
		return 1;
	if (lc_sym_setiv(aes_cbc, iv, ivlen))
		return 1;
	lc_sym_encrypt(aes_cbc, pt, out_compare, ptlen);

	ret_checked += lc_compare(out_enc, out_compare, ptlen,
				  "SymHMAC: Encryption, compare with CBC");

	/* Compare with HMAC */
	if (lc_hmac_init(hmac_ctx, keystream + sizeof(keystream) / 2,
			 sizeof(keystream) / 2))
		return 1;
	lc_hmac_update(hmac_ctx, aad, aadlen);
	lc_hmac_update(hmac_ctx, out_compare, ptlen);
	lc_hmac_final(hmac_ctx, tag_compare);
	ret_checked += lc_compare(tag, tag_compare, exp_tag_len,
				  "SymHMAC: Encryption, compare with HMAC");

	/* One shot encryption with pt ptr == ct ptr */
	if (lc_sh_alloc(sym, hash, &sh_heap))
		return 1;

	if (lc_aead_setkey(sh_heap, key, keylen, iv, ivlen)) {
		lc_aead_zero_free(sh_heap);
		return 1;
	}
	memcpy(out_enc, pt, ptlen);
	lc_aead_encrypt(sh_heap, out_enc, out_enc, ptlen, aad, aadlen, tag,
			exp_tag_len);

	lc_aead_zero_free(sh_heap);

	ret_checked += lc_compare(out_enc, out_compare, ptlen,
				  "SymHMAC crypt: Encryption, ciphertext");
	ret_checked += lc_compare(tag, tag_compare, exp_tag_len,
				  "SymHMAC crypt: Encryption, tag");

	/* One shot decryption with pt ptr != ct ptr */
	if (lc_aead_setkey(sh, key, keylen, iv, ivlen))
		return 1;

	ret = lc_aead_decrypt(sh, out_enc, out_dec, ptlen, aad, aadlen, tag,
			      exp_tag_len);
	if (ret < 0)
		return 1;

	ret_checked += lc_compare(out_dec, pt, ptlen,
				  "SymHMAC crypt: Decryption, plaintext");

	lc_aead_zero(sh);

	/* Check authentication error */
	if (lc_aead_setkey(sh, key, keylen, iv, ivlen))
		return 1;

	out_enc[0] = (uint8_t)((out_enc[0] + 1) & 0xff);
	ret = lc_aead_decrypt(sh, out_enc, out_dec, ptlen, aad, aadlen, tag,
			      exp_tag_len);
	lc_aead_zero(sh);
	if (ret != -EBADMSG)
		return 1;

	return ret_checked;
}

static int sh_nonaligned(void)
{
	uint8_t pt[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	};
	uint8_t ct[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	};
	uint8_t zero[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	uint8_t tag[16];
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	static const uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	int ret_checked = 0;
	LC_SH_CTX_ON_STACK(sh, lc_aes_cbc, lc_sha512);

	/* One shot encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(sh, key, 32, in, 16))
		return 1;

	lc_aead_encrypt(sh, pt, pt, sizeof(pt), NULL, 0, tag, sizeof(tag));

	ret_checked += lc_compare(pt, zero, sizeof(pt),
				  "SymHMAC: nonaligned Encryption");

	lc_aead_decrypt(sh, ct, ct, sizeof(ct), NULL, 0, tag, sizeof(tag));

	ret_checked += lc_compare(ct, zero, sizeof(ct),
				  "SymHMAC: nonaligned Decryption");

	return ret_checked;
}

static int sh_tester(void)
{
	int ret = 0;
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
		0xf8, 0xf6, 0xf0, 0x2d, 0x2f, 0xb6, 0xee, 0x57, 0x92, 0x49,
		0xb8, 0xa2, 0xe7, 0xc1, 0xe0, 0x48, 0x6a, 0x0e, 0x0a, 0x46,
		0x24, 0x11, 0xef, 0x3b, 0x6a, 0x0b, 0xc9, 0x2a, 0xb8, 0x94,
		0xd5, 0xac, 0x3f, 0x0a, 0x22, 0x21, 0x61, 0x23, 0x81, 0x40,
		0x22, 0x3d, 0x72, 0x94, 0xe6, 0x4a, 0x05, 0x6c, 0x55, 0x9a,
		0x0d, 0x7d, 0x6c, 0x6a, 0xb3, 0x58, 0x69, 0x8d, 0xaa, 0x6c,
		0x9b, 0x53, 0xa1, 0x67
	};
	static const uint8_t exp_tag[] = {
		0xa9, 0xd1, 0x8a, 0x72, 0xed, 0xc2, 0x30, 0x26, 0xef, 0x4c,
		0x69, 0x1e, 0xf9, 0x67, 0x1b, 0x7c, 0xaf, 0x40, 0x59, 0x59,
		0x90, 0x63, 0xd5, 0x64, 0x5f, 0x19, 0x4a, 0x98, 0xf6, 0x4d,
		0x72, 0x2e, 0xf5, 0xc7, 0xcb, 0x67, 0x1d, 0x1a, 0x34, 0xf8,
		0x79, 0xd8, 0xc3, 0x36, 0x59, 0xbf, 0x9a, 0xcb, 0xb3, 0x58,
		0x62, 0xac, 0xc4, 0x83, 0x91, 0x97, 0x31, 0x19, 0x56, 0x8d,
		0x32, 0xbe, 0xf1, 0x30
	};

	printf("SymHMAC crypt ctx len %u, state len %u\n",
	       (unsigned int)LC_SH_CTX_SIZE(lc_aes_cbc),
	       (unsigned int)LC_SH_STATE_SIZE(lc_aes_cbc));

	ret += sh_tester_one(lc_aes_cbc, lc_sha512, in, sizeof(in), in,
			     sizeof(in), key, sizeof(key), in, 16, exp_ct,
			     exp_tag, sizeof(exp_tag));

	ret += sh_tester_one(lc_aes_cbc, lc_sha256, in, sizeof(in), in,
			     sizeof(in), key, sizeof(key), in, 16, NULL, NULL,
			     32);

	ret += sh_tester_one(lc_aes_ctr, lc_sha256, in, sizeof(in), in,
			     sizeof(in), key, sizeof(key), in, 16, NULL, NULL,
			     32);

	ret += sh_tester_one(lc_aes_ctr, lc_sha512, in, sizeof(in), in,
			     sizeof(in), key, sizeof(key), in, 16, NULL, NULL,
			     64);

	ret += sh_tester_one(lc_aes_ctr, lc_sha3_256, in, sizeof(in), in,
			     sizeof(in), key, sizeof(key), in, 16, NULL, NULL,
			     32);

	ret += sh_tester_one(lc_aes_ctr, lc_sha3_512, in, sizeof(in), in,
			     sizeof(in), key, sizeof(key), in, 16, NULL, NULL,
			     64);

	ret += sh_tester_one(lc_aes_cbc, lc_sha3_256, in, sizeof(in), in,
			     sizeof(in), key, sizeof(key), in, 16, NULL, NULL,
			     32);

	ret += sh_tester_one(lc_aes_cbc, lc_sha3_512, in, sizeof(in), in,
			     sizeof(in), key, sizeof(key), in, 16, NULL, NULL,
			     64);

	ret += sh_nonaligned();

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = sh_tester();

	ret = test_validate_status(ret, LC_ALG_STATUS_SYM_HMAC, 1);
	ret = test_validate_status(ret, LC_ALG_STATUS_HMAC, 1);
	ret = test_validate_status(ret, LC_ALG_STATUS_SHA256, 1);
	ret = test_validate_status(ret, LC_ALG_STATUS_HKDF, 1);
#ifndef LC_FIPS140_DEBUG
	ret = test_validate_status(ret, LC_ALG_STATUS_AES_CBC, 1);
	ret = test_validate_status(ret, LC_ALG_STATUS_SHA512, 1);
	ret = test_validate_status(ret, LC_ALG_STATUS_SHA3, 1);
#endif
	ret += test_print_status();

	return ret;
}
