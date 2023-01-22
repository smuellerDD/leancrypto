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

#include "compare.h"
#include "ext_headers.h"
#include "lc_cshake_crypt.h"
#include "lc_cshake.h"
#include "visibility.h"

static int cc_tester_cshake_one(const uint8_t *pt, size_t ptlen,
				const uint8_t *aad, size_t aadlen,
				const uint8_t *key, size_t keylen,
				const uint8_t *exp_ct,
				const uint8_t *exp_tag, size_t exp_tag_len)
{
	struct lc_aead_ctx *cc_heap = NULL;
	ssize_t ret;
	int ret_checked = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
	uint8_t out_enc[ptlen];
	uint8_t out_dec[ptlen];
	uint8_t tag[exp_tag_len];
#pragma GCC diagnostic pop
	LC_CC_CTX_ON_STACK(cc, lc_cshake256);

	/* One shot encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(cc, key, keylen, NULL, 0))
		return 1;

	lc_aead_encrypt(cc, pt, out_enc, ptlen, aad, aadlen,
			tag, exp_tag_len);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "cSHAKE crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "cSHAKE crypt: Encryption, tag");

	//bin2print(out_enc, ptlen, stderr, "out_enc");
	//bin2print(tag, exp_tag_len, stderr, "tag");

	lc_aead_zero(cc);

	/* One shot encryption with pt ptr == ct ptr */
	if (lc_cc_alloc(lc_cshake256, &cc_heap))
		return 1;

	if (lc_aead_setkey(cc_heap, key, keylen, NULL, 0)) {
		lc_aead_zero_free(cc_heap);
		return 1;
	}

	memcpy(out_enc, pt, ptlen);
	lc_aead_encrypt(cc_heap, out_enc, out_enc, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	lc_aead_zero_free(cc_heap);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "cSHAKE crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "cSHAKE crypt: Encryption, tag");

	/* Stream encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(cc, key, keylen, NULL, 0))
		return 1;

	if (ptlen < 7)
		return 1;

	lc_aead_enc_update(cc, pt, out_enc, 1);
	lc_aead_enc_update(cc, pt + 1, out_enc + 1, 1);
	lc_aead_enc_update(cc, pt + 2, out_enc + 2, 5);
	lc_aead_enc_update(cc, pt + 7, out_enc + 7, (ptlen - 7));
	lc_aead_enc_final(cc, aad, aadlen, tag, exp_tag_len);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "cSHAKE crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "cSHAKE crypt: Encryption, tag");

	lc_aead_zero(cc);

	/* One shot decryption with pt ptr != ct ptr */
	if (lc_aead_setkey(cc, key, keylen, NULL, 0))
		return 1;

	ret = lc_aead_decrypt(cc, out_enc, out_dec, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	if (ret < 0)
		return 1;

	ret_checked += compare(out_dec, pt, ptlen,
			       "cSHAKE crypt: Decryption, plaintext");

	/* Stream decryption with pt ptr != ct ptr */
	lc_aead_zero(cc);
	lc_aead_setkey(cc, key, keylen, NULL, 0);
	lc_aead_dec_update(cc, out_enc, out_dec, 1);
	lc_aead_dec_update(cc, out_enc + 1, out_dec + 1, 1);
	lc_aead_dec_update(cc, out_enc + 2, out_dec + 2, 5);
	lc_aead_dec_update(cc, out_enc + 7, out_dec + 7, (ptlen - 7));
	ret = lc_aead_dec_final(cc, aad, aadlen, tag, exp_tag_len);
	if (ret < 0)
		return 1;

	//bin2print(out_dec, sizeof(out_dec), stderr, "out_dec");
	ret_checked += compare(out_dec, pt, ptlen,
			       "cSHAKE crypt: Decryption, plaintext");

	lc_aead_zero(cc);

	/* Check authentication error */
	if (lc_aead_setkey(cc, key, keylen, NULL, 0))
		return 1;

	out_enc[0] = (uint8_t)((out_enc[0] + 1) &0xff);
	ret = lc_aead_decrypt(cc, out_enc, out_dec, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	lc_aead_zero(cc);
	if (ret != -EBADMSG)
		return 1;

	return ret_checked;
}

static int cc_tester_cshake_validate(void)
{
#define LC_CC_CUSTOMIZATION_STRING	"cSHAKE-AEAD crypt"
	static const uint8_t in[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	uint8_t out_enc[sizeof(in)];
	uint8_t out_cshake[sizeof(in) + 32];
	LC_CC_CTX_ON_STACK(cc, lc_cshake256);
	LC_CSHAKE_256_CTX_ON_STACK(cshake256);

	memset(out_enc, 0, sizeof(out_enc));
	memset(out_cshake, 0, sizeof(out_cshake));

	if (lc_aead_setkey(cc, in, sizeof(in), NULL, 0))
		return 1;
	lc_aead_encrypt(cc, in, out_enc, sizeof(in), NULL, 0, NULL, 0);

	lc_cshake_init(cshake256,
		       (uint8_t *)LC_CC_CUSTOMIZATION_STRING,
		       sizeof(LC_CC_CUSTOMIZATION_STRING) - 1,
		       in, sizeof(in));
	lc_cshake_final(cshake256, out_cshake, sizeof(out_cshake));

	return compare(out_cshake + 32, out_enc, sizeof(out_enc),
		       "cSHAKE crypt: Validation");
}

static int cc_tester_cshake(void)
{
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	};
	static const uint8_t exp_ct[] = {
		0x5d, 0x9f, 0x69, 0xff, 0xbc, 0xaf, 0x76, 0xeb,
		0x86, 0xdd, 0xaf, 0x5f, 0x37, 0x0c, 0xb8, 0xf3,
		0x4f, 0xf5, 0xf4, 0xa4, 0xbc, 0x11, 0x98, 0x11,
		0x96, 0x29, 0x14, 0x48, 0xc3, 0xfe, 0x62, 0x1f,
		0x3a, 0x0d, 0x3a, 0x62, 0xae, 0xe4, 0x74, 0x65,
		0x02, 0x31, 0x47, 0xf7, 0x36, 0xf8, 0xfd, 0x26,
		0x96, 0xf3, 0x32, 0x35, 0xb2, 0x44, 0x21, 0x1f,
		0x56, 0xb7, 0x01, 0xaa, 0x01, 0xef, 0x16, 0x09
	};
	static const uint8_t exp_tag[] = {
		0x82, 0x40, 0x81, 0x7f, 0xf9, 0xa0, 0xef, 0x9f,
		0x53, 0x29, 0x82, 0x80, 0x8b, 0xdb, 0xc1, 0x0d,
		0x52, 0x10, 0x10, 0x87, 0x7e, 0x30, 0x9c, 0x6e,
		0x49, 0xb0, 0x33, 0x8e, 0xfa, 0x7c, 0x28, 0x6d,
		0x98, 0x94, 0x30, 0xad, 0x39, 0x62, 0xfd, 0x5f,
		0xb0, 0x14, 0x6d, 0xe7, 0x36, 0x17, 0x49, 0x20,
		0x79, 0x5a, 0xc5, 0xbd, 0x6b, 0xd9, 0xbd, 0x72,
		0x0a, 0x54, 0x79, 0x67, 0x0d, 0xe3, 0xc3, 0x83
	};

	//printf("cSHAKE crypt ctx len %lu, state len %d\n",
	//       LC_CC_CTX_SIZE(lc_cshake256),
	//       LC_CC_STATE_SIZE(lc_cshake256));
	return cc_tester_cshake_one(in, sizeof(in),
				    in, sizeof(in),
				    in, sizeof(in),
				    exp_ct,
				    exp_tag, sizeof(exp_tag));
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0;

	(void)argc;
	(void)argv;
	ret += cc_tester_cshake();
	ret += cc_tester_cshake_validate();

	return ret;
}
