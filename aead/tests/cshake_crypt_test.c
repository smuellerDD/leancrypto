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

#include <errno.h>

#include "compare.h"
#include "binhexbin.h"
#include "lc_cshake_crypt.h"
#include "lc_cshake.h"

static int cc_tester_cshake_one(const uint8_t *pt, size_t ptlen,
				const uint8_t *aad, size_t aadlen,
				const uint8_t *key, size_t keylen,
				const uint8_t *exp_ct,
				const uint8_t *exp_tag, size_t exp_tag_len)
{
	LC_CC_CTX_ON_STACK(cc, lc_cshake256);
	struct lc_cc_cryptor *cc_heap = NULL;
	ssize_t ret;
	int ret_checked = 0;
	uint8_t out_enc[ptlen];
	uint8_t out_dec[ptlen];
	uint8_t tag[exp_tag_len];

	/* One shot encryption with pt ptr != ct ptr */
	lc_cc_setkey(cc, key, keylen, NULL, 0);

	lc_cc_encrypt_oneshot(cc, pt, out_enc, ptlen, aad, aadlen,
			      tag, exp_tag_len);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "cSHAKE crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "cSHAKE crypt: Encryption, tag");

	//bin2print(out_enc, ptlen, stderr, "out_enc");
	//bin2print(tag, exp_tag_len, stderr, "tag");

	lc_cc_zero(cc);

	/* One shot encryption with pt ptr == ct ptr */
	if (lc_cc_alloc(lc_cshake256, &cc_heap))
		return 1;

	lc_cc_setkey(cc_heap, key, keylen, NULL, 0);

	memcpy(out_enc, pt, ptlen);
	lc_cc_encrypt_oneshot(cc_heap, out_enc, out_enc, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	lc_cc_zero_free(cc_heap);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "cSHAKE crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "cSHAKE crypt: Encryption, tag");

	/* Stream encryption with pt ptr != ct ptr */
	lc_cc_setkey(cc, key, keylen, NULL, 0);

	if (ptlen < 7)
		return 1;

	lc_cc_encrypt(cc, pt, out_enc, 1);
	lc_cc_encrypt(cc, pt + 1, out_enc + 1, 1);
	lc_cc_encrypt(cc, pt + 2, out_enc + 2, 5);
	lc_cc_encrypt(cc, pt + 7, out_enc + 7, (ptlen - 7));
	lc_cc_encrypt_tag(cc, aad, aadlen, tag, exp_tag_len);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "cSHAKE crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "cSHAKE crypt: Encryption, tag");

	lc_cc_zero(cc);

	/* One shot decryption with pt ptr != ct ptr */
	lc_cc_setkey(cc, key, keylen, NULL, 0);

	ret = lc_cc_decrypt_oneshot(cc, out_enc, out_dec, ptlen, aad, aadlen,
				    tag, exp_tag_len);
	if (ret < 0)
		return 1;

	ret_checked += compare(out_dec, pt, ptlen,
			       "cSHAKE crypt: Decryption, plaintext");

	//bin2print(out_dec, sizeof(out_dec), stderr, "out_dec");
	ret_checked += compare(out_dec, pt, ptlen,
			       "cSHAKE crypt: Decryption, ciphertext");

	lc_cc_zero(cc);

	/* Check authentication error */
	lc_cc_setkey(cc, key, keylen, NULL, 0);

	out_enc[0] = (out_enc[0] + 1) &0xff;
	ret = lc_cc_decrypt_oneshot(cc, out_enc, out_dec, ptlen, aad, aadlen,
				    tag, exp_tag_len);
	lc_cc_zero(cc);
	if (ret != -EBADMSG)
		return 1;

	return ret_checked;
}

static int cc_tester_cshake_validate(void)
{
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

	lc_cc_setkey(cc, in, sizeof(in), NULL, 0);
	lc_cc_encrypt_oneshot(cc, in, out_enc, sizeof(in), NULL, 0, NULL, 0);

	lc_cshake_init(cshake256, in, sizeof(in), NULL, 0);
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
		0x2e, 0xa2, 0xfd, 0xd6, 0x36, 0xe1, 0x34, 0x08,
		0x86, 0xf5, 0xf2, 0xf8, 0x64, 0xbd, 0x23, 0x03,
		0x8e, 0x51, 0xc6, 0x76, 0xd4, 0x4f, 0xb2, 0x51,
		0x01, 0x46, 0x06, 0x86, 0x12, 0x57, 0x48, 0x77,
		0xce, 0x23, 0x0a, 0x88, 0x41, 0x77, 0x6f, 0x75,
		0x39, 0xce, 0x61, 0x72, 0x50, 0x90, 0xc9, 0x97,
		0x12, 0x18, 0x2d, 0x03, 0x20, 0xbf, 0xd4, 0x7e,
		0xbe, 0x5d, 0x45, 0xd0, 0x8c, 0xce, 0x32, 0x07
	};
	static const uint8_t exp_tag[] = {
		0xd9, 0x86, 0x90, 0x1d, 0x1a, 0xba, 0x57, 0x81,
		0xa3, 0x4b, 0x5e, 0x74, 0x99, 0x85, 0x8d, 0x70,
		0x6b, 0xc7, 0x89, 0x6b, 0x53, 0x0c, 0x13, 0x08,
		0x53, 0x2c, 0x4d, 0xb6, 0xb7, 0x75, 0x38, 0x42,
		0xfa, 0x90, 0x78, 0x10, 0x7c, 0xaf, 0x63, 0x66,
		0xec, 0x31, 0xb9, 0x3b, 0x3e, 0x82, 0x37, 0x70,
		0xcf, 0x39, 0x38, 0x47, 0x98, 0xe7, 0xd5, 0xad,
		0x05, 0xce, 0xb3, 0x75, 0xd0, 0xb9, 0xf3, 0x2f
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

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;
	ret = cc_tester_cshake();
	ret += cc_tester_cshake_validate();

	return ret;
}
