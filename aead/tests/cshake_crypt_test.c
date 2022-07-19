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
		0x6a, 0x66, 0x8a, 0xae, 0x61, 0x7a, 0xdc, 0xba,
		0x04, 0x4d, 0x1d, 0x64, 0x64, 0x3d, 0xe2, 0xfa,
		0x92, 0x1a, 0x35, 0x1d, 0x7b, 0xc0, 0x81, 0xcd,
		0x50, 0x6f, 0x04, 0x2b, 0x97, 0x43, 0x08, 0xb7,
		0xda, 0xcc, 0x77, 0x77, 0xa9, 0xd1, 0xa5, 0x69,
		0xb2, 0xc4, 0xe4, 0xf4, 0xfc, 0x7b, 0x64, 0x3e,
		0x4b, 0xb4, 0x44, 0xbf, 0xdd, 0xf0, 0xe2, 0xac,
		0xc2, 0xea, 0xd3, 0xf4, 0xa0, 0x4e, 0xf1, 0xc6
	};
	static const uint8_t exp_tag[] = {
		0x24, 0x17, 0x60, 0xd7, 0xf0, 0x07, 0xaa, 0xdf,
		0xdf, 0x7d, 0xc9, 0xcd, 0xdf, 0x81, 0xc5, 0xba,
		0xf9, 0xcd, 0x9d, 0x59, 0x42, 0x2d, 0x91, 0x13,
		0x32, 0xb7, 0xca, 0x8a, 0x22, 0xa7, 0x82, 0x1c,
		0x76, 0x9c, 0x29, 0xac, 0x2d, 0x71, 0xac, 0x42,
		0xa9, 0x26, 0x7f, 0x44, 0xdc, 0x1c, 0x20, 0x74,
		0x81, 0x8f, 0x7b, 0xeb, 0x8b, 0x32, 0xcd, 0x33,
		0xed, 0x4a, 0xca, 0x21, 0x2e, 0xdb, 0x31, 0x9f
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
	(void)argc;
	(void)argv;
	return cc_tester_cshake();
}
