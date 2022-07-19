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
#include "lc_kmac_crypt.h"
#include "lc_cshake.h"

static int kc_tester_kmac_one(const uint8_t *pt, size_t ptlen,
			      const uint8_t *aad, size_t aadlen,
			      const uint8_t *key, size_t keylen,
			      const uint8_t *exp_ct,
			      const uint8_t *exp_tag, size_t exp_tag_len)
{
	LC_KC_CTX_ON_STACK(kc, lc_cshake256);
	struct lc_kc_cryptor *kc_heap = NULL;
	ssize_t ret;
	int ret_checked = 0;
	uint8_t out_enc[ptlen];
	uint8_t out_dec[ptlen];
	uint8_t tag[exp_tag_len];

	/* One shot encryption with pt ptr != ct ptr */
	lc_kc_setkey(kc, key, keylen, NULL, 0);

	lc_kc_encrypt_oneshot(kc, pt, out_enc, ptlen, aad, aadlen,
			      tag, exp_tag_len);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "KMAC crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "KMAC crypt: Encryption, tag");

	//bin2print(out_enc, ptlen, stderr, "out_enc");
	//bin2print(tag, exp_tag_len, stderr, "tag");

	lc_kc_zero(kc);

	/* One shot encryption with pt ptr == ct ptr */
	if (lc_kc_alloc(lc_cshake256, &kc_heap))
		return 1;

	lc_kc_setkey(kc_heap, key, keylen, NULL, 0);

	memcpy(out_enc, pt, ptlen);
	lc_kc_encrypt_oneshot(kc_heap, out_enc, out_enc, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	lc_kc_zero_free(kc_heap);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "KMAC crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "KMAC crypt: Encryption, tag");

	/* Stream encryption with pt ptr != ct ptr */
	lc_kc_setkey(kc, key, keylen, NULL, 0);

	if (ptlen < 7)
		return 1;

	lc_kc_encrypt(kc, pt, out_enc, 1);
	lc_kc_encrypt(kc, pt + 1, out_enc + 1, 1);
	lc_kc_encrypt(kc, pt + 2, out_enc + 2, 5);
	lc_kc_encrypt(kc, pt + 7, out_enc + 7, (ptlen - 7));
	lc_kc_encrypt_tag(kc, aad, aadlen, tag, exp_tag_len);

	ret_checked += compare(out_enc, exp_ct, ptlen,
			       "KMAC crypt: Encryption, ciphertext");
	ret_checked += compare(tag, exp_tag, exp_tag_len,
			       "KMAC crypt: Encryption, tag");

	lc_kc_zero(kc);

	/* One shot decryption with pt ptr != ct ptr */
	lc_kc_setkey(kc, key, keylen, NULL, 0);

	ret = lc_kc_decrypt_oneshot(kc, out_enc, out_dec, ptlen, aad, aadlen,
				    tag, exp_tag_len);
	if (ret < 0)
		return 1;

	ret_checked += compare(out_dec, pt, ptlen,
			       "KMAC crypt: Decryption, plaintext");

	//bin2print(out_dec, sizeof(out_dec), stderr, "out_dec");
	ret_checked += compare(out_dec, pt, ptlen,
			       "KMAC crypt: Decryption, ciphertext");

	lc_kc_zero(kc);

	/* Check authentication error */
	lc_kc_setkey(kc, key, keylen, NULL, 0);

	out_enc[0] = (out_enc[0] + 1) &0xff;
	ret = lc_kc_decrypt_oneshot(kc, out_enc, out_dec, ptlen, aad, aadlen,
				    tag, exp_tag_len);
	lc_kc_zero(kc);
	if (ret != -EBADMSG)
		return 1;

	return ret_checked;
}

static int kc_tester_kmac(void)
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
		0x95, 0x35, 0x0c, 0x0a, 0xa3, 0xdd, 0x48, 0x27,
		0x4f, 0xde, 0xf5, 0x20, 0x89, 0xbd, 0x6c, 0x7f,
		0x12, 0x6e, 0x94, 0xb7, 0x8f, 0xe4, 0xce, 0xd0,
		0xd3, 0x83, 0xf0, 0xad, 0x11, 0xa2, 0x4f, 0xac,
		0xbf, 0xfa, 0x5e, 0x03, 0x2f, 0xb8, 0x71, 0xb0,
		0x91, 0xb5, 0xe1, 0x6f, 0xb5, 0x0f, 0x88, 0x1c,
		0x30, 0x9d, 0x68, 0xa8, 0x19, 0xec, 0xea, 0x2b,
		0xaf, 0xa2, 0x9a, 0xff, 0x3b, 0xb9, 0x63, 0xa5
	};
	static const uint8_t exp_tag[] = {
		0xe7, 0x11, 0xbf, 0x2e, 0xd8, 0x1e, 0x2c, 0x0d,
		0x0f, 0x9a, 0x02, 0xc9, 0xee, 0xbf, 0x11, 0x38,
		0xf7, 0x9b, 0x71, 0xf7, 0x78, 0x0a, 0x72, 0x42,
		0x1c, 0x84, 0x45, 0xe3, 0x42, 0xfc, 0xe7, 0xa7,
		0x4d, 0x2c, 0x36, 0x28, 0x04, 0x61, 0xaa, 0x76,
		0xab, 0x38, 0x4c, 0x4b, 0xeb, 0xb9, 0xa2, 0xe6,
		0x0e, 0xd3, 0x99, 0xb4, 0xc8, 0x34, 0x7e, 0x0f,
		0xbb, 0xf9, 0xc1, 0x89, 0x11, 0x4d, 0x3e, 0xbd
	};

	//printf("KMAC crypt ctx len %lu, state len %d\n",
	//       LC_KC_CTX_SIZE(lc_cshake256),
	//       LC_KC_STATE_SIZE(lc_cshake256));
	return kc_tester_kmac_one(in, sizeof(in),
				  in, sizeof(in),
				  in, sizeof(in),
				  exp_ct,
				  exp_tag, sizeof(exp_tag));
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kc_tester_kmac();
}
