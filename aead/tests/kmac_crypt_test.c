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
#include "lc_kmac.h"

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

static int kc_tester_kmac_validate(void)
{
	static const uint8_t in[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	};
	uint8_t out_enc[sizeof(in)];
	uint8_t out_kmac[sizeof(in) + 32];
	LC_KC_CTX_ON_STACK(kc, lc_cshake256);
	LC_KMAC_CTX_ON_STACK(kmac256, lc_cshake256);

	lc_kc_setkey(kc, in, sizeof(in), NULL, 0);
	lc_kc_encrypt_oneshot(kc, in, out_enc, sizeof(in), NULL, 0, NULL, 0);

	lc_kmac_init(kmac256, in, sizeof(in), NULL, 0);
	lc_kmac_final_xof(kmac256, out_kmac, sizeof(out_kmac));

	return compare(out_kmac + 32, out_enc, sizeof(out_enc),
		       "KMAC crypt: Validation");
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
		0x32, 0x26, 0x28, 0x44, 0xf4, 0x08, 0x27, 0x4a,
		0x75, 0xf9, 0x84, 0xbb, 0x4f, 0x31, 0x67, 0x81,
		0x38, 0xc6, 0x41, 0xe5, 0x04, 0x26, 0x01, 0xda,
		0xdb, 0x6c, 0x0b, 0xe4, 0x9c, 0xc1, 0x63, 0x46,
		0x1c, 0xf2, 0x31, 0x30, 0xb8, 0x27, 0xf2, 0x53,
		0x39, 0x49, 0x99, 0x98, 0x61, 0x9b, 0x70, 0xf0,
		0xfe, 0x1e, 0x7a, 0x57, 0x5c, 0x1f, 0xaf, 0xa1,
		0x3a, 0x6b, 0x18, 0x1a, 0x44, 0x99, 0xda, 0x28
	};
	static const uint8_t exp_tag[] = {
		0x8b, 0x4a, 0x42, 0x87, 0x97, 0xff, 0x1a, 0x14,
		0x3a, 0x98, 0x40, 0x5e, 0x60, 0x7f, 0x6c, 0x18,
		0xdb, 0xb3, 0xd3, 0xa4, 0x33, 0x2f, 0x3f, 0x25,
		0x3c, 0x1f, 0x7a, 0x20, 0xea, 0xa9, 0x06, 0x25,
		0x72, 0x11, 0xe8, 0xe1, 0xbe, 0x57, 0x76, 0x64,
		0xc5, 0x1b, 0x83, 0x87, 0x3a, 0x0f, 0x1e, 0xa4,
		0x0a, 0x8b, 0x46, 0xbf, 0x29, 0xcc, 0x51, 0x3a,
		0x04, 0xf2, 0x8d, 0x56, 0x91, 0xad, 0x45, 0x13
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
	int ret;
	(void)argc;
	(void)argv;

	ret = kc_tester_kmac();
	ret += kc_tester_kmac_validate();
	return ret;
}
