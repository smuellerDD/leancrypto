/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "lc_hash_crypt.h"
#include "lc_sha512.h"
#include "visibility.h"

static int hc_tester_sha512_one(const uint8_t *pt, size_t ptlen,
				const uint8_t *aad, size_t aadlen,
				const uint8_t *key, size_t keylen,
				const uint8_t *exp_ct, const uint8_t *exp_tag,
				size_t exp_tag_len)
{
	struct lc_aead_ctx *hc_heap = NULL;
	ssize_t ret;
	int ret_checked = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
	uint8_t out_enc[ptlen];
	uint8_t out_dec[ptlen];
	uint8_t tag[exp_tag_len];
#pragma GCC diagnostic pop
	LC_HC_CTX_ON_STACK(hc, lc_sha512);

	/* One shot encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(hc, key, keylen, NULL, 0) < 0)
		return 1;

	lc_aead_encrypt(hc, pt, out_enc, ptlen, aad, aadlen, tag, exp_tag_len);

	ret_checked += lc_compare(out_enc, exp_ct, ptlen,
				  "Hash crypt: Encryption, ciphertext");
	ret_checked += lc_compare(tag, exp_tag, exp_tag_len,
				  "Hash crypt: Encryption, tag");

	//bin2print(out_enc, ptlen, stderr, "out_enc");
	//bin2print(tag, exp_tag_len, stderr, "tag");

	lc_aead_zero(hc);

	/* One shot encryption with pt ptr == ct ptr */
	if (lc_hc_alloc(lc_sha512, &hc_heap))
		return 1;

	if (lc_aead_setkey(hc_heap, key, keylen, NULL, 0) < 0) {
		lc_aead_zero_free(hc_heap);
		return 1;
	}

	memcpy(out_enc, pt, ptlen);
	lc_aead_encrypt(hc_heap, out_enc, out_enc, ptlen, aad, aadlen, tag,
			exp_tag_len);
	lc_aead_zero_free(hc_heap);

	ret_checked += lc_compare(out_enc, exp_ct, ptlen,
				  "Hash crypt: Encryption, ciphertext");
	ret_checked += lc_compare(tag, exp_tag, exp_tag_len,
				  "Hash crypt: Encryption, tag");

	lc_aead_zero(hc);

	/* Stream encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(hc, key, keylen, NULL, 0) < 0)
		return 1;

	if (ptlen < 7)
		return 1;

	lc_aead_enc_init(hc, aad, aadlen);
	lc_aead_enc_update(hc, pt, out_enc, 1);
	lc_aead_enc_update(hc, pt + 1, out_enc + 1, 1);
	lc_aead_enc_update(hc, pt + 2, out_enc + 2, 5);
	lc_aead_enc_update(hc, pt + 7, out_enc + 7, (ptlen - 7));
	lc_aead_enc_final(hc, tag, exp_tag_len);

	ret_checked += lc_compare(out_enc, exp_ct, ptlen,
				  "Hash crypt: Encryption, ciphertext");
	ret_checked += lc_compare(tag, exp_tag, exp_tag_len,
				  "Hash crypt: Encryption, tag");

	lc_aead_zero(hc);

	/* One shot decryption with pt ptr != ct ptr */
	if (lc_aead_setkey(hc, key, keylen, NULL, 0) < 0)
		return 1;

	ret = lc_aead_decrypt(hc, out_enc, out_dec, ptlen, aad, aadlen, tag,
			      exp_tag_len);
	if (ret < 0)
		return 1;

	ret_checked += lc_compare(out_dec, pt, ptlen,
				  "Hash crypt: Decryption, plaintext");

	//bin2print(out_dec, sizeof(out_dec), stderr, "out_dec");
	ret_checked += lc_compare(out_dec, pt, ptlen,
				  "Hash crypt: Decryption, ciphertext");

	lc_aead_zero(hc);

	/* Check authentication error */
	if (lc_aead_setkey(hc, key, keylen, NULL, 0) < 0)
		return 1;

	out_enc[0] = (uint8_t)((out_enc[0] + 1) & 0xff);
	ret = lc_aead_decrypt(hc, out_enc, out_dec, ptlen, aad, aadlen, tag,
			      exp_tag_len);
	if (ret != -EBADMSG)
		return 1;

	return ret_checked;
}

static int hc_tester_sha512(void)
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
		0xdf, 0xcd, 0x29, 0x7a, 0x28, 0x82, 0x78, 0xfa, 0xfe, 0x14,
		0x36, 0x36, 0xae, 0x60, 0x4b, 0xcb, 0xac, 0x89, 0x92, 0xa7,
		0x0e, 0xa8, 0x53, 0xbe, 0x00, 0x02, 0x92, 0x22, 0x20, 0x65,
		0x77, 0x0e, 0xe9, 0xb4, 0x94, 0x74, 0xdb, 0xab, 0xaa, 0x53,
		0xdc, 0xff, 0x2f, 0x59, 0x1a, 0xc9, 0x38, 0xb1, 0xad, 0x33,
		0x27, 0x69, 0x77, 0x48, 0xcd, 0xbd, 0x88, 0x72, 0xbe, 0xe0,
		0x7c, 0xca, 0x3e, 0xb8
	};

	printf("hash crypt ctx len %" PRIu64 "\n", LC_HC_CTX_SIZE(lc_sha512));
	return hc_tester_sha512_one(in, sizeof(in), in, sizeof(in), in,
				    sizeof(in), exp_ct, exp_tag,
				    sizeof(exp_tag));
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return hc_tester_sha512();
}
