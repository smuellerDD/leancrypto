/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
#include "lc_aes.h"
#include "lc_kmac.h"
#include "lc_symkmac.h"
#include "visibility.h"

static int kh_tester_one(const struct lc_sym *sym, const struct lc_hash *hash,
			 const uint8_t *pt, size_t ptlen,
			 const uint8_t *aad, size_t aadlen,
			 const uint8_t *key, size_t keylen,
			 const uint8_t *iv, size_t ivlen,
			 const uint8_t *exp_ct,
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
	LC_KH_CTX_ON_STACK(kh, sym, hash);
	LC_KMAC_CTX_ON_STACK(kmac_ctx, hash);
	LC_SYM_CTX_ON_STACK(aes_cbc, sym);

	/* One shot encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(kh, key, keylen, iv, ivlen))
		return 1;

	lc_aead_encrypt(kh, pt, out_enc, ptlen, aad, aadlen,
			tag, exp_tag_len);

	if (exp_ct) {
		ret_checked += lc_compare(out_enc, exp_ct, ptlen,
					  "SymKMAC: Encryption, ciphertext");
	}

	if (exp_tag) {
		ret_checked += lc_compare(tag, exp_tag, exp_tag_len,
					  "SymKMAC: Encryption, tag");
	}

	//bin2print(out_enc, ptlen, stderr, "out_enc");
	//bin2print(tag, exp_tag_len, stderr, "tag");

	lc_aead_zero(kh);

	/* Compare with CBC */
	lc_kmac(lc_cshake256, key, keylen, NULL, 0, NULL, 0,
		keystream, sizeof(keystream));
	lc_sym_init(aes_cbc);
	if (lc_sym_setkey(aes_cbc, keystream, sizeof(keystream)/2))
		return 1;
	if (lc_sym_setiv(aes_cbc, iv, ivlen))
		return 1;
	lc_sym_encrypt(aes_cbc, pt, out_compare, ptlen);

	ret_checked += lc_compare(out_enc, out_compare, ptlen,
				  "SymKMAC: Encryption, compare with CBC");

	/* Compare with KMAC */
	lc_kmac_init(kmac_ctx, keystream + sizeof(keystream)/2,
		     sizeof(keystream)/2, NULL, 0);
	lc_kmac_update(kmac_ctx, out_compare, ptlen);
	lc_kmac_update(kmac_ctx, aad, aadlen);
	lc_kmac_final(kmac_ctx, tag_compare, exp_tag_len);
	ret_checked += lc_compare(tag, tag_compare, exp_tag_len,
				  "SymKMAC: Encryption, compare with HMAC");

	/* One shot encryption with pt ptr == ct ptr */
	if (lc_kh_alloc(sym, hash, &sh_heap))
		return 1;

	if (lc_aead_setkey(sh_heap, key, keylen, iv, ivlen)) {
		lc_aead_zero_free(sh_heap);
		return 1;
	}
	memcpy(out_enc, pt, ptlen);
	lc_aead_encrypt(sh_heap, out_enc, out_enc, ptlen, aad, aadlen,
			tag, exp_tag_len);

	lc_aead_zero_free(sh_heap);

	ret_checked += lc_compare(out_enc, out_compare, ptlen,
				  "SymKMAC crypt: Encryption, ciphertext");
	ret_checked += lc_compare(tag, tag_compare, exp_tag_len,
				  "SymKMAC crypt: Encryption, tag");

	/* One shot decryption with pt ptr != ct ptr */
	if (lc_aead_setkey(kh, key, keylen, iv, ivlen))
		return 1;

	ret = lc_aead_decrypt(kh, out_enc, out_dec, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	if (ret < 0)
		return 1;

	ret_checked += lc_compare(out_dec, pt, ptlen,
				  "SymHMAC crypt: Decryption, plaintext");

	lc_aead_zero(kh);

	/* Check authentication error */
	if (lc_aead_setkey(kh, key, keylen, iv, ivlen))
		return 1;

	out_enc[0] = (uint8_t)((out_enc[0] + 1) &0xff);
	ret = lc_aead_decrypt(kh, out_enc, out_dec, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	lc_aead_zero(kh);
	if (ret != -EBADMSG)
		return 1;

	return ret_checked;
}

static int kh_nonaligned(void)
{
	uint8_t pt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,};
	uint8_t ct[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,};
	uint8_t zero[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,};
	uint8_t tag[16];
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};
	int ret_checked = 0;
	LC_KH_CTX_ON_STACK(sh, lc_aes_cbc, lc_cshake256);

	/* One shot encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(sh, in, 32, in, 16))
		return 1;

	lc_aead_encrypt(sh, pt, pt, sizeof(pt), NULL, 0, tag, sizeof(tag));

	ret_checked += lc_compare(pt, zero, sizeof(pt),
				  "SymKMAC: nonaligned Encryption");

	lc_aead_decrypt(sh, ct, ct, sizeof(ct), NULL, 0, tag, sizeof(tag));

	ret_checked += lc_compare(ct, zero, sizeof(ct),
				  "SymKMAC: nonaligned Decryption");

	return ret_checked;
}

static int kh_tester(void)
{
	int ret = 0;
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
		0x36, 0xce, 0x12, 0xe8, 0xf6, 0x05, 0xfd, 0x0d,
		0x65, 0xf5, 0x63, 0x54, 0x91, 0xa9, 0xd1, 0x7a,
		0x4e, 0x13, 0x14, 0x0b, 0x3f, 0xc4, 0x2a, 0xef,
		0x53, 0x61, 0x24, 0x40, 0x14, 0x1c, 0x7c, 0xbd,
		0x84, 0xb7, 0xbf, 0x86, 0x6c, 0x99, 0xf6, 0xf4,
		0xf2, 0x5f, 0xd0, 0x1d, 0xce, 0xfe, 0x3f, 0x75,
		0x84, 0x8e, 0x3d, 0x3a, 0x05, 0x88, 0x07, 0x59,
		0xb7, 0x86, 0xf8, 0xcc, 0xca, 0xbf, 0x00, 0xf1
	};
	static const uint8_t exp_tag[] = {
		0x10, 0x90, 0x7f, 0x42, 0x48, 0xdb, 0xb7, 0xfc,
		0xd0, 0x9e, 0xfc, 0xe5, 0xd7, 0x05, 0xf8, 0xb0,
		0x7c, 0xc6, 0xd6, 0x4c, 0x25, 0xf2, 0x8c, 0xc5,
		0x8a, 0x61, 0xcf, 0x56, 0xe3, 0x5a, 0x72, 0xa3,
		0xdc, 0x4a, 0x79, 0x32, 0x0f, 0x96, 0x8e, 0xd8,
		0x76, 0x2a, 0xfe, 0xfb, 0xe0, 0xca, 0x62, 0xf0,
		0x63, 0x54, 0x7b, 0x70, 0x07, 0x7c, 0x74, 0xe0,
		0x0d, 0x2c, 0xf0, 0x2e, 0x7e, 0x21, 0xce, 0xf8
	};

	printf("SymKMAC crypt ctx len %lu, state len %lu\n",
	       LC_KH_CTX_SIZE(lc_aes_cbc, lc_cshake256),
	       LC_KH_STATE_SIZE(lc_aes_cbc, lc_cshake256));

	ret += kh_tester_one(lc_aes_cbc, lc_cshake256,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     exp_ct,
			     exp_tag, sizeof(exp_tag));

	ret += kh_tester_one(lc_aes_cbc, lc_cshake256,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 32);

	ret += kh_tester_one(lc_aes_ctr, lc_cshake256,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 32);

	ret += kh_tester_one(lc_aes_ctr, lc_cshake256,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 64);

	ret += kh_nonaligned();

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;
	ret = kh_tester();

	return ret;
}
