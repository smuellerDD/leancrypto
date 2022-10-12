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
#include "lc_aes.h"
#include "lc_hkdf.h"
#include "lc_hmac.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "lc_symhmac.h"

static int sh_tester_one(const struct lc_sym *sym, const struct lc_hash *hash,
			 const uint8_t *pt, size_t ptlen,
			 const uint8_t *aad, size_t aadlen,
			 const uint8_t *key, size_t keylen,
			 const uint8_t *iv, size_t ivlen,
			 const uint8_t *exp_ct,
			 const uint8_t *exp_tag, size_t exp_tag_len)
{
	LC_SH_CTX_ON_STACK(sh, sym, hash);
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);
	LC_SYM_CTX_ON_STACK(aes_cbc, sym);
	struct lc_aead_ctx *sh_heap = NULL;
	ssize_t ret;
	int ret_checked = 0;
	uint8_t out_enc[ptlen];
	uint8_t out_dec[ptlen];
	uint8_t out_compare[ptlen];
	uint8_t tag[exp_tag_len];
	uint8_t tag_compare[64];
	uint8_t keystream[(256 / 8) * 2];

	/* One shot encryption with pt ptr != ct ptr */
	if (lc_aead_setkey(sh, key, keylen, iv, ivlen))
		return 1;

	lc_aead_encrypt(sh, pt, out_enc, ptlen, aad, aadlen,
			tag, exp_tag_len);

	if (exp_ct) {
		ret_checked += compare(out_enc, exp_ct, ptlen,
				       "SymHMAC: Encryption, ciphertext");
	}

	if (exp_tag) {
		ret_checked += compare(tag, exp_tag, exp_tag_len,
				       "SymHMAC: Encryption, tag");
	}

	//bin2print(out_enc, ptlen, stderr, "out_enc");
	//bin2print(tag, exp_tag_len, stderr, "tag");

	lc_aead_zero(sh);

	/* Compare with CBC */
	if (lc_hkdf(lc_sha512, key, keylen, NULL, 0, NULL, 0,
		    keystream, sizeof(keystream)))
		return 1;
	lc_sym_init(aes_cbc);
	if (lc_sym_setkey(aes_cbc, keystream, sizeof(keystream)/2))
		return 1;
	if (lc_sym_setiv(aes_cbc, iv, ivlen))
		return 1;
	lc_sym_encrypt(aes_cbc, pt, out_compare, ptlen);

	ret_checked += compare(out_enc, out_compare, ptlen,
			       "SymHMAC: Encryption, compare with CBC");

	/* Compare with HMAC */
	lc_hmac_init(hmac_ctx, keystream + sizeof(keystream)/2,
		     sizeof(keystream)/2);
	lc_hmac_update(hmac_ctx, out_compare, ptlen);
	lc_hmac_update(hmac_ctx, aad, aadlen);
	lc_hmac_final(hmac_ctx, tag_compare);
	ret_checked += compare(tag, tag_compare, exp_tag_len,
			       "SymHMAC: Encryption, compare with HMAC");

	/* One shot encryption with pt ptr == ct ptr */
	if (lc_sh_alloc(sym, hash, &sh_heap))
		return 1;

	if (lc_aead_setkey(sh_heap, key, keylen, iv, ivlen)) {
		lc_aead_zero_free(sh_heap);
		return 1;
	}
	memcpy(out_enc, pt, ptlen);
	lc_aead_encrypt(sh_heap, out_enc, out_enc, ptlen, aad, aadlen,
			tag, exp_tag_len);

	lc_aead_zero_free(sh_heap);

	ret_checked += compare(out_enc, out_compare, ptlen,
			       "SymHMAC crypt: Encryption, ciphertext");
	ret_checked += compare(tag, tag_compare, exp_tag_len,
			       "SymHMAC crypt: Encryption, tag");

	/* One shot decryption with pt ptr != ct ptr */
	if (lc_aead_setkey(sh, key, keylen, iv, ivlen))
		return 1;

	ret = lc_aead_decrypt(sh, out_enc, out_dec, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	if (ret < 0)
		return 1;

	ret_checked += compare(out_dec, pt, ptlen,
			       "SymHMAC crypt: Decryption, plaintext");

	lc_aead_zero(sh);

	/* Check authentication error */
	if (lc_aead_setkey(sh, key, keylen, iv, ivlen))
		return 1;

	out_enc[0] = (out_enc[0] + 1) &0xff;
	ret = lc_aead_decrypt(sh, out_enc, out_dec, ptlen, aad, aadlen,
			      tag, exp_tag_len);
	lc_aead_zero(sh);
	if (ret != -EBADMSG)
		return 1;

	return ret_checked;
}

static int sh_tester(void)
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
		0xf8, 0xf6, 0xf0, 0x2d, 0x2f, 0xb6, 0xee, 0x57,
		0x92, 0x49, 0xb8, 0xa2, 0xe7, 0xc1, 0xe0, 0x48,
		0x6a, 0x0e, 0x0a, 0x46, 0x24, 0x11, 0xef, 0x3b,
		0x6a, 0x0b, 0xc9, 0x2a, 0xb8, 0x94, 0xd5, 0xac,
		0x3f, 0x0a, 0x22, 0x21, 0x61, 0x23, 0x81, 0x40,
		0x22, 0x3d, 0x72, 0x94, 0xe6, 0x4a, 0x05, 0x6c,
		0x55, 0x9a, 0x0d, 0x7d, 0x6c, 0x6a, 0xb3, 0x58,
		0x69, 0x8d, 0xaa, 0x6c, 0x9b, 0x53, 0xa1, 0x67
	};
	static const uint8_t exp_tag[] = {
		0x99, 0xf7, 0x17, 0x92, 0x78, 0x5f, 0xb6, 0xb3,
		0xc5, 0xb4, 0x8d, 0xb6, 0xc6, 0xb3, 0x27, 0xf0,
		0x0c, 0xd1, 0x8d, 0x21, 0x30, 0x76, 0x8a, 0x7d,
		0x68, 0x20, 0xf5, 0x60, 0x0b, 0xbe, 0x89, 0xce,
		0x1f, 0x64, 0xb4, 0x31, 0x26, 0x73, 0x98, 0xb5,
		0x28, 0xf6, 0x53, 0xce, 0x4e, 0x45, 0x12, 0xaa,
		0x34, 0xe0, 0xe5, 0x98, 0x24, 0x9b, 0x6a, 0xcb,
		0xff, 0xdb, 0x87, 0xbc, 0xe9, 0x40, 0xce, 0xea
	};

	printf("SymHMAC crypt ctx len %lu, state len %d\n",
	       LC_SH_CTX_SIZE(lc_aes_cbc, lc_sha512),
	       LC_SH_STATE_SIZE(lc_aes_cbc, lc_sha512));

	ret += sh_tester_one(lc_aes_cbc, lc_sha512,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     exp_ct,
			     exp_tag, sizeof(exp_tag));

	ret += sh_tester_one(lc_aes_cbc, lc_sha256,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 32);

	ret += sh_tester_one(lc_aes_ctr, lc_sha256,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 32);

	ret += sh_tester_one(lc_aes_ctr, lc_sha512,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 64);

	ret += sh_tester_one(lc_aes_ctr, lc_sha3_256,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 32);

	ret += sh_tester_one(lc_aes_ctr, lc_sha3_512,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 64);

	ret += sh_tester_one(lc_aes_cbc, lc_sha3_256,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 32);

	ret += sh_tester_one(lc_aes_cbc, lc_sha3_512,
			     in, sizeof(in),
			     in, sizeof(in),
			     in, sizeof(in),
			     in, 16,
			     NULL,
			     NULL, 64);

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;
	ret = sh_tester();

	return ret;
}
