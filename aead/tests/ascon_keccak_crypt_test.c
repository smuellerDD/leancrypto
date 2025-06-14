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
#include "ext_headers.h"
#include "lc_ascon_keccak.h"
#include "visibility.h"

#include "sha3_c.h"
#include "sha3_arm_asm.h"
#include "sha3_arm_ce.h"
#include "sha3_arm_neon.h"
#include "sha3_avx2.h"
#include "sha3_avx512.h"
#include "sha3_riscv_asm.h"

#define LC_EXEC_ONE_TEST_512(sha3_impl)                                        \
	if (sha3_impl) {                                                       \
		ret += ak_tester_512(sha3_impl, #sha3_impl);                   \
		ret += ak_tester_512_large_iv_tag(sha3_impl, #sha3_impl);      \
	}

#define LC_EXEC_ONE_TEST_256(sha3_impl)                                        \
	if (sha3_impl) {                                                       \
		ret += ak_tester_256(sha3_impl, #sha3_impl);                   \
		ret += ak_tester_256_large_iv_tag(sha3_impl, #sha3_impl);      \
	}

static int ak_tester_one(const struct lc_hash *hash, const uint8_t *pt,
			 size_t ptlen, const uint8_t *iv, size_t ivlen,
			 const uint8_t *aad, size_t aadlen, const uint8_t *key,
			 size_t keylen, const uint8_t *exp_ct,
			 const uint8_t *exp_tag, uint8_t exp_tag_len)
{
	struct lc_aead_ctx *ak_heap = NULL;
	ssize_t ret;
	int ret_checked = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
	uint8_t out_enc[ptlen];
	uint8_t out_dec[ptlen];
	uint8_t tag[exp_tag_len];
#pragma GCC diagnostic pop
	LC_AK_CTX_ON_STACK_TAGLEN(ak, hash, exp_tag_len);

	/* One shot encryption with pt ptr != ct ptr */
	ret = lc_aead_setkey(ak, key, keylen, iv, ivlen);
	if (ret) {
		printf("AEAD setkey failed: %zd\n", ret);
		return (int)ret;
	}

	lc_aead_encrypt(ak, pt, out_enc, ptlen, aad, aadlen, tag, exp_tag_len);
	lc_aead_zero(ak);

	ret_checked += lc_compare(out_enc, exp_ct, ptlen,
				  "Ascon Keccak crypt: Encryption, ciphertext");
	ret_checked += lc_compare(tag, exp_tag, exp_tag_len,
				  "Ascon Keccak crypt: Encryption, tag");

	//bin2print(out_enc, ptlen, stderr, "out_enc");
	//bin2print(tag, exp_tag_len, stderr, "tag");

	/* One shot encryption with pt ptr == ct ptr */
	if (lc_ak_alloc_taglen(hash, exp_tag_len, &ak_heap))
		return 1;

	lc_aead_setkey(ak_heap, key, keylen, iv, ivlen);

	memcpy(out_enc, pt, ptlen);
	lc_aead_encrypt(ak_heap, out_enc, out_enc, ptlen, aad, aadlen, tag,
			exp_tag_len);
	lc_aead_zero_free(ak_heap);

	ret_checked += lc_compare(out_enc, exp_ct, ptlen,
				  "Ascon Keccak: Encryption, ciphertext");
	ret_checked += lc_compare(tag, exp_tag, exp_tag_len,
				  "Ascon Keccak: Encryption, tag");

	/* One shot decryption with pt ptr != ct ptr */
	if (lc_aead_setkey(ak, key, keylen, iv, ivlen))
		return 1;
	ret = lc_aead_decrypt(ak, out_enc, out_dec, ptlen, aad, aadlen, tag,
			      exp_tag_len);
	//bin2print(out_dec, ptlen, stderr, "out_enc");
	lc_aead_zero(ak);
	if (ret < 0)
		ret_checked += 1;

	ret_checked += lc_compare(out_dec, pt, ptlen,
				  "Ascon Keccak crypt: Decryption, plaintext");

	/* Check authentication error */
	if (lc_aead_setkey(ak, key, keylen, iv, ivlen))
		return -EFAULT;

	out_enc[0] = (uint8_t)((out_enc[0] + 1) & 0xff);
	ret = lc_aead_decrypt(ak, out_enc, out_dec, ptlen, aad, aadlen, tag,
			      exp_tag_len);
	lc_aead_zero(ak);
	if (ret != -EBADMSG)
		ret_checked += 1;

	return ret_checked;
}

static int ak_tester_512_large_iv_tag(const struct lc_hash *hash,
				      const char *name)
{
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
		0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
		0x3e, 0x3f,
	};
	static const uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f
	};
	static const uint8_t iv[] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
		0x2e, 0x2f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x20, 0x21,
		0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
		0x2c, 0x2d, 0x2e, 0x2f,
	};
	static const uint8_t exp_ct[] = {
		0x29, 0x09, 0x36, 0x4d, 0xa7, 0xd1, 0x01, 0xbf, 0x09, 0xd0,
		0x07, 0x2f, 0xd3, 0xcc, 0x4b, 0x28, 0xdf, 0xd8, 0xfd, 0x9b,
		0x54, 0x6e, 0xac, 0xca, 0x1d, 0x1c, 0x4b, 0x47, 0x31, 0x97,
		0x7d, 0xcc, 0xff, 0xfe, 0x31, 0xe7, 0x0a, 0x39, 0xa1, 0x75,
		0x71, 0x1b, 0x58, 0x72, 0x06, 0x7a, 0x3a, 0x77, 0x73, 0x64,
		0x99, 0x62, 0x16, 0x05, 0x70, 0x2b, 0x19, 0x2d, 0x01, 0xf0,
		0x26, 0xe2, 0x9b, 0x74, 0x8f, 0xfd, 0x74, 0x5c, 0x7a, 0xbf,
		0x88, 0x79, 0xd8, 0x01, 0x32, 0x38, 0x77, 0x86, 0x46, 0x47,
		0x35, 0xab, 0x94, 0x8f, 0x8c, 0x61, 0x52, 0x6f, 0x67, 0xb0,
		0x7d, 0x6f, 0xbd, 0x01, 0x8c, 0x03, 0xba, 0x81, 0x97, 0x94,
		0xa3, 0x67, 0xa8, 0xbb, 0x3f, 0x08, 0xa7, 0x39, 0xf3, 0xc4,
		0x41, 0xe5, 0x16, 0xf5, 0x0c, 0x00, 0x82, 0x23, 0xf6, 0x86,
		0x62, 0x53, 0xe6, 0x67, 0x9a, 0xfb, 0x37, 0xe1, 0x4e, 0x7e,
		0xc1, 0xc2, 0x70, 0xdd, 0xb8, 0xa4, 0x18, 0x09, 0xdd, 0x99,
		0x44, 0x69, 0x5c, 0xc6, 0x29, 0xe4, 0x13, 0x3a, 0xa3, 0x52,
		0xe1, 0xb1, 0xcd, 0x29, 0x68, 0x76, 0x4e, 0x93, 0x45, 0xe4,
		0x19, 0xa4, 0x98, 0x9c, 0xb4, 0x19, 0xd8, 0x12, 0x5c, 0x67,
		0x57, 0xec, 0x22, 0x56, 0xef, 0x87, 0x6e, 0x3f, 0x31, 0x8c,
		0x3f, 0x36, 0x00, 0xad, 0x0d, 0xa4, 0x15, 0x34, 0x2f, 0xd6,
		0x75, 0xb4
	};
	static const uint8_t exp_tag[] = {
		0xf7, 0x5a, 0x99, 0xd0, 0x7c, 0x5e, 0x60, 0x35, 0x0a, 0xaa,
		0x88, 0x70, 0x0d, 0xa3, 0x0a, 0xdd, 0xf7, 0x26, 0x77, 0xd9,
		0x3f, 0x71, 0x62, 0xb2, 0xef, 0xc4, 0xad, 0xec, 0xec, 0xfb,
		0xd3, 0xe1, 0xc0, 0x47, 0xe7, 0x99, 0x58, 0x7a, 0x56, 0x57,
		0xfd, 0x06, 0x57, 0x41, 0xda, 0xc6, 0x5e, 0xd6, 0xb1, 0x58,
		0xe7, 0x23, 0xc5, 0x4b, 0xc8, 0x57, 0x9e, 0xf5, 0x2c, 0x6d,
		0xc0, 0xe5, 0xc7, 0x6e,

	};

	printf("Ascon Keccak 512 crypt ctx %s (%s implementation) len %u, state len %u\n",
	       name, hash == lc_sha3_512_c ? "C" : "accelerated",
	       (unsigned int)LC_AK_CTX_SIZE(hash),
	       (unsigned int)LC_AK_STATE_SIZE);
	return ak_tester_one(hash, in, sizeof(in), iv, sizeof(iv), in,
			     sizeof(in), key, sizeof(key), exp_ct, exp_tag,
			     sizeof(exp_tag));
}

static int ak_tester_512(const struct lc_hash *hash, const char *name)
{
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
		0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
		0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
		0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
		0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
		0x3e, 0x3f,
	};
	static const uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f
	};
	static const uint8_t iv[] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	};
	static const uint8_t exp_ct[] = {
		0xed, 0x50, 0x43, 0x63, 0x83, 0x2f, 0xaf, 0x87, 0xf0, 0x17,
		0x47, 0x2c, 0x70, 0x24, 0xf3, 0x04, 0xea, 0x6c, 0xff, 0x9d,
		0x96, 0xd2, 0x04, 0xe7, 0xe4, 0x73, 0x90, 0x77, 0x85, 0xf5,
		0x45, 0xcd, 0xad, 0xc4, 0x88, 0x49, 0x01, 0x09, 0x1a, 0xb4,
		0xf2, 0xaf, 0x34, 0xa7, 0xdc, 0x6c, 0x02, 0x02, 0xdb, 0x27,
		0x50, 0xc0, 0x07, 0xda, 0xa2, 0xb7, 0x8f, 0x6c, 0xd1, 0xa0,
		0xa4, 0xa5, 0x8e, 0x97, 0xbf, 0xb2, 0x29, 0x08, 0xdd, 0xbc,
		0x5c, 0x89, 0x3b, 0x79, 0x5f, 0x9f, 0xf5, 0x6d, 0x02, 0xfd,
		0x8d, 0x09, 0x72, 0x7b, 0x1f, 0xf7, 0xc5, 0x4a, 0x68, 0xd5,
		0x6e, 0x91, 0x4d, 0x72, 0x64, 0xaf, 0x57, 0x55, 0x0c, 0x54,
		0xdc, 0xa6, 0xd5, 0xbc, 0x1c, 0x03, 0x6a, 0xf6, 0x9f, 0x03,
		0x7f, 0x37, 0xed, 0xae, 0x75, 0xbb, 0x03, 0x09, 0x62, 0x47,
		0x33, 0x18, 0xab, 0xc0, 0x2b, 0x2c, 0x2d, 0xb0, 0x88, 0xef,
		0x7c, 0x4b, 0x75, 0x56, 0x7d, 0x58, 0xbd, 0x81, 0x72, 0x24,
		0x7e, 0x55, 0x1b, 0x5c, 0x1f, 0x35, 0x9d, 0x1d, 0xa1, 0xf3,
		0x29, 0x28, 0x11, 0xab, 0xb5, 0xea, 0x56, 0xd0, 0x94, 0x2f,
		0x15, 0x72, 0x0a, 0x58, 0xf8, 0x4b, 0x8e, 0x61, 0xb9, 0xcf,
		0xdd, 0xcc, 0x42, 0xed, 0xf0, 0xe1, 0x6e, 0x5d, 0x85, 0xe7,
		0x35, 0x74, 0x20, 0xbb, 0x3e, 0x79, 0x2f, 0x59, 0xe3, 0xf4,
		0x5f, 0x54
	};
	static const uint8_t exp_tag[] = { 0xb5, 0x63, 0x33, 0x41, 0x9a, 0xda,
					   0x82, 0xc1, 0xba, 0xdc, 0xcd, 0x70,
					   0xe7, 0x98, 0xfa, 0xe5 };

	printf("Ascon Keccak 512 crypt ctx %s (%s implementation) len %u, state len %u\n",
	       name, hash == lc_sha3_512_c ? "C" : "accelerated",
	       (unsigned int)LC_AK_CTX_SIZE(hash),
	       (unsigned int)LC_AK_STATE_SIZE);
	return ak_tester_one(hash, in, sizeof(in), iv, sizeof(iv), in,
			     sizeof(in), key, sizeof(key), exp_ct, exp_tag,
			     sizeof(exp_tag));
}

static int ak_tester_256(const struct lc_hash *hash, const char *name)
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
	static const uint8_t key[] = {
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	};
	static const uint8_t iv[] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	};
	static const uint8_t exp_ct[] = {
		0xbf, 0xdf, 0xeb, 0x80, 0x84, 0x88, 0xbe, 0xd1, 0xda, 0xdb,
		0x85, 0xda, 0xe2, 0x39, 0x18, 0xfc, 0x14, 0x20, 0xf1, 0x0b,
		0xc4, 0xd2, 0xaf, 0xc3, 0x1c, 0xee, 0x97, 0x0f, 0xad, 0x52,
		0xa0, 0xfa, 0xa6, 0x1a, 0x58, 0x0b, 0x56, 0x3f, 0xf6, 0xe8,
		0x03, 0x49, 0x43, 0xf1, 0x12, 0x0d, 0x5e, 0xb0, 0x82, 0x69,
		0xe2, 0xfd, 0xde, 0x02, 0xc2, 0x12, 0xd6, 0x91, 0x3b, 0x31,
		0x3d, 0x20, 0x54, 0x63
	};
	static const uint8_t exp_tag[] = { 0xc5, 0x72, 0x34, 0x77, 0xa0, 0x60,
					   0x46, 0x0d, 0xc1, 0x74, 0x21, 0x17,
					   0x6a, 0x28, 0xbb, 0x70 };

	printf("Ascon Keccak 256 crypt ctx %s (%s implementation) len %u, state len %u\n",
	       name, hash == lc_sha3_256_c ? "C" : "accelerated",
	       (unsigned int)LC_AK_CTX_SIZE(hash),
	       (unsigned int)LC_AK_STATE_SIZE);
	return ak_tester_one(hash, in, sizeof(in), iv, sizeof(iv), in,
			     sizeof(in), key, sizeof(key), exp_ct, exp_tag,
			     sizeof(exp_tag));
}

static int ak_tester_256_large_iv_tag(const struct lc_hash *hash,
				      const char *name)
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
	static const uint8_t key[] = {
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
		0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
		0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
		0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	};
	static const uint8_t iv[] = {
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	};
	static const uint8_t exp_ct[] = {
		0xff, 0xf3, 0x0f, 0x02, 0xb8, 0x3d, 0xbf, 0xcd, 0xbc, 0x3a,
		0x52, 0x55, 0x68, 0xab, 0xff, 0xa4, 0x78, 0x82, 0x31, 0x88,
		0x83, 0x3f, 0x9d, 0xad, 0xad, 0x43, 0x70, 0x5d, 0x6d, 0x49,
		0x34, 0x01, 0xb2, 0x25, 0xe1, 0xa2, 0xec, 0xbf, 0xc0, 0xa3,
		0x81, 0x12, 0x6f, 0x62, 0x85, 0xcc, 0x0a, 0x7d, 0x59, 0x0a,
		0x8c, 0x33, 0xd8, 0x47, 0x54, 0xee, 0x8a, 0x61, 0x8a, 0xc2,
		0x48, 0xe5, 0x48, 0x0a
	};
	static const uint8_t exp_tag[] = { 0xa1, 0xa3, 0xce, 0xdf, 0x40, 0x06,
					   0x24, 0x5b, 0x4a, 0x7f, 0x6f, 0x31,
					   0xcb, 0x44, 0xae, 0x71, 0xf5, 0xe2,
					   0xac, 0x24, 0xc8, 0xc6, 0x90, 0x46,
					   0x1f, 0x86, 0x07, 0x47, 0x58, 0x40,
					   0xe9, 0xb9 };

	printf("Ascon Keccak 256 crypt ctx %s (%s implementation) len %u, state len %u\n",
	       name, hash == lc_sha3_256_c ? "C" : "accelerated",
	       (unsigned int)LC_AK_CTX_SIZE(hash),
	       (unsigned int)LC_AK_STATE_SIZE);
	return ak_tester_one(hash, in, sizeof(in), iv, sizeof(iv), in,
			     sizeof(in), key, sizeof(key), exp_ct, exp_tag,
			     sizeof(exp_tag));
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0;
	(void)argc;
	(void)argv;

	LC_EXEC_ONE_TEST_512(lc_sha3_512);
	LC_EXEC_ONE_TEST_512(lc_sha3_512_c);
	LC_EXEC_ONE_TEST_512(lc_sha3_512_arm_asm);
	LC_EXEC_ONE_TEST_512(lc_sha3_512_arm_ce);
	LC_EXEC_ONE_TEST_512(lc_sha3_512_arm_neon);
	LC_EXEC_ONE_TEST_512(lc_sha3_512_avx2);
	LC_EXEC_ONE_TEST_512(lc_sha3_512_avx512);
	LC_EXEC_ONE_TEST_512(lc_sha3_512_riscv_asm);

	LC_EXEC_ONE_TEST_256(lc_sha3_256);
	LC_EXEC_ONE_TEST_256(lc_sha3_256_c);
	LC_EXEC_ONE_TEST_256(lc_sha3_256_arm_asm);
	LC_EXEC_ONE_TEST_256(lc_sha3_256_arm_ce);
	LC_EXEC_ONE_TEST_256(lc_sha3_256_arm_neon);
	LC_EXEC_ONE_TEST_256(lc_sha3_256_avx2);
	LC_EXEC_ONE_TEST_256(lc_sha3_256_avx512);
	LC_EXEC_ONE_TEST_256(lc_sha3_256_riscv_asm);

	return ret;
}
