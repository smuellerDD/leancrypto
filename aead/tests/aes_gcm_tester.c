/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include "aes_c.h"
#include "alignment.h"
#include "compare.h"
#include "cpufeatures.h"
#include "lc_aes_gcm.h"
#include "lc_status.h"
#include "math_helper.h"
#include "test_helper_common.h"
#include "visibility.h"

static int lc_aes_gcm_test(int argc)
{
#if 0
	static const uint8_t aad[] = { 0xff, 0x76, 0x28, 0xf6, 0x42, 0x7f,
				       0xbc, 0xef, 0x1f, 0x3b, 0x82, 0xb3,
				       0x74, 0x04, 0xe1, 0x16 };
	const uint8_t *aadp = aad;
	size_t aadlen = sizeof(aad);
	static const uint8_t in[] = { 0xb7, 0x06, 0x19, 0x4b, 0xb0, 0xb1,
				      0x0c, 0x47, 0x4e, 0x1b, 0x2d, 0x7b,
				      0x22, 0x78, 0x22, 0x4c };
	static const uint8_t key[] = { 0x7f, 0x71, 0x68, 0xa4, 0x06, 0xe7, 0xc1,
				       0xef, 0x0f, 0xd4, 0x7a, 0xc9, 0x22, 0xc5,
				       0xec, 0x5f, 0x65, 0x97, 0x65, 0xfb, 0x6a,
				       0xaa, 0x04, 0x8f, 0x70, 0x56, 0xf6, 0xc6,
				       0xb5, 0xd8, 0x51, 0x3d };
	static const uint8_t iv[] = { 0xb8, 0xb5, 0xe4, 0x07, 0xad, 0xc0,
				      0xe2, 0x93, 0xe3, 0xe7, 0xe9, 0x91 };
	static const uint8_t exp_ct[] = { 0x8f, 0xad, 0xa0, 0xb8, 0xe7, 0x77,
					  0xa8, 0x29, 0xca, 0x96, 0x80, 0xd3,
					  0xbf, 0x4f, 0x35, 0x74 };
	static const uint8_t exp_tag[] = { 0xda, 0xca, 0x35, 0x42, 0x77,
					   0xf6, 0x33, 0x5f, 0xc8, 0xbe,
					   0xc9, 0x08, 0x86, 0xda, 0x70 };
#else
	/*
	 * Test cases with non-block-size AAD and PT to be inserted with
	 * multiple updates
	 */
	static const uint8_t aad[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
				       0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
				       0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2 };
	const uint8_t *aadp = aad;
	size_t aadlen = sizeof(aad);
	static const uint8_t in[] = {
		0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59,
		0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53,
		0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31,
		0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
		0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a,
		0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39,
	};
	static const uint8_t key[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
				       0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				       0x67, 0x30, 0x83, 0x08 };
	static const uint8_t iv[] = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
				      0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
	static const uint8_t exp_ct[] = {
		0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72,
		0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f,
		0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac,
		0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
		0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3,
		0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91
	};
	static const uint8_t exp_tag[] = { 0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21,
					   0xa5, 0xdb, 0x94, 0xfa, 0xe9, 0x5a,
					   0xe7, 0x12, 0x1a, 0x47 };
#endif

	uint8_t act_ct[sizeof(exp_ct)] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(exp_tag)] __align(sizeof(uint32_t));
	size_t len, i;
	const uint8_t *in_p;
	uint8_t *out_p;
	int ret = 0, rc;
	LC_AES_GCM_CTX_ON_STACK(aes_gcm);

	if (argc >= 2) {
		struct lc_aes_gcm_cryptor *c = aes_gcm->aead_state;
		c->sym_ctx.sym = lc_aes_c;
	}

	if (lc_aead_setkey(aes_gcm, key, sizeof(key), iv, sizeof(iv)))
		return 1;

	if (lc_status_get_result(LC_ALG_STATUS_AES_GCM) !=
	    lc_alg_status_result_passed) {
		printf("Self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_AES_GCM));
		ret += 1;
	}

	lc_aead_encrypt(aes_gcm, in, act_ct, sizeof(in), aadp, aadlen, act_tag,
			sizeof(act_tag));
	ret += lc_compare(act_ct, exp_ct, sizeof(exp_ct),
			  "AES GCM encrypt ciphertext");
	ret += lc_compare(act_tag, exp_tag, sizeof(exp_tag),
			  "AES GCM encrypt tag");
	lc_aead_zero(aes_gcm);

	if (lc_aead_setkey(aes_gcm, key, sizeof(key), iv, sizeof(iv)))
		return 1;
	rc = lc_aead_decrypt(aes_gcm, act_ct, act_ct, sizeof(act_ct), aadp,
			     aadlen, act_tag, sizeof(act_tag));
	if (rc) {
		ret += 1;
		printf("AES GCM decryption authentication failed\n");
	}
	ret += lc_compare(act_ct, in, sizeof(in), "AES GCM decrypt plaintext");
	lc_aead_zero(aes_gcm);

	/* Test the encryption stream cipher API */
	if (lc_aead_setkey(aes_gcm, key, sizeof(key), iv, sizeof(iv)))
		return 1;

	/* Multi-update of AAD as supported by GCM */
	if (aadlen > 3) {
		lc_aead_enc_init(aes_gcm, aadp, 1);
		lc_aead_enc_init(aes_gcm, aadp + 1, 2);
		lc_aead_enc_init(aes_gcm, aadp + 3, aadlen - 3);
	} else {
		lc_aead_enc_init(aes_gcm, aadp, aadlen);
	}

	len = sizeof(in);
	i = 1;
	in_p = in;
	out_p = act_ct;
	while (len) {
		size_t todo = min_size(len, i);

		lc_aead_enc_update(aes_gcm, in_p, out_p, todo);

		len -= todo;
		in_p += todo;
		out_p += todo;
		i++;
	}

	lc_aead_enc_final(aes_gcm, act_tag, sizeof(act_tag));

	ret += lc_compare(act_ct, exp_ct, sizeof(exp_ct),
			  "AES GCM encrypt ciphertext");
	ret += lc_compare(act_tag, exp_tag, sizeof(exp_tag),
			  "AES GCM encrypt tag");
	lc_aead_zero(aes_gcm);

	/* Test the decryption stream cipher API */
	if (lc_aead_setkey(aes_gcm, key, sizeof(key), iv, sizeof(iv)))
		return 1;

	/* Multi-update of AAD as supported by GCM */
	if (aadlen > 7) {
		lc_aead_dec_init(aes_gcm, aadp, 3);
		lc_aead_dec_init(aes_gcm, aadp + 3, 4);
		lc_aead_dec_init(aes_gcm, aadp + 7, aadlen - 7);
	} else {
		lc_aead_dec_init(aes_gcm, aadp, aadlen);
	}

	len = sizeof(act_ct);
	i = 1;

	in_p = act_ct;
	out_p = act_ct;
	while (len) {
		size_t todo = min_size(len, i);

		lc_aead_dec_update(aes_gcm, in_p, out_p, todo);

		len -= todo;
		in_p += todo;
		out_p += todo;
		i++;
	}
	rc = lc_aead_dec_final(aes_gcm, act_tag, sizeof(act_tag));
	if (rc) {
		ret += 1;
		printf("AES GCM decryption authentication failed\n");
	}

	ret += lc_compare(act_ct, in, sizeof(in), "AES GCM decrypt ciphertext");
	lc_aead_zero(aes_gcm);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	if (argc >= 2)
		lc_cpu_feature_disable();

	ret = lc_aes_gcm_test(argc);

	ret += test_print_status();

	lc_cpu_feature_enable();

	return ret;
}
