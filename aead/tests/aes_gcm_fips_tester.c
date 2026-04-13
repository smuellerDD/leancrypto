/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
#include "lc_init.h"
#include "lc_status.h"
#include "math_helper.h"
#include "test_helper_common.h"
#include "visibility.h"

static int lc_aes_gcm_test(int argc)
{
	/*
	 * Test cases with non-block-size AAD and PT to be inserted with
	 * multiple updates
	 */
	static const uint8_t aad[] = { 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe,
				       0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
				       0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2 };
	static const uint8_t zero[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	static const uint8_t one[] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};
	static const uint8_t key[] = { 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65,
				       0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
				       0x67, 0x30, 0x83, 0x08 };
	uint8_t act_ct[sizeof(zero)] __align(sizeof(uint32_t));
	uint8_t act_iv[12] __align(sizeof(uint32_t));
	uint8_t act_tag[sizeof(zero)] __align(sizeof(uint32_t));
	int ret = 0;
	LC_AES_GCM_CTX_ON_STACK(aes_gcm);

	if (argc >= 2) {
		struct lc_aes_gcm_cryptor *c = aes_gcm->aead_state;
		c->sym_ctx.sym = lc_aes_c;
	}

	/*
	 * Test that encryption fails with external IV
	 */
	memset(act_ct, 0xff, sizeof(act_ct));
	memset(act_tag, 0xff, sizeof(act_tag));
	if (lc_aead_setkey(aes_gcm, key, sizeof(key), zero, sizeof(zero)))
		return 1;

	lc_aead_encrypt(aes_gcm, one, act_ct, sizeof(zero), aad, sizeof(aad),
			act_tag, sizeof(act_tag));
	ret += lc_compare(act_ct, zero, sizeof(zero),
			  "AES GCM encrypt ciphertext");
	ret += lc_compare(act_tag, zero, sizeof(zero), "AES GCM encrypt tag");
	lc_aead_zero(aes_gcm);


	/*
	 * Test that encryption succeeds with internal IV
	 */
	memset(act_ct, 0xff, sizeof(act_ct));
	memset(act_tag, 0xff, sizeof(act_tag));
	if (lc_aead_setkey(aes_gcm, key, sizeof(key), NULL, 0))
		return 1;

	if (lc_aes_gcm_generate_iv(aes_gcm, one, 4, act_iv, sizeof(act_iv),
				   lc_aes_gcm_iv_generate_new))
		return 1;

	ret += lc_compare(act_iv, one, 4, "AES GCM IV generate");

	lc_aead_encrypt(aes_gcm, one, act_ct, sizeof(zero), aad, sizeof(aad),
			act_tag, sizeof(act_tag));
	if (!memcmp(act_ct, zero, sizeof(act_ct))) {
		printf("AES GCM encrypt ciphertext is equal to zero\n");
		return 1;
	}
	if (!memcmp(act_tag, zero, sizeof(act_tag))) {
		printf("AES GCM tag is equal to zero\n");
		return 1;
	}

	lc_aead_zero(aes_gcm);

	/*
	 * Test that decryption with the IV that was generated during encrypt
	 */
	if (lc_aead_setkey(aes_gcm, key, sizeof(key), act_iv, sizeof(act_iv)))
		return 1;
	lc_aead_decrypt(aes_gcm, act_ct, act_ct, sizeof(zero), aad, sizeof(aad),
			act_tag, sizeof(act_tag));
	ret += lc_compare(act_ct, one, sizeof(one), "AES GCM decrypt");

	lc_aead_zero(aes_gcm);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	if (argc >= 2) {
		if (*argv[1] == 'c')
			lc_cpu_feature_disable();
		if (*argv[1] == 't')
			lc_init(LC_INIT_AES_SBOX);
	}

	ret = lc_aes_gcm_test(argc);

	lc_cpu_feature_enable();

	return ret;
}
