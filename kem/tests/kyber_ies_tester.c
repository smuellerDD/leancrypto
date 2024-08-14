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
#include "kyber_type.h"
#include "kyber_internal.h"
#include "lc_cshake256_drng.h"
#include "lc_cshake_crypt.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "selftest_rng.h"
#include "small_stack_support.h"
#include "visibility.h"

static int kyber_ies_determinisitic(void)
{
	static const uint8_t plain[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
	};
#if LC_KYBER_K == 2
	static const uint8_t exp_cipher[] = {
		0x2e, 0xab, 0x21, 0x90, 0x34, 0x9c, 0x38, 0x90, 0xda, 0x06,
		0x6c, 0xf6, 0x97, 0xe3, 0xed, 0xc7, 0x1d, 0x5f, 0x38, 0x84,
		0xad, 0x6f, 0xb8, 0xd3, 0x6e, 0xaa, 0x6c, 0xf3, 0xa8, 0x2d,
		0x23, 0x1d, 0x08, 0xa8, 0x9b, 0x17, 0xc6, 0x53, 0xdc, 0xa2,
		0x9f, 0x45, 0xe6, 0x31, 0xe4, 0xec, 0xc3, 0x1b
	};
	static const uint8_t exp_tag[] = { 0xe2, 0xdd, 0xe4, 0x4d, 0x73, 0x73,
					   0xf9, 0x2a, 0x42, 0x86, 0xbc, 0xa4,
					   0xfa, 0xe7, 0x1b, 0xd3 };
#elif LC_KYBER_K == 3
	static const uint8_t exp_cipher[] = {
		0x16, 0xbd, 0xab, 0x85, 0x05, 0x35, 0xf4, 0x8a, 0xf2, 0xc9,
		0xc8, 0x7a, 0xc0, 0xa0, 0x32, 0xd5, 0x75, 0xf7, 0x86, 0xe1,
		0x12, 0xd0, 0x36, 0xee, 0x8a, 0xfa, 0xc4, 0xcd, 0x75, 0x17,
		0x69, 0x83, 0xbe, 0x1f, 0x6d, 0xfd, 0xf3, 0x32, 0xd6, 0x20,
		0x19, 0x44, 0x02, 0xe3, 0x3f, 0xf5, 0x33, 0xe5
	};
	static const uint8_t exp_tag[] = { 0xb8, 0xd3, 0xf5, 0x1a, 0x76, 0x38,
					   0x44, 0x67, 0x6a, 0x80, 0x2f, 0x2d,
					   0x0a, 0x9e, 0xa7, 0x2d };
#elif LC_KYBER_K == 4
	static const uint8_t exp_cipher[] = {
		0x9b, 0xba, 0x97, 0x90, 0x85, 0xff, 0xb5, 0xf6, 0x25, 0x7d,
		0x5c, 0xb8, 0x2d, 0x8e, 0x3e, 0x42, 0x03, 0x26, 0x0e, 0xf7,
		0x56, 0x36, 0xdf, 0x3e, 0x23, 0x00, 0xa5, 0x01, 0x9e, 0xad,
		0xab, 0x14, 0x97, 0x46, 0xe3, 0x57, 0x08, 0x0f, 0x84, 0xc6,
		0x92, 0x84, 0x9f, 0xc2, 0xae, 0x23, 0x94, 0x98
	};
	static const uint8_t exp_tag[] = { 0xdf, 0xcf, 0x82, 0xf4, 0x24, 0x5e,
					   0x9e, 0xc1, 0x0e, 0xe0, 0x2c, 0x2c,
					   0xec, 0x75, 0x64, 0xda };
#endif
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;

		struct lc_kyber_ct ct;

		uint8_t cipher[sizeof(plain)];
		uint8_t plain_new[sizeof(plain)];
		uint8_t tag[16];
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_CC_CTX_ON_STACK(cc, lc_cshake256);
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	CKINT(lc_kyber_keypair(&ws->pk, &ws->sk, selftest_rng));

	lc_rng_zero(selftest_rng);
	lc_rng_seed(selftest_rng, NULL, 0, NULL, 0);
	CKINT(lc_kyber_ies_enc_internal(&ws->pk, &ws->ct, plain, ws->cipher,
					sizeof(plain), NULL, 0, ws->tag,
					sizeof(ws->tag), cc, selftest_rng));

	//	bin2print(ws->pk.pk, sizeof(ws->pk.pk), stdout, "PK");
	//	bin2print(ws->sk.sk, sizeof(ws->sk.sk), stdout, "SK");
	//	bin2print(ws->ct.ct, sizeof(ws->ct.ct), stdout, "CT");
	//
	//	bin2print(ws->cipher, sizeof(ws->cipher), stdout, "Ciphertext");
	//	bin2print(ws->tag, sizeof(ws->tag), stdout, "Tag");

	if (lc_compare(ws->cipher, exp_cipher, sizeof(exp_cipher),
		       "Encryption of oneshot IES: ciphertext\n")) {
		ret = 1;
		goto out;
	}
	if (lc_compare(ws->tag, exp_tag, sizeof(exp_tag),
		       "Encryption of oneshot IES: tag\n")) {
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);

	lc_rng_zero(selftest_rng);
	lc_rng_seed(selftest_rng, NULL, 0, NULL, 0);
	CKINT(lc_kyber_ies_enc_init_internal(cc, &ws->pk, &ws->ct, NULL, 0,
					     selftest_rng));
	lc_kyber_ies_enc_update(cc, plain, ws->cipher, sizeof(plain));
	lc_kyber_ies_enc_final(cc, ws->tag, sizeof(ws->tag));
	if (memcmp(ws->cipher, exp_cipher, sizeof(exp_cipher))) {
		printf("Error in encryption of stream IES: ciphertext\n");
		ret = 1;
		goto out;
	}
	if (memcmp(ws->tag, exp_tag, sizeof(exp_tag))) {
		printf("Error in encryption of stream IES: tag\n");
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_dec(&ws->sk, &ws->ct, ws->cipher, ws->plain_new,
			       sizeof(plain), NULL, 0, ws->tag, sizeof(ws->tag),
			       cc));

	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of oneshot IES\n");
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_dec_init(cc, &ws->sk, &ws->ct, NULL, 0));

	lc_kyber_ies_dec_update(cc, ws->cipher, ws->plain_new, sizeof(plain));
	CKINT(lc_kyber_ies_dec_final(cc, ws->tag, sizeof(ws->tag)));
	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of stream IES\n");
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);

	/* Modify the ciphertext -> integrity error */
	ws->cipher[0] = (ws->cipher[0] + 0x01) & 0xff;
	ret = lc_kyber_ies_dec(&ws->sk, &ws->ct, ws->cipher, ws->plain_new,
			       sizeof(ws->cipher), NULL, 0, ws->tag,
			       sizeof(ws->tag), cc);
	if (ret != -EBADMSG) {
		printf("Error in detecting authentication error\n");
		ret = 1;
		goto out;
	}

	ret = 0;

out:
	LC_RELEASE_MEM(ws);
	lc_aead_zero(cc);
	return ret;
}

static int kyber_ies_nondeterministic(void)
{
	static const uint8_t plain[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
	};
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;

		struct lc_kyber_ct ct;

		struct lc_kyber_ct ct2;

		uint8_t cipher[sizeof(plain)];
		uint8_t cipher2[sizeof(plain)];
		uint8_t plain_new[sizeof(plain)];
		uint8_t tag[16];
	};
	int ret = 1;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_CC_CTX_ON_STACK(cc, lc_cshake256);
	LC_CSHAKE256_DRNG_CTX_ON_STACK(rng);

	if (lc_rng_seed(rng, plain, sizeof(plain), NULL, 0))
		goto out;

	CKINT(lc_kyber_keypair(&ws->pk, &ws->sk, rng));

	/* First enc/dec */
	CKINT(lc_kyber_ies_enc_internal(&ws->pk, &ws->ct, plain, ws->cipher,
					sizeof(plain), NULL, 0, ws->tag,
					sizeof(ws->tag), cc, rng));

	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_dec(&ws->sk, &ws->ct, ws->cipher, ws->plain_new,
			       sizeof(ws->cipher), NULL, 0, ws->tag,
			       sizeof(ws->tag), cc));
	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of IES\n");
		ret = 1;
		goto out;
	}

	/* 2nd enc/dec */
	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_enc_internal(&ws->pk, &ws->ct2, plain, ws->cipher2,
					sizeof(plain), NULL, 0, ws->tag,
					sizeof(ws->tag), cc, rng));

	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_dec(&ws->sk, &ws->ct2, ws->cipher2, ws->plain_new,
			       sizeof(ws->cipher2), NULL, 0, ws->tag,
			       sizeof(ws->tag), cc));
	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of IES\n");
		ret = 1;
		goto out;
	}

	/* Check that produced data from 2nd enc is different to 1st enc */
	if (!memcmp(ws->ct.ct, ws->ct2.ct, sizeof(ws->ct.ct))) {
		printf("Error: identical kyber ciphertexts\n");
		ret = 1;
		goto out;
	}
	if (!memcmp(ws->cipher, ws->cipher2, sizeof(ws->cipher))) {
		printf("Error: identical ciphertexts\n");
		ret = 1;
		goto out;
	}

out:
	LC_RELEASE_MEM(ws);
	lc_aead_zero(cc);
	return ret;
}

static int kyber_ies_tester(void)
{
	int ret;

	ret = kyber_ies_determinisitic();
	if (ret)
		goto out;

	CKINT(kyber_ies_nondeterministic());

out:
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kyber_ies_tester();
}
