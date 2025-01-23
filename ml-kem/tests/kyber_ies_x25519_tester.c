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
#include "kyber_x25519_internal.h"
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
		0x3f, 0x97, 0x21, 0xfe, 0x69, 0x6a, 0xd0, 0xe8, 0xa6, 0x12,
		0x80, 0xf5, 0x97, 0xa5, 0xf2, 0xef, 0x29, 0x8b, 0x3f, 0xaf,
		0x38, 0x55, 0x53, 0xf6, 0xa4, 0xfd, 0x73, 0xb3, 0x5c, 0x00,
		0x02, 0x74, 0x7b, 0xf3, 0x16, 0x1a, 0xeb, 0x7b, 0x42, 0x33,
		0xd3, 0x13, 0xc7, 0xeb, 0x96, 0xd3, 0x62, 0x81
	};
	static const uint8_t exp_tag[] = { 0x58, 0xa3, 0x8e, 0xcf, 0x6b, 0xa1,
					   0x60, 0x41, 0x6f, 0x3d, 0x7b, 0xfc,
					   0xdb, 0xda, 0x87, 0x62 };
#elif LC_KYBER_K == 3
	static const uint8_t exp_cipher[] = {
		0x7b, 0x47, 0x32, 0xd0, 0x5e, 0x0f, 0xae, 0x04, 0x62, 0xec,
		0xe8, 0x0a, 0x1b, 0xd9, 0xe1, 0xd0, 0x5d, 0x56, 0xad, 0x3a,
		0xd4, 0x63, 0x3a, 0xe2, 0xf6, 0xc3, 0x54, 0xc9, 0xed, 0x25,
		0x20, 0x94, 0x34, 0x47, 0xec, 0x25, 0x99, 0x27, 0xa7, 0x44,
		0x9c, 0x08, 0x45, 0xfc, 0xf8, 0xc3, 0x19, 0xc3
	};
	static const uint8_t exp_tag[] = { 0xfb, 0x71, 0xb5, 0xb3, 0x24, 0xf4,
					   0x06, 0x23, 0xca, 0xc7, 0xcf, 0xdc,
					   0x84, 0xd6, 0x40, 0x20 };
#elif LC_KYBER_K == 4
	static const uint8_t exp_cipher[] = {
		0xfe, 0x56, 0xfe, 0x72, 0xbf, 0xdf, 0x2f, 0x02, 0x73, 0x46,
		0xf3, 0xf8, 0x4d, 0x3e, 0x5c, 0x40, 0x71, 0xca, 0x6e, 0xa3,
		0x6d, 0xd2, 0x55, 0x19, 0x37, 0x4a, 0x30, 0xe2, 0xa0, 0x82,
		0xb0, 0xa4, 0x3a, 0x4c, 0x89, 0xa3, 0x25, 0x22, 0x69, 0x4b,
		0x81, 0x85, 0x0c, 0x6f, 0x93, 0x2d, 0xdd, 0x76
	};
	static const uint8_t exp_tag[] = { 0xea, 0xa6, 0x37, 0xaf, 0x17, 0x70,
					   0x17, 0x09, 0xb1, 0xfd, 0x70, 0x89,
					   0x94, 0xff, 0x1b, 0x00 };
#endif
	struct workspace {
		struct lc_kyber_x25519_pk pk;
		struct lc_kyber_x25519_sk sk;

		struct lc_kyber_x25519_ct ct;

		uint8_t cipher[sizeof(plain)];
		uint8_t plain_new[sizeof(plain)];
		uint8_t tag[16];
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_CC_CTX_ON_STACK(cc, lc_cshake256);
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	CKINT(lc_kyber_x25519_keypair(&ws->pk, &ws->sk, selftest_rng));

	lc_rng_zero(selftest_rng);
	lc_rng_seed(selftest_rng, NULL, 0, NULL, 0);
	CKINT(lc_kyber_x25519_ies_enc_internal(
		&ws->pk, &ws->ct, plain, ws->cipher, sizeof(plain), NULL, 0,
		ws->tag, sizeof(ws->tag), cc, selftest_rng));

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
	CKINT(lc_kyber_x25519_ies_enc_init_internal(cc, &ws->pk, &ws->ct, NULL,
						    0, selftest_rng));
	lc_kyber_x25519_ies_enc_update(cc, plain, ws->cipher, sizeof(plain));
	lc_kyber_x25519_ies_enc_final(cc, ws->tag, sizeof(ws->tag));
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
	CKINT(lc_kyber_x25519_ies_dec(&ws->sk, &ws->ct, ws->cipher,
				      ws->plain_new, sizeof(plain), NULL, 0,
				      ws->tag, sizeof(ws->tag), cc));

	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of oneshot IES\n");
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);
	CKINT(lc_kyber_x25519_ies_dec_init(cc, &ws->sk, &ws->ct, NULL, 0));

	lc_kyber_x25519_ies_dec_update(cc, ws->cipher, ws->plain_new,
				       sizeof(plain));
	CKINT(lc_kyber_x25519_ies_dec_final(cc, ws->tag, sizeof(ws->tag)));
	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of stream IES\n");
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);

	/* Modify the ciphertext -> integrity error */
	ws->cipher[0] = (uint8_t)((ws->cipher[0] + 0x01) & 0xff);
	ret = lc_kyber_x25519_ies_dec(&ws->sk, &ws->ct, ws->cipher,
				      ws->plain_new, sizeof(ws->cipher), NULL,
				      0, ws->tag, sizeof(ws->tag), cc);
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
		struct lc_kyber_x25519_pk pk;
		struct lc_kyber_x25519_sk sk;

		struct lc_kyber_x25519_ct ct;

		struct lc_kyber_x25519_ct ct2;

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

	CKINT(lc_kyber_x25519_keypair(&ws->pk, &ws->sk, rng));

	/* First enc/dec */
	CKINT(lc_kyber_x25519_ies_enc_internal(
		&ws->pk, &ws->ct, plain, ws->cipher, sizeof(plain), NULL, 0,
		ws->tag, sizeof(ws->tag), cc, rng));

	lc_aead_zero(cc);
	CKINT(lc_kyber_x25519_ies_dec(&ws->sk, &ws->ct, ws->cipher,
				      ws->plain_new, sizeof(ws->cipher), NULL,
				      0, ws->tag, sizeof(ws->tag), cc));
	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of IES\n");
		ret = 1;
		goto out;
	}

	/* 2nd enc/dec */
	lc_aead_zero(cc);
	CKINT(lc_kyber_x25519_ies_enc_internal(
		&ws->pk, &ws->ct2, plain, ws->cipher2, sizeof(plain), NULL, 0,
		ws->tag, sizeof(ws->tag), cc, rng));

	lc_aead_zero(cc);
	CKINT(lc_kyber_x25519_ies_dec(&ws->sk, &ws->ct2, ws->cipher2,
				      ws->plain_new, sizeof(ws->cipher2), NULL,
				      0, ws->tag, sizeof(ws->tag), cc));
	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of IES\n");
		ret = 1;
		goto out;
	}

	/* Check that produced data from 2nd enc is different to 1st enc */
	if (!memcmp(&ws->ct, &ws->ct2, sizeof(ws->ct))) {
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
