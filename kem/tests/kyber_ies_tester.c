/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers.h"
#include "kyber_internal.h"
#include "lc_cshake256_drng.h"
#include "lc_cshake_crypt.h"
#include "lc_kyber.h"
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
		0x99, 0xea, 0x96, 0x54, 0x8f, 0x28, 0xe7, 0xe5, 0xac, 0xbe,
		0x7d, 0xac, 0x74, 0x60, 0xef, 0x75, 0x6e, 0x0b, 0xa1, 0x27,
		0x3d, 0x4b, 0x42, 0x74, 0x5f, 0xe2, 0x2d, 0xa2, 0xf0, 0xf0,
		0x4f, 0xa5, 0x00, 0xcb, 0xb2, 0x47, 0xb2, 0x1c, 0x16, 0x87,
		0x4a, 0x42, 0x6c, 0x04, 0xe4, 0x66, 0xce, 0x74
	};
	static const uint8_t exp_tag[] = { 0xd3, 0xd4, 0x92, 0xef, 0x04, 0x31,
					   0xac, 0x63, 0x08, 0xe6, 0x95, 0xc6,
					   0x6c, 0xef, 0xb3, 0x57 };
#elif LC_KYBER_K == 3
	static const uint8_t exp_cipher[] = {
		0xb3, 0xb9, 0xe7, 0xdc, 0x67, 0x28, 0x10, 0xa6, 0x9a, 0x0d,
		0x5c, 0xaa, 0x72, 0xd5, 0x81, 0xf8, 0x47, 0x2f, 0xfa, 0xd7,
		0x0b, 0x46, 0x4e, 0x6f, 0x2a, 0x91, 0xd1, 0xdf, 0x54, 0x24,
		0x4d, 0xe2, 0x9e, 0xa9, 0xff, 0xf1, 0xba, 0x7a, 0xeb, 0x00,
		0xc8, 0x7f, 0xbb, 0x6b, 0xbc, 0x21, 0xfc, 0x66
	};
	static const uint8_t exp_tag[] = { 0xa1, 0x20, 0x77, 0x9e, 0xe1, 0x6e,
					   0x04, 0xf3, 0x08, 0x1e, 0xa8, 0x5f,
					   0xfe, 0xf0, 0x49, 0x83 };
#elif LC_KYBER_K == 4
	static const uint8_t exp_cipher[] = {
		0x2a, 0xe4, 0xf2, 0xc4, 0x15, 0x3a, 0x8e, 0x36, 0xeb, 0x5d,
		0xb8, 0xa5, 0x5e, 0x8a, 0xd6, 0x0b, 0x9c, 0x23, 0x4e, 0xbc,
		0x01, 0xc6, 0x41, 0x40, 0x52, 0x97, 0xcf, 0x72, 0xf6, 0x8f,
		0x99, 0x5d, 0x3d, 0xd8, 0x63, 0x5e, 0x40, 0xe4, 0x66, 0x53,
		0xe8, 0x82, 0x1d, 0x92, 0x1a, 0x21, 0xba, 0xf2
	};
	static const uint8_t exp_tag[] = { 0x90, 0x58, 0x88, 0xc2, 0x7d, 0x0b,
					   0xac, 0xff, 0x4a, 0xf8, 0x99, 0x8a,
					   0xff, 0xa2, 0x2f, 0xc3 };
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

	if (memcmp(ws->cipher, exp_cipher, sizeof(exp_cipher))) {
		printf("Error in encryption of oneshot IES: ciphertext\n");
		ret = 1;
		goto out;
	}
	if (memcmp(ws->tag, exp_tag, sizeof(exp_tag))) {
		printf("Error in encryption of oneshot IES: tag\n");
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);

	lc_rng_zero(selftest_rng);
	lc_rng_seed(selftest_rng, NULL, 0, NULL, 0);
	CKINT(lc_kyber_ies_enc_init_internal(cc, &ws->pk, &ws->ct,
					     selftest_rng));
	lc_kyber_ies_enc_update(cc, plain, ws->cipher, sizeof(plain));
	lc_kyber_ies_enc_final(cc, NULL, 0, ws->tag, sizeof(ws->tag));
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
	CKINT(lc_kyber_ies_dec_init(cc, &ws->sk, &ws->ct));

	lc_kyber_ies_dec_update(cc, ws->cipher, ws->plain_new, sizeof(plain));
	CKINT(lc_kyber_ies_dec_final(cc, NULL, 0, ws->tag, sizeof(ws->tag)));
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
