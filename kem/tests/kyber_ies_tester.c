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
#include "small_stack_support.h"
#include "visibility.h"

static uint64_t ctr = 0;

static int randombytes(void *_state, const uint8_t *addtl_input,
		       size_t addtl_input_len, uint8_t *out, size_t outlen)
{
	unsigned int i;
	uint8_t buf[8];

	(void)_state;
	(void)addtl_input;
	(void)addtl_input_len;

	for (i = 0; i < 8; ++i)
		buf[i] = (uint8_t)(ctr >> 8 * i);

	ctr++;
	lc_shake(lc_shake128, buf, 8, out, outlen);

	return 0;
}

static int randombytes_seed(void *_state, const uint8_t *seed, size_t seedlen,
			    const uint8_t *persbuf, size_t perslen)
{
	(void)_state;
	(void)seed;
	(void)seedlen;
	(void)persbuf;
	(void)perslen;
	return 0;
}

static void randombytes_zero(void *_state)
{
	(void)_state;
}

static const struct lc_rng kyber_drng = {
	.generate = randombytes,
	.seed = randombytes_seed,
	.zero = randombytes_zero,
};

static int kyber_ies_determinisitic(void)
{
	static const uint8_t plain[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
	};
	static const uint8_t exp_cipher[] = {
		0x44, 0x9f, 0x79, 0x66, 0x66, 0x4f, 0x48, 0x73, 0x70, 0xdf,
		0xb9, 0x59, 0x10, 0x2e, 0x0b, 0xfc, 0x42, 0x0c, 0x1e, 0xa4,
		0x49, 0x71, 0xc9, 0xda, 0x7b, 0x6c, 0x07, 0x69, 0xa1, 0xa0,
		0xd5, 0x68, 0x3b, 0xa6, 0x02, 0xd6, 0xe7, 0x21, 0xc0, 0xa7,
		0x90, 0x84, 0x98, 0x36, 0xb0, 0x44, 0x43, 0x4a
	};
	static const uint8_t exp_tag[] = { 0x15, 0x93, 0x5e, 0xb3, 0xed, 0xf4,
					   0x07, 0x22, 0xf9, 0x7d, 0x35, 0x6c,
					   0x7d, 0x6b, 0xb9, 0x32 };
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;

		struct lc_kyber_ct ct;

		uint8_t cipher[sizeof(plain)];
		uint8_t plain_new[sizeof(plain)];
		uint8_t tag[16];
	};
	uint64_t remember_ctr;
	int ret;
	struct lc_rng_ctx cshake_rng = { .rng = &kyber_drng,
					 .rng_state = NULL };
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_CC_CTX_ON_STACK(cc, lc_cshake256);

	CKINT(lc_kyber_keypair(&ws->pk, &ws->sk, &cshake_rng));

	remember_ctr = ctr;

	CKINT(lc_kyber_ies_enc_internal(&ws->pk, &ws->ct, plain, ws->cipher,
					sizeof(plain), NULL, 0, ws->tag,
					sizeof(ws->tag), cc, &cshake_rng));

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

	/* Reset RNG */
	ctr = remember_ctr;
	CKINT(lc_kyber_ies_enc_init_internal(cc, &ws->pk, &ws->ct,
					     &cshake_rng));
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
