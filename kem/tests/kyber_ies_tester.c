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
#include "lc_cshake256_drng.h"
#include "lc_cshake_crypt.h"
#include "lc_kyber.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

static int
randombytes(void *_state,
	    const uint8_t *addtl_input, size_t addtl_input_len,
	    uint8_t *out, size_t outlen)
{
	unsigned int i;
	uint8_t buf[8];
	static uint64_t ctr = 0;

	(void)_state;
	(void)addtl_input;
	(void)addtl_input_len;

	for (i = 0; i < 8; ++i)
		buf[i] = (uint8_t)(ctr >> 8*i);

	ctr++;
	lc_shake(lc_shake128, buf, 8, out, outlen);

	return 0;
}

static int
randombytes_seed(void *_state,
		 const uint8_t *seed, size_t seedlen,
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
	.generate	= randombytes,
	.seed		= randombytes_seed,
	.zero		= randombytes_zero,
};

static int kyber_ies_determinisitic(void)
{
	static const uint8_t plain[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
	};
	static const uint8_t exp_cipher[] = {
		0x83, 0x45, 0x79, 0x46, 0x57, 0x15, 0x0d, 0x76,
		0x89, 0x73, 0x21, 0x6a, 0x80, 0xd4, 0x66, 0x3a,
		0x72, 0x0d, 0x04, 0x1f, 0xbc, 0xea, 0x11, 0x51,
		0x48, 0x8a, 0x77, 0x1e, 0xe8, 0x81, 0x01, 0x01,
		0xb4, 0xe6, 0xfb, 0xbf, 0x56, 0xf8, 0x99, 0x9a,
		0x2d, 0xee, 0x9e, 0xa9, 0xb1, 0xbd, 0x7c, 0x08
	};
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;

		struct lc_kyber_ct ct;

		uint8_t cipher[sizeof(plain)];
		uint8_t plain_new[sizeof(plain)];
		uint8_t tag[16];
	};
	int ret;
	struct lc_rng_ctx cshake_rng =
		{ .rng = &kyber_drng, .rng_state = NULL };
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_CC_CTX_ON_STACK(cc, lc_cshake256);

	CKINT(lc_kyber_keypair(&ws->pk, &ws->sk, &cshake_rng));

	CKINT(lc_kyber_ies_enc(&ws->pk, &ws->ct,
			       plain, ws->cipher, sizeof(plain), NULL, 0,
			       ws->tag, sizeof(ws->tag),
			       cc, &cshake_rng));

// 	bin2print(pk.pk, sizeof(pk.pk), stdout, "PK");
// 	bin2print(sk.sk, sizeof(sk.sk), stdout, "SK");
// 	bin2print(ct.ct, sizeof(ct.ct), stdout, "CT");
//
// 	bin2print(cipher, sizeof(cipher), stdout, "Ciphertext");
// 	bin2print(tag, sizeof(tag), stdout, "Tag");

	if (memcmp(ws->cipher, exp_cipher, sizeof(exp_cipher))){
		printf("Error in encryption of IES\n");
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_dec(&ws->sk, &ws->ct,
			       ws->cipher, ws->plain_new, sizeof(ws->cipher),
			       NULL, 0,
			       ws->tag, sizeof(ws->tag), cc));

	if (memcmp(plain, ws->plain_new, sizeof(plain))){
		printf("Error in decryption of IES\n");
		ret = 1;
		goto out;
	}

	lc_aead_zero(cc);

	/* Modify the ciphertext -> integrity error */
	ws->cipher[0] = (ws->cipher[0] + 0x01) & 0xff;
	ret = lc_kyber_ies_dec(&ws->sk, &ws->ct,
			       ws->cipher, ws->plain_new, sizeof(ws->cipher),
			       NULL, 0,
			       ws->tag, sizeof(ws->tag), cc);
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
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
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
	CKINT(lc_kyber_ies_enc(&ws->pk, &ws->ct,
			       plain, ws->cipher, sizeof(plain),
			       NULL, 0,
			       ws->tag, sizeof(ws->tag),
			       cc, rng));

	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_dec(&ws->sk, &ws->ct,
			       ws->cipher, ws->plain_new, sizeof(ws->cipher),
			       NULL, 0,
			       ws->tag, sizeof(ws->tag), cc));
	if (memcmp(plain, ws->plain_new, sizeof(plain))) {
		printf("Error in decryption of IES\n");
		ret = 1;
		goto out;
	}

	/* 2nd enc/dec */
	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_enc(&ws->pk, &ws->ct2,
			       plain, ws->cipher2, sizeof(plain), NULL, 0,
			       ws->tag, sizeof(ws->tag),
			       cc, rng));

	lc_aead_zero(cc);
	CKINT(lc_kyber_ies_dec(&ws->sk, &ws->ct2,
			       ws->cipher2, ws->plain_new, sizeof(ws->cipher2),
			       NULL, 0,
			       ws->tag, sizeof(ws->tag), cc));
	if (memcmp(plain, ws->plain_new, sizeof(plain))){
		printf("Error in decryption of IES\n");
		ret = 1;
		goto out;
	}

	/* Check that produced data from 2nd enc is different to 1st enc */
	if (!memcmp(ws->ct.ct, ws->ct2.ct, sizeof(ws->ct.ct))){
		printf("Error: identical kyber ciphertexts\n");
		ret = 1;
		goto out;
	}
	if (!memcmp(ws->cipher, ws->cipher2, sizeof(ws->cipher))){
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
	ret += kyber_ies_nondeterministic();

	return ret;
}


LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kyber_ies_tester();
}
