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

#include <stdio.h>

#include "binhexbin.h"
#include "lc_kyber.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "ret_checkers.h"

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

	for(i = 0; i < 8; ++i)
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
		0x8c, 0x4b, 0x57, 0xe2, 0x73, 0xd4, 0x8d, 0xc8,
		0x92, 0x86, 0x5a, 0x27, 0x68, 0x17, 0xdc, 0x14,
		0x3e, 0xc3, 0xd5, 0x81, 0x4d, 0x86, 0xe8, 0x9c,
		0x5c, 0xcd, 0x10, 0xe6, 0x79, 0x3f, 0x9f, 0xb8,
		0x61, 0xa5, 0x06, 0xec, 0xb6, 0x20, 0xa6, 0x48,
		0x4f, 0xd7, 0xe2, 0x14, 0xce, 0x0f, 0xdc, 0x2b
	};
	struct lc_kyber_pk pk;
	struct lc_kyber_sk sk;

	struct lc_kyber_ct ct;

	uint8_t cipher[sizeof(plain)];
	uint8_t plain_new[sizeof(plain)];
	uint8_t tag[16];

	int ret;

	struct lc_rng_ctx cshake_rng =
		{ .rng = &kyber_drng, .rng_state = NULL };

	CKINT(lc_kyber_keypair(&pk, &sk, &cshake_rng));

	CKINT(lc_kyber_ies_enc(&pk, &ct,
			       plain, cipher, sizeof(plain), NULL, 0,
			       tag, sizeof(tag),
			       &cshake_rng));

// 	bin2print(pk.pk, sizeof(pk.pk), stdout, "PK");
// 	bin2print(sk.sk, sizeof(sk.sk), stdout, "SK");
// 	bin2print(ct.ct, sizeof(ct.ct), stdout, "CT");
//
// 	bin2print(cipher, sizeof(cipher), stdout, "Ciphertext");
// 	bin2print(tag, sizeof(tag), stdout, "Tag");

	if (memcmp(cipher, exp_cipher, sizeof(exp_cipher))){
		printf("Error in encryption of IES\n");
		return 1;
	}

	CKINT(lc_kyber_ies_dec(&sk, &ct,
			       cipher, plain_new, sizeof(cipher), NULL, 0,
			       tag, sizeof(tag)));

	if (memcmp(plain, plain_new, sizeof(plain))){
		printf("Error in decryption of IES\n");
		return 1;
	}

	/* Modify the ciphertext -> integrity error */
	cipher[0] = (cipher[0] + 0x01) & 0xff;
	ret = lc_kyber_ies_dec(&sk, &ct,
			       cipher, plain_new, sizeof(cipher), NULL, 0,
			       tag, sizeof(tag));
	if (ret != -EBADMSG) {
		printf("Error in detecting authentication error\n");
		return 1;
	}

	ret = 0;

out:
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
	struct lc_kyber_pk pk;
	struct lc_kyber_sk sk;

	struct lc_kyber_ct ct;

	struct lc_kyber_ct ct2;

	uint8_t cipher[sizeof(plain)];
	uint8_t cipher2[sizeof(plain)];
	uint8_t plain_new[sizeof(plain)];
	uint8_t tag[16];

	int ret;

	CKINT(lc_kyber_keypair(&pk, &sk, lc_seeded_rng));

	/* First enc/dec */
	CKINT(lc_kyber_ies_enc(&pk, &ct,
			       plain, cipher, sizeof(plain), NULL, 0,
			       tag, sizeof(tag),
			       lc_seeded_rng));

	CKINT(lc_kyber_ies_dec(&sk, &ct,
			       cipher, plain_new, sizeof(cipher), NULL, 0,
			       tag, sizeof(tag)));
	if (memcmp(plain, plain_new, sizeof(plain))){
		printf("Error in decryption of IES\n");
		return 1;
	}

	/* 2nd enc/dec */
	CKINT(lc_kyber_ies_enc(&pk, &ct2,
			       plain, cipher2, sizeof(plain), NULL, 0,
			       tag, sizeof(tag),
			       lc_seeded_rng));

	CKINT(lc_kyber_ies_dec(&sk, &ct2,
			       cipher2, plain_new, sizeof(cipher2), NULL, 0,
			       tag, sizeof(tag)));
	if (memcmp(plain, plain_new, sizeof(plain))){
		printf("Error in decryption of IES\n");
		return 1;
	}

	/* Check that produced data from 2nd enc is different to 1st enc */
	if (!memcmp(ct.ct, ct2.ct, sizeof(ct.ct))){
		printf("Error: identical kyber ciphertexts\n");
		return 1;
	}
	if (!memcmp(cipher, cipher2, sizeof(cipher))){
		printf("Error: identical ciphertexts\n");
		return 1;
	}

out:
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = kyber_ies_determinisitic();
	ret += kyber_ies_nondeterministic();

	return ret;
}
