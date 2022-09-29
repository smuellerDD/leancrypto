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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lc_kyber.h"
#include "lc_sha3.h"
#include "ret_checkers.h"

/*
 * Enable to generate vectors. When enabling this, invoke the application
 * which outputs the header file of kyber_tester_vectors.h. This
 * vector file can be included and will be applied when this option
 * not defined any more.
 *
 * The generated data could be cross-compared with test_vectors*
 * from https://github.com/pq-crystals/kyber.
 */
#undef GENERATE_VECTORS
#undef DEBUG

#ifndef GENERATE_VECTORS
#if LC_KYBER_K == 2
#include "kyber_kem_tester_vectors_512.h"
#elif LC_KYBER_K == 3
#include "kyber_kem_tester_vectors_768.h"
#elif LC_KYBER_K == 4
#include "kyber_kem_tester_vectors_1024.h"
#endif
#endif

#define NTESTS 50

static uint32_t seed[32] = {
	3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,3,8,4,6,2,6,4,3,3,8,3,2,7,9,5
};
static uint32_t in[12];
static uint32_t out[8];
static int outleft = 0;

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static void surf(void)
{
	uint32_t t[12]; uint32_t x; uint32_t sum = 0;
	int r; int i; int loop;

	for (i = 0; i < 12; ++i)
		t[i] = in[i] ^ seed[12 + i];

	for (i = 0;i < 8; ++i)
		out[i] = seed[24 + i];

	x = t[11];
	for (loop = 0;loop < 2; ++loop) {
		for (r = 0;r < 16;++r) {
			sum += 0x9e3779b9;
			MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
			MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
			MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
		}
		for (i = 0;i < 8;++i)
			out[i] ^= t[i + 4];
	}
}

static int
randombytes(void *_state,
	    const uint8_t *addtl_input, size_t addtl_input_len,
	    uint8_t *x, size_t xlen)
{
	(void)_state;
	(void)addtl_input;
	(void)addtl_input_len;

	while (xlen > 0) {
		if (!outleft) {
			if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
			surf();
			outleft = 8;
		}
		*x = (uint8_t)out[--outleft];
		//printf("%02x", *x);
		++x;
		--xlen;
	}
	//printf("\n");

	return 0;
}

static int
randombytes2 (void *_state,
	     const uint8_t *addtl_input, size_t addtl_input_len,
	     uint8_t *x, size_t xlen)
{
	randombytes(_state, addtl_input, addtl_input_len, x, xlen);
	lc_hash(lc_sha3_256, x, xlen, x);
	return 0;
}

static int
randombytes_seed(void *_state,
		 const uint8_t *rng_seed, size_t seedlen,
		 const uint8_t *persbuf, size_t perslen)
{
	(void)_state;
	(void)rng_seed;
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

static const struct lc_rng kyber_drng2 = {
	.generate	= randombytes2,
	.seed		= randombytes_seed,
	.zero		= randombytes_zero,
};

int main(void)
{
	unsigned int i, j;
	struct lc_kyber_pk pk;
	struct lc_kyber_sk sk;
	struct lc_kyber_ct ct;
	struct lc_kyber_ss key_a;
	struct lc_kyber_ss key_b;
	int ret = 0;

	/*
	 * The testing is based on the fact that,
	 * - this "RNG" produces identical output
	 * - encapsulation was invoked with this RNG
	 */
	struct lc_rng_ctx kyber_rng =
		{ .rng = &kyber_drng, .rng_state = NULL };
	struct lc_rng_ctx kyber_rng2 =
		{ .rng = &kyber_drng2, .rng_state = NULL };
	unsigned int nvectors;


#ifdef GENERATE_VECTORS
	printf ("#ifndef KYBER_TESTVECTORS_H\n"
		"#define KYBER_TESTVECTORS_H\n"
		"#include \"lc_kyber.h\"\n"
		"struct kyber_testvector {\n"
		"\tuint8_t pk[LC_CRYPTO_PUBLICKEYBYTES];\n"
		"\tuint8_t sk[LC_CRYPTO_SECRETKEYBYTES];\n"
		"\tuint8_t ct[LC_CRYPTO_CIPHERTEXTBYTES];\n"
		"\tuint8_t ss[LC_CRYPTO_BYTES];\n"
		"};\n\n"
		"static const struct kyber_testvector kyber_testvectors[] =\n"
		"{\n");
	nvectors = NTESTS;
#else
	nvectors = ARRAY_SIZE(kyber_testvectors);
#endif

	for (i = 0; i < nvectors; i++) {
		// Key-pair generation
		CKINT(lc_kyber_keypair(&pk, &sk, &kyber_rng));

		// Encapsulation
		CKINT(lc_kyber_enc(&ct, key_b.ss, LC_KYBER_SSBYTES, &pk,
				   &kyber_rng2));

		// Decapsulation
		CKINT(lc_kyber_dec(key_a.ss, LC_KYBER_SSBYTES, &ct, &sk));

#ifdef DEBUG
		printf("Public Key: ");
		for (j = 0; j < LC_CRYPTO_PUBLICKEYBYTES; j++)
			printf("%02x", pk.pk[j]);
		printf("\n");
		printf("Secret Key: ");
		for (j = 0; j < LC_CRYPTO_SECRETKEYBYTES; j++)
			printf("%02x", sk.sk[j]);
		printf("\n");

		printf("Ciphertext: ");
		for (j = 0; j < LC_CRYPTO_CIPHERTEXTBYTES; j++)
			printf("%02x", ct.ct[j]);
		printf("\n");
		printf("Shared Secret B: ");
		for (j = 0; j < LC_CRYPTO_BYTES; j++)
			printf("%02x",key_b.ss[j]);
		printf("\n");

		printf("Shared Secret A: ");
		for (j = 0; j < LC_CRYPTO_BYTES; j++)
			printf("%02x",key_a.ss[j]);
		printf("\n");
#endif

#ifdef GENERATE_VECTORS

		printf("\t{\n\t\t.pk = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_PUBLICKEYBYTES; j++) {
			printf("0x%02x, ", pk.pk[j]);
			if (j && !((j+1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.sk = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_SECRETKEYBYTES; ++j) {
			printf("0x%02x, ", sk.sk[j]);
			if (j && !((j+1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.ct = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_CIPHERTEXTBYTES; ++j) {
			printf("0x%02x, ", ct.ct[j]);
			if (j && !((j+1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.ss = {\n\t\t\t");
		for (j = 0; j < LC_KYBER_SSBYTES; ++j) {
			printf("0x%02x, ", key_a.ss[j]);
			if (j && !((j+1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n\t}, ");
#else
		if (memcmp(pk.pk, kyber_testvectors[i].pk,
			   LC_CRYPTO_PUBLICKEYBYTES)) {
			printf("Public key mismatch at test vector %u\n", i);
			return 1;
		}
		if (memcmp(sk.sk, kyber_testvectors[i].sk,
			   LC_CRYPTO_SECRETKEYBYTES)) {
			printf("Secret key mismatch at test vector %u\n", i);
			return 1;
		}
		if (memcmp(ct.ct, kyber_testvectors[i].ct,
			   LC_CRYPTO_CIPHERTEXTBYTES)) {
			printf("Ciphertext mismatch at test vector %u\n", i);
			return 1;
		}
		if (memcmp(key_b.ss, kyber_testvectors[i].ss,
			   LC_KYBER_SSBYTES)) {
			printf("Shared secret mismatch at test vector %u\n", i);
			return 1;
		}

		printf("Sucessful validation of test vector %u\n", i);
#endif

		for (j = 0; j < LC_KYBER_SSBYTES; j++) {
			if(key_a.ss[j] != key_b.ss[j]) {
				fprintf(stderr, "ERROR\n");
				return 1;
			}
		}
	}

#ifdef GENERATE_VECTORS
	printf("\n};\n");
	printf("#endif\n");
#endif

out:
	return ret;
}
