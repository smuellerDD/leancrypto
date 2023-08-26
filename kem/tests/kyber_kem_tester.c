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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "ext_headers.h"
#include "kyber_kem_tester.h"
#include "lc_kyber.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

/*
 * Enable to generate vectors. When enabling this, invoke the application
 * which outputs the header file of kyber_tester_vectors.h. This
 * vector file can be included and will be applied when this option
 * not defined any more.
 *
 * The generated non-KDF data could be cross-compared with test_vectors* when
 * commenting out the final block "Decapsulation of invalid (random)
 * ciphertexts" in ref/test/test_vectors.c
 * from https://github.com/pq-crystals/kyber.
 */
#undef GENERATE_VECTORS
#undef DEBUG

#ifndef GENERATE_VECTORS
#if LC_KYBER_K == 2
#include "kyber_kem_tester_vectors_512.h"
#include "kyber_kem_kdf_tester_vectors_512.h"
#elif LC_KYBER_K == 3
#include "kyber_kem_tester_vectors_768.h"
#include "kyber_kem_kdf_tester_vectors_768.h"
#elif LC_KYBER_K == 4
#include "kyber_kem_tester_vectors_1024.h"
#include "kyber_kem_kdf_tester_vectors_1024.h"
#endif
#endif

#define NTESTS 50

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct lc_hash_ctx *rng_hash_ctx = NULL;

static int randombytes(void *_state, const uint8_t *addtl_input,
		       size_t addtl_input_len, uint8_t *out, size_t outlen)
{
	(void)addtl_input;
	(void)addtl_input_len;
	(void)_state;

	if (!rng_hash_ctx) {
		int ret = lc_hash_alloc(lc_shake128, &rng_hash_ctx);

		if (ret)
			return ret;

		lc_hash_init(rng_hash_ctx);
	}

	lc_hash_set_digestsize(rng_hash_ctx, outlen);
	lc_hash_final(rng_hash_ctx, out);

	return 0;
}

static int randombytes_seed(void *_state, const uint8_t *rng_seed,
			    size_t seedlen, const uint8_t *persbuf,
			    size_t perslen)
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
	.generate = randombytes,
	.seed = randombytes_seed,
	.zero = randombytes_zero,
};

int _kyber_kem_tester(unsigned int rounds,
		      int (*_lc_kyber_keypair)(struct lc_kyber_pk *pk,
					       struct lc_kyber_sk *sk,
					       struct lc_rng_ctx *rng_ctx),
		      int (*_lc_kyber_enc)(struct lc_kyber_ct *ct,
					   struct lc_kyber_ss *ss,
					   const struct lc_kyber_pk *pk,
					   struct lc_rng_ctx *rng_ctx),
		      int (*_lc_kyber_dec)(struct lc_kyber_ss *ss,
					   const struct lc_kyber_ct *ct,
					   const struct lc_kyber_sk *sk))
{
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;
		struct lc_kyber_ct ct;
		struct lc_kyber_ss key_a;
		struct lc_kyber_ss key_b;
	};
	int ret = 0;
	unsigned int i, j;

	/*
	 * The testing is based on the fact that,
	 * - this "RNG" produces identical output
	 * - encapsulation was invoked with this RNG
	 */
	struct lc_rng_ctx kyber_rng = { .rng = &kyber_drng, .rng_state = NULL };
	unsigned int nvectors;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* Zeroize RNG state */
	lc_hash_init(rng_hash_ctx);

#ifdef GENERATE_VECTORS
	printf("#ifndef KYBER_TESTVECTORS_H\n"
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

	if (!rounds)
		rounds = nvectors;

	for (i = 0; i < rounds; i++) {
		// Key-pair generation
		CKINT(_lc_kyber_keypair(&ws->pk, &ws->sk, &kyber_rng));

		// Encapsulation
		CKINT(_lc_kyber_enc(&ws->ct, &ws->key_b, &ws->pk, &kyber_rng));

		// Decapsulation
		CKINT(_lc_kyber_dec(&ws->key_a, &ws->ct, &ws->sk));

#ifdef DEBUG
		printf("Public Key: ");
		for (j = 0; j < LC_CRYPTO_PUBLICKEYBYTES; j++)
			printf("%02x", ws->pk.pk[j]);
		printf("\n");
		printf("Secret Key: ");
		for (j = 0; j < LC_CRYPTO_SECRETKEYBYTES; j++)
			printf("%02x", ws->sk.sk[j]);
		printf("\n");

		printf("Ciphertext: ");
		for (j = 0; j < LC_CRYPTO_CIPHERTEXTBYTES; j++)
			printf("%02x", ws->ct.ct[j]);
		printf("\n");
		printf("Shared Secret B: ");
		for (j = 0; j < LC_CRYPTO_BYTES; j++)
			printf("%02x", ws->key_b.ss[j]);
		printf("\n");

		printf("Shared Secret A: ");
		for (j = 0; j < LC_CRYPTO_BYTES; j++)
			printf("%02x", ws->key_a.ss[j]);
		printf("\n");
#endif

#ifdef GENERATE_VECTORS

		printf("\t{\n\t\t.pk = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_PUBLICKEYBYTES; j++) {
			printf("0x%02x, ", ws->pk.pk[j]);
			if (j && !((j + 1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.sk = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_SECRETKEYBYTES; ++j) {
			printf("0x%02x, ", ws->sk.sk[j]);
			if (j && !((j + 1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.ct = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_CIPHERTEXTBYTES; ++j) {
			printf("0x%02x, ", ws->ct.ct[j]);
			if (j && !((j + 1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.ss = {\n\t\t\t");
		for (j = 0; j < LC_KYBER_SSBYTES; ++j) {
			printf("0x%02x, ", ws->key_a.ss[j]);
			if (j && !((j + 1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n\t}, ");
#else
		if (i < nvectors && memcmp(ws->pk.pk, kyber_testvectors[i].pk,
					   LC_CRYPTO_PUBLICKEYBYTES)) {
			printf("Public key mismatch at test vector %u\n", i);
			ret = 1;
			goto out;
		}
		if (i < nvectors && memcmp(ws->sk.sk, kyber_testvectors[i].sk,
					   LC_CRYPTO_SECRETKEYBYTES)) {
			printf("Secret key mismatch at test vector %u\n", i);
			ret = 1;
			goto out;
		}
		if (i < nvectors && memcmp(ws->ct.ct, kyber_testvectors[i].ct,
					   LC_CRYPTO_CIPHERTEXTBYTES)) {
			printf("Ciphertext mismatch at test vector %u\n", i);
			ret = 1;
			goto out;
		}
		if (i < nvectors &&
		    memcmp(ws->key_b.ss, kyber_testvectors[i].ss,
			   LC_KYBER_SSBYTES)) {
			printf("Shared secret mismatch at test vector %u\n", i);
			ret = 1;
			goto out;
		}

		//printf("Sucessful validation of test vector %u\n", i);

		for (j = 0; j < LC_KYBER_SSBYTES; j++) {
			if (ws->key_a.ss[j] != ws->key_b.ss[j]) {
				printf("ERROR\n");
				ret = 1;
				goto out;
			}
		}
#endif
	}

#ifdef GENERATE_VECTORS
	printf("\n};\n");
	printf("#endif\n");
#endif

out:
	lc_hash_zero_free(rng_hash_ctx);
	rng_hash_ctx = NULL;
	LC_RELEASE_MEM(ws);
	return ret;
}

int _kyber_kem_kdf_tester(
	unsigned int rounds,
	int (*_lc_kyber_keypair)(struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
				 struct lc_rng_ctx *rng_ctx),
	int (*_lc_kyber_kdf_enc)(struct lc_kyber_ct *ct, uint8_t *ss,
				 size_t ss_len, const struct lc_kyber_pk *pk,
				 struct lc_rng_ctx *rng_ctx),
	int (*_lc_kyber_kdf_dec)(uint8_t *ss, size_t ss_len,
				 const struct lc_kyber_ct *ct,
				 const struct lc_kyber_sk *sk))
{
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;
		struct lc_kyber_ct ct;
		struct lc_kyber_ss key_a;
		struct lc_kyber_ss key_b;
	};
	int ret = 0;
	unsigned int i, j;

	/*
	 * The testing is based on the fact that,
	 * - this "RNG" produces identical output
	 * - encapsulation was invoked with this RNG
	 */
	struct lc_rng_ctx kyber_rng = { .rng = &kyber_drng, .rng_state = NULL };
	unsigned int nvectors;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/* Zeroize RNG state */
	lc_hash_init(rng_hash_ctx);

#ifdef GENERATE_VECTORS
	printf("#ifndef KYBER_KDF_TESTVECTORS_H\n"
	       "#define KYBER_KDF_TESTVECTORS_H\n"
	       "#include \"lc_kyber.h\"\n"
	       "struct kyber_kdf_testvector {\n"
	       "\tuint8_t pk[LC_CRYPTO_PUBLICKEYBYTES];\n"
	       "\tuint8_t sk[LC_CRYPTO_SECRETKEYBYTES];\n"
	       "\tuint8_t ct[LC_CRYPTO_CIPHERTEXTBYTES];\n"
	       "\tuint8_t ss[LC_CRYPTO_BYTES];\n"
	       "};\n\n"
	       "static const struct kyber_kdf_testvector kyber_kdf_testvectors[] =\n"
	       "{\n");
	nvectors = NTESTS;
#else
	nvectors = ARRAY_SIZE(kyber_testvectors);
#endif

	if (!rounds)
		rounds = nvectors;

	for (i = 0; i < rounds; i++) {
		// Key-pair generation
		CKINT(_lc_kyber_keypair(&ws->pk, &ws->sk, &kyber_rng));

		// Encapsulation
		CKINT(_lc_kyber_kdf_enc(&ws->ct, ws->key_b.ss, LC_KYBER_SSBYTES,
					&ws->pk, &kyber_rng));

		// Decapsulation
		CKINT(_lc_kyber_kdf_dec(ws->key_a.ss, LC_KYBER_SSBYTES, &ws->ct,
					&ws->sk));

#ifdef DEBUG
		printf("Public Key: ");
		for (j = 0; j < LC_CRYPTO_PUBLICKEYBYTES; j++)
			printf("%02x", ws->pk.pk[j]);
		printf("\n");
		printf("Secret Key: ");
		for (j = 0; j < LC_CRYPTO_SECRETKEYBYTES; j++)
			printf("%02x", ws->sk.sk[j]);
		printf("\n");

		printf("Ciphertext: ");
		for (j = 0; j < LC_CRYPTO_CIPHERTEXTBYTES; j++)
			printf("%02x", ws->ct.ct[j]);
		printf("\n");
		printf("Shared Secret B: ");
		for (j = 0; j < LC_CRYPTO_BYTES; j++)
			printf("%02x", ws->key_b.ss[j]);
		printf("\n");

		printf("Shared Secret A: ");
		for (j = 0; j < LC_CRYPTO_BYTES; j++)
			printf("%02x", ws->key_a.ss[j]);
		printf("\n");
#endif

#ifdef GENERATE_VECTORS

		printf("\t{\n\t\t.pk = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_PUBLICKEYBYTES; j++) {
			printf("0x%02x, ", ws->pk.pk[j]);
			if (j && !((j + 1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.sk = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_SECRETKEYBYTES; ++j) {
			printf("0x%02x, ", ws->sk.sk[j]);
			if (j && !((j + 1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.ct = {\n\t\t\t");
		for (j = 0; j < LC_CRYPTO_CIPHERTEXTBYTES; ++j) {
			printf("0x%02x, ", ws->ct.ct[j]);
			if (j && !((j + 1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.ss = {\n\t\t\t");
		for (j = 0; j < LC_KYBER_SSBYTES; ++j) {
			printf("0x%02x, ", ws->key_a.ss[j]);
			if (j && !((j + 1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n\t}, ");
#else
		if (i < nvectors &&
		    memcmp(ws->pk.pk, kyber_kdf_testvectors[i].pk,
			   LC_CRYPTO_PUBLICKEYBYTES)) {
			printf("KDF Public key mismatch at test vector %u\n",
			       i);
			ret = 1;
			goto out;
		}
		if (i < nvectors &&
		    memcmp(ws->sk.sk, kyber_kdf_testvectors[i].sk,
			   LC_CRYPTO_SECRETKEYBYTES)) {
			printf("KDF Secret key mismatch at test vector %u\n",
			       i);
			ret = 1;
			goto out;
		}
		if (i < nvectors &&
		    memcmp(ws->ct.ct, kyber_kdf_testvectors[i].ct,
			   LC_CRYPTO_CIPHERTEXTBYTES)) {
			printf("KDF Ciphertext mismatch at test vector %u\n",
			       i);
			ret = 1;
			goto out;
		}
		if (i < nvectors &&
		    memcmp(ws->key_b.ss, kyber_kdf_testvectors[i].ss,
			   LC_KYBER_SSBYTES)) {
			printf("KDF Shared secret mismatch at test vector %u\n",
			       i);
			ret = 1;
			goto out;
		}

		//printf("Sucessful validation of test vector %u\n", i);

		for (j = 0; j < LC_KYBER_SSBYTES; j++) {
			if (ws->key_a.ss[j] != ws->key_b.ss[j]) {
				printf("ERROR\n");
				ret = 1;
				goto out;
			}
		}
#endif
	}

#ifdef GENERATE_VECTORS
	printf("\n};\n");
	printf("#endif\n");
#endif

out:
	lc_hash_zero_free(rng_hash_ctx);
	rng_hash_ctx = NULL;
	LC_RELEASE_MEM(ws);
	return ret;
}
