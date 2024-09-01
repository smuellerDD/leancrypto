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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "compare.h"
#include "ext_headers.h"
#include "kyber_type.h"
#include "kyber_kem_tester.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "selftest_rng.h"
#include "timecop.h"
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

/********** Raw execution of operations for performance measurement ***********/
int _kyber_kem_enc_tester(int (*_lc_kyber_enc)(struct lc_kyber_ct *ct,
					       struct lc_kyber_ss *ss,
					       const struct lc_kyber_pk *pk,
					       struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_kyber_ct ct;
		struct lc_kyber_ss key_b;
	};
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	lc_disable_selftest();

#ifndef GENERATE_VECTORS
	// Encapsulation
	CKINT(_lc_kyber_enc(&ws->ct, &ws->key_b,
			    (const struct lc_kyber_pk *)&kyber_testvectors[0].pk,
			    selftest_rng));

out:
#else
	(void)_lc_kyber_enc;
#endif
	LC_RELEASE_MEM(ws);
	return ret;
}

int _kyber_kem_dec_tester(int (*_lc_kyber_dec)(struct lc_kyber_ss *ss,
					       const struct lc_kyber_ct *ct,
					       const struct lc_kyber_sk *sk))
{
	struct workspace {
		struct lc_kyber_ss key_a;
	};
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	lc_disable_selftest();

#ifndef GENERATE_VECTORS
	// Decapsulation
	CKINT(_lc_kyber_dec(
		&ws->key_a,
		(const struct lc_kyber_ct *)&kyber_testvectors[0].ct,
		(const struct lc_kyber_sk *)&kyber_testvectors[0].sk));

out:
#else
	(void)_lc_kyber_dec;
#endif
	LC_RELEASE_MEM(ws);
	return ret;
}

int _kyber_kem_keygen_tester(
	int (*_lc_kyber_keypair)(struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
				 struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;
	};
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	lc_disable_selftest();

	CKINT(_lc_kyber_keypair(&ws->pk, &ws->sk, selftest_rng));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

/***************************** Regression testing *****************************/
int _kyber_kem_tester(
	unsigned int rounds,
	int (*_lc_kyber_keypair)(struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
				 struct lc_rng_ctx *rng_ctx),
	int (*_lc_kyber_keypair_from_seed)(struct lc_kyber_pk *pk,
					   struct lc_kyber_sk *sk,
					   const uint8_t *seed, size_t seedlen),
	int (*_lc_kyber_enc)(struct lc_kyber_ct *ct, struct lc_kyber_ss *ss,
			     const struct lc_kyber_pk *pk,
			     struct lc_rng_ctx *rng_ctx),
	int (*_lc_kyber_dec)(struct lc_kyber_ss *ss,
			     const struct lc_kyber_ct *ct,
			     const struct lc_kyber_sk *sk))
{
	struct workspace {
		struct lc_kyber_pk pk, pk2;
		struct lc_kyber_sk sk, sk2;
		struct lc_kyber_ct ct;
		struct lc_kyber_ss key_a;
		struct lc_kyber_ss key_b;
		uint8_t buf[2 * LC_KYBER_SYMBYTES];
	};
	int ret = 0;
	unsigned int i, j, nvectors;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

#ifdef GENERATE_VECTORS
	printf("#ifndef KYBER_TESTVECTORS_H\n"
	       "#define KYBER_TESTVECTORS_H\n"
	       "#include \"kyber_type.h\"\n"
	       "struct kyber_testvector {\n"
	       "\tuint8_t pk[LC_CRYPTO_PUBLICKEYBYTES];\n"
	       "\tuint8_t sk[LC_CRYPTO_SECRETKEYBYTES];\n"
	       "\tuint8_t ct[LC_CRYPTO_CIPHERTEXTBYTES];\n"
	       "\tuint8_t ss[LC_CRYPTO_BYTES];\n"
	       "};\n\n"
	       "static const struct kyber_testvector kyber_testvectors[] =\n"
	       "{\n");
	nvectors = NTESTS;

	(void)_lc_kyber_keypair_from_seed;
#else
	nvectors = ARRAY_SIZE(kyber_testvectors);

	if (_lc_kyber_keypair_from_seed(&ws->pk, &ws->sk, ws->buf,
					sizeof(ws->buf))) {
		ret = 1;
		goto out;
	}
	if (_lc_kyber_keypair_from_seed(&ws->pk2, &ws->sk2, ws->buf,
					sizeof(ws->buf))) {
		ret = 1;
		goto out;
	}

	if (memcmp(ws->pk.pk, ws->pk2.pk, LC_CRYPTO_PUBLICKEYBYTES)) {
		printf("Public key mismatch for keygen from seed\n");
		ret = 1;
		goto out;
	}
	if (memcmp(ws->sk.sk, ws->sk2.sk, LC_CRYPTO_SECRETKEYBYTES)) {
		printf("Secret key mismatch for keygen from seed\n");
		ret = 1;
		goto out;
	}
#endif

	if (!rounds)
		rounds = nvectors;

	for (i = 0; i < rounds; i++) {
		// Key-pair generation
		CKINT(_lc_kyber_keypair(&ws->pk, &ws->sk, selftest_rng));

		// Encapsulation
		CKINT(_lc_kyber_enc(&ws->ct, &ws->key_b, &ws->pk,
				    selftest_rng));

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

		unpoison(ws->sk.sk, LC_CRYPTO_SECRETKEYBYTES);
		if (i < nvectors && memcmp(ws->sk.sk, kyber_testvectors[i].sk,
					   LC_CRYPTO_SECRETKEYBYTES)) {
			printf("Secret key mismatch at test vector %u\n", i);
			ret = 1;
			goto out;
		}

		unpoison(ws->ct.ct, LC_CRYPTO_CIPHERTEXTBYTES);
		if (i < nvectors && memcmp(ws->ct.ct, kyber_testvectors[i].ct,
					   LC_CRYPTO_CIPHERTEXTBYTES)) {
			printf("Ciphertext mismatch at test vector %u\n", i);
			ret = 1;
			goto out;
		}

		unpoison(ws->key_b.ss, LC_KYBER_SSBYTES);
		if (i < nvectors &&
		    memcmp(ws->key_b.ss, kyber_testvectors[i].ss,
			   LC_KYBER_SSBYTES)) {
			printf("Shared secret mismatch at test vector %u\n", i);
			ret = 1;
			goto out;
		}

		//printf("Sucessful validation of test vector %u\n", i);

		unpoison(ws->key_a.ss, LC_KYBER_SSBYTES);
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
	unsigned int i, j, nvectors;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

#ifdef GENERATE_VECTORS
	printf("#ifndef KYBER_KDF_TESTVECTORS_H\n"
	       "#define KYBER_KDF_TESTVECTORS_H\n"
	       "#include \"kyber_type.h\"\n"
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
		CKINT(_lc_kyber_keypair(&ws->pk, &ws->sk, selftest_rng));

		// Encapsulation
		CKINT(_lc_kyber_kdf_enc(&ws->ct, ws->key_b.ss, LC_KYBER_SSBYTES,
					&ws->pk, selftest_rng));

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
	LC_RELEASE_MEM(ws);
	return ret;
}
