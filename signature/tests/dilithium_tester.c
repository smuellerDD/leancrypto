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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dilithium_pack.h"
#include "dilithium_poly.h"
#include "dilithium_polyvec.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sha3.h"

#define MLEN 32
#define NVECTORS 50

#undef DILITHIUM_DEBUG

/*
 * Enable to generate vectors. When enabling this, invoke the application
 * which outputs the header file of dilithium_tester_vectors.h. This
 * vector file can be included and will be applied when this option
 * not defined any more.
 *
 * The generated data could be cross-compared with test/test_vectors2
 * from https://github.com/pq-crystals/dilithium when printing out the
 * full keys/signatures instead of the SHAKE'd versions.
 */
#undef GENERATE_VECTORS
#undef SHOW_SHAKEd_KEY

#ifndef GENERATE_VECTORS
#include "dilithium_tester_vectors.h"
#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

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

static const struct lc_rng dilithium_drng = {
	.generate	= randombytes,
	.seed		= randombytes_seed,
	.zero		= randombytes_zero,
};

int main(void)
{
	unsigned int i, j, k, l;
	struct lc_dilithium_pk pk;
	struct lc_dilithium_sk sk;
	struct lc_dilithium_sig sig;
	struct lc_dilithium_sig sig_tmp;
	uint8_t m[MLEN];
	uint8_t seed[LC_DILITHIUM_CRHBYTES];
	uint8_t buf[LC_DILITHIUM_SECRETKEYBYTES];
	poly c, tmp;
	polyvecl s, y, mat[LC_DILITHIUM_K];
	polyveck w, w1, w0, t1, t0, h;

	/*
	 * The testing is based on the fact that,
	 * - this "RNG" produces identical output
	 * - the signature generation is performed with deterministic
	 *   behavior (i.e. rng_ctx is NULL)
	 */
	struct lc_rng_ctx dilithium_rng =
		{ .rng = &dilithium_drng, .rng_state = NULL };
	unsigned int nvectors;

	(void)k;
	(void)l;

#ifdef GENERATE_VECTORS
	printf ("#ifndef DILITHIUM_TESTVECTORS_H\n"
		"#define DILITHIUM_TESTVECTORS_H\n"
		"#include \"lc_dilithium.h\"\n"
		"struct dilithium_testvector {\n"
		"\tuint8_t m[32];\n"
		"\tuint8_t pk[LC_DILITHIUM_PUBLICKEYBYTES];\n"
		"\tuint8_t sk[LC_DILITHIUM_SECRETKEYBYTES];\n"
		"\tuint8_t sig[LC_DILITHIUM_CRYPTO_BYTES];\n"
		"};\n\n"
		"static const struct dilithium_testvector dilithium_testvectors[] =\n"
		"{\n");
	nvectors = NVECTORS;
#else
	nvectors = ARRAY_SIZE(dilithium_testvectors);
#endif

	for (i = 0; i < nvectors; ++i) {
		lc_rng_generate(&dilithium_rng, NULL, 0, m, MLEN);
		lc_dilithium_keypair(&pk, &sk, &dilithium_rng);
		lc_dilithium_sign(&sig, m, MLEN, &sk, NULL /*dilithium_rng*/);

#ifdef GENERATE_VECTORS

		printf("\t{\n\t\t.m = {\n\t\t\t");
		for (j = 0; j < MLEN; ++j) {
			printf("0x%02x, ", m[j]);
			if (j && !((j+1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");

		printf("\t\t.pk = {\n\t\t\t");
		for (j = 0; j < LC_DILITHIUM_PUBLICKEYBYTES; ++j) {
			printf("0x%02x, ", pk.pk[j]);
			if (j && !((j+1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.sk = {\n\t\t\t");
		for (j = 0; j < LC_DILITHIUM_SECRETKEYBYTES; ++j) {
			printf("0x%02x, ", sk.sk[j]);
			if (j && !((j+1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n");
		printf("\t\t.sig = {\n\t\t\t");
		for (j = 0; j < LC_DILITHIUM_CRYPTO_BYTES; ++j) {
			printf("0x%02x, ", sig.sig[j]);
			if (j && !((j+1) % 8))
				printf("\n\t\t\t");
		}
		printf("},\n\t}, ");
#else
		if (memcmp(m, dilithium_testvectors[i].m, MLEN)) {
			printf("Message mismatch at test vector %u\n", i);
			return 1;
		}

		if (memcmp(pk.pk, dilithium_testvectors[i].pk,
			   LC_DILITHIUM_PUBLICKEYBYTES)) {
			printf("Public key mismatch at test vector %u\n", i);
			return 1;
		}
		if (memcmp(sk.sk, dilithium_testvectors[i].sk,
			   LC_DILITHIUM_SECRETKEYBYTES)) {
			printf("Secret key mismatch at test vector %u\n", i);
			return 1;
		}
		if (memcmp(sig.sig, dilithium_testvectors[i].sig,
			   LC_DILITHIUM_CRYPTO_BYTES)) {
			printf("Signature mismatch at test vector %u\n", i);
			return 1;
		}

		printf("Sucessful validation of test vector %u\n", i);

#ifdef SHOW_SHAKEd_KEY
		printf("count = %u\n", i);
		lc_shake(lc_shake256, pk.pk, LC_DILITHIUM_PUBLICKEYBYTES,
			 buf, 32);
		printf("pk = ");
		for (j = 0; j < 32; ++j)
			printf("%02x", buf[j]);
		printf("\n");
		lc_shake(lc_shake256, sk.sk, LC_DILITHIUM_SECRETKEYBYTES,
			 buf, 32);
		printf("sk = ");
		for (j = 0; j < 32; ++j)
			printf("%02x", buf[j]);
		printf("\n");
		lc_shake(lc_shake256, sig.sig, LC_DILITHIUM_CRYPTO_BYTES,
			 buf, 32);
		printf("sig = ");
		for (j = 0; j < 32; ++j)
			printf("%02x", buf[j]);
		printf("\n");
#endif
#endif

		if (lc_dilithium_verify(&sig, m, MLEN, &pk))
			fprintf(stderr,"Signature verification failed!\n");

		lc_rng_generate(&dilithium_rng, NULL, 0, seed, sizeof(seed));
#ifdef SHOW_SHAKEd_KEY
		printf("seed = ");
		for (j = 0; j < sizeof(seed); ++j)
			printf("%02x", seed[j]);
		printf("\n");
#endif

		polyvec_matrix_expand(mat, seed);
#ifdef DILITHIUM_DEBUG
		printf("A = ([");
		for (j = 0; j < LC_DILITHIUM_K; ++j) {
			for (k = 0; k < LC_DILITHIUM_L; ++k) {
				for (l = 0; l < LC_DILITHIUM_N; ++l) {
					printf("%8d", mat[j].vec[k].coeffs[l]);
					if (l < LC_DILITHIUM_N-1)
						printf(", ");
					else if (k < LC_DILITHIUM_L-1)
						printf("], [");
					else if (j < LC_DILITHIUM_K-1)
						printf("];\n     [");
					else
						printf("])\n");
				}
			}
		}
#endif

		polyvecl_uniform_eta(&s, seed, 0);

		polyeta_pack(buf, &s.vec[0]);
		polyeta_unpack(&tmp, buf);
		for (j = 0; j < LC_DILITHIUM_N; ++j)
			if (tmp.coeffs[j] != s.vec[0].coeffs[j])
				fprintf(stderr, "ERROR in polyeta_(un)pack!\n");

		if (polyvecl_chknorm(&s, LC_DILITHIUM_ETA+1))
			fprintf(stderr, "ERROR in polyvecl_chknorm(&s ,ETA+1)!\n");

#ifdef DILITHIUM_DEBUG
		printf("s = ([");
		for (j = 0; j < LC_DILITHIUM_L; ++j) {
			for (k = 0; k < LC_DILITHIUM_N; ++k) {
				printf("%3d", s.vec[j].coeffs[k]);
				if (k < LC_DILITHIUM_N-1)
					printf(", ");
				else if (j < LC_DILITHIUM_L-1)
					printf("],\n     [");
				else
					printf("])\n");
			}
		}
#endif

		polyvecl_uniform_gamma1(&y, seed, 0);

		polyz_pack(buf, &y.vec[0]);
		polyz_unpack(&tmp, buf);
		for (j = 0; j < LC_DILITHIUM_N; ++j)
			if (tmp.coeffs[j] != y.vec[0].coeffs[j])
				fprintf(stderr, "ERROR in polyz_(un)pack!\n");

		if(polyvecl_chknorm(&y, LC_DILITHIUM_GAMMA1+1))
			fprintf(stderr, "ERROR in polyvecl_chknorm(&y, GAMMA1)!\n");

#ifdef DILITHIUM_DEBUG
		printf("y = ([");
		for (j = 0; j < LC_DILITHIUM_L; ++j) {
			for (k = 0; k < LC_DILITHIUM_N; ++k) {
				printf("%8d", y.vec[j].coeffs[k]);
				if (k < LC_DILITHIUM_N-1)
					printf(", ");
				else if (j < LC_DILITHIUM_L-1)
					printf("],\n     [");
				else
					printf("])\n");
			}
		}
#endif

		polyvecl_ntt(&y);
		polyvec_matrix_pointwise_montgomery(&w, mat, &y);
		polyveck_reduce(&w);
		polyveck_invntt_tomont(&w);
		polyveck_caddq(&w);
		polyveck_decompose(&w1, &w0, &w);

		for (j = 0; j < LC_DILITHIUM_N; ++j) {
			tmp.coeffs[j] = w1.vec[0].coeffs[j]*2*LC_DILITHIUM_GAMMA2 + w0.vec[0].coeffs[j];
			if (tmp.coeffs[j] < 0)
				tmp.coeffs[j] += LC_DILITHIUM_Q;
			if (tmp.coeffs[j] != w.vec[0].coeffs[j])
				fprintf(stderr, "ERROR in poly_decompose!\n");
		}

		polyw1_pack(buf, &w1.vec[0]);
#if LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q-1)/32
		for (j = 0; j < LC_DILITHIUM_N/2; ++j) {
			tmp.coeffs[2*j+0] = buf[j] & 0xF;
			tmp.coeffs[2*j+1] = buf[j] >> 4;
			if(tmp.coeffs[2*j+0] != w1.vec[0].coeffs[2*j+0]
				|| tmp.coeffs[2*j+1] != w1.vec[0].coeffs[2*j+1])
				fprintf(stderr, "ERROR in polyw1_pack!\n");
		}
#endif

#if LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q-1)/32
		if (polyveck_chknorm(&w1, 16))
			fprintf(stderr, "ERROR in polyveck_chknorm(&w1, 16)!\n");
#elif LC_DILITHIUM_GAMMA2 == (LC_DILITHIUM_Q-1)/88
		if (polyveck_chknorm(&w1, 44))
			fprintf(stderr, "ERROR in polyveck_chknorm(&w1, 4)!\n");
#endif
		if (polyveck_chknorm(&w0, LC_DILITHIUM_GAMMA2 + 1))
			fprintf(stderr, "ERROR in polyveck_chknorm(&w0, GAMMA2+1)!\n");

#ifdef DILITHIUM_DEBUG
		printf("w1 = ([");
		for (j = 0; j < LC_DILITHIUM_K; ++j) {
			for (k = 0; k < LC_DILITHIUM_N; ++k) {
				printf("%2d", w1.vec[j].coeffs[k]);
				if (k < LC_DILITHIUM_N-1)
					printf(", ");
				else if(j < LC_DILITHIUM_K-1)
					printf("],\n      [");
				else
					printf("])\n");
			}
		}
		printf("w0 = ([");
		for (j = 0; j < LC_DILITHIUM_K; ++j) {
			for(k = 0; k < LC_DILITHIUM_N; ++k) {
				printf("%8d", w0.vec[j].coeffs[k]);
				if (k < LC_DILITHIUM_N-1)
					printf(", ");
				else if (j < LC_DILITHIUM_K-1)
					printf("],\n      [");
				else
					printf("])\n");
			}
		}
#endif

		polyveck_power2round(&t1, &t0, &w);

		for (j = 0; j < LC_DILITHIUM_N; ++j) {
			tmp.coeffs[j] = (t1.vec[0].coeffs[j] << LC_DILITHIUM_D) + t0.vec[0].coeffs[j];
			if (tmp.coeffs[j] != w.vec[0].coeffs[j])
				fprintf(stderr, "ERROR in poly_power2round!\n");
		}

		polyt1_pack(buf, &t1.vec[0]);
		polyt1_unpack(&tmp, buf);
		for (j = 0; j < LC_DILITHIUM_N; ++j) {
			if (tmp.coeffs[j] != t1.vec[0].coeffs[j])
				fprintf(stderr, "ERROR in polyt1_(un)pack!\n");
		}
		polyt0_pack(buf, &t0.vec[0]);
		polyt0_unpack(&tmp, buf);
		for (j = 0; j < LC_DILITHIUM_N; ++j) {
			if(tmp.coeffs[j] != t0.vec[0].coeffs[j])
				fprintf(stderr, "ERROR in polyt0_(un)pack!\n");
		}

		if (polyveck_chknorm(&t1, 1024))
			fprintf(stderr, "ERROR in polyveck_chknorm(&t1, 1024)!\n");
		if (polyveck_chknorm(&t0, (1U << (LC_DILITHIUM_D-1)) + 1))
			fprintf(stderr, "ERROR in polyveck_chknorm(&t0, (1 << (D-1)) + 1)!\n");

#ifdef DILITHIUM_DEBUG
		printf("t1 = ([");
		for (j = 0; j < LC_DILITHIUM_K; ++j) {
			for (k = 0; k < LC_DILITHIUM_N; ++k) {
				printf("%3d", t1.vec[j].coeffs[k]);
				if (k < LC_DILITHIUM_N-1)
					printf(", ");
				else if (j < LC_DILITHIUM_K-1)
					printf("],\n      [");
				else
					printf("])\n");
			}
		}
		printf("t0 = ([");
		for (j = 0; j < LC_DILITHIUM_K; ++j) {
			for(k = 0; k < LC_DILITHIUM_N; ++k) {
				printf("%5d", t0.vec[j].coeffs[k]);
				if (k < LC_DILITHIUM_N-1)
					printf(", ");
				else if (j < LC_DILITHIUM_K-1)
					printf("],\n      [");
				else
					printf("])\n");
			}
		}
#endif

		poly_challenge(&c, seed);
#ifdef DILITHIUM_DEBUG
		printf("c = [");
		for (j = 0; j < LC_DILITHIUM_N; ++j) {
			printf("%2d", c.coeffs[j]);
			if (j < LC_DILITHIUM_N-1)
				printf(", ");
			else
				printf("]\n");
		}
#endif

		polyveck_make_hint(&h, &w0, &w1);
		pack_sig(&sig_tmp, seed, &y, &h);
		unpack_sig(seed, &y, &w, &sig_tmp);
		if (memcmp(&h, &w, sizeof(h)))
			fprintf(stderr, "ERROR in (un)pack_sig!\n");
	}

#ifdef GENERATE_VECTORS
	printf("\n};\n");
	printf("#endif\n");
#endif
	return 0;
}
