/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "bike_internal.h"

#if (LC_BIKE_LEVEL == 1)
#include "bike_tester_vectors_l1.h"
#elif (LC_BIKE_LEVEL == 3)
#include "bike_tester_vectors_l3.h"
#elif (LC_BIKE_LEVEL == 5)
#include "bike_tester_vectors_l5.h"
#else
#error "Bad level, choose one of 1/3/5"
#endif

#include "compare.h"
#include "cpufeatures.h"
#include "static_rng.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

/*
 * Enable to generate vectors. When enabling this, invoke the application
 * which outputs the header file.
 */
#undef GENERATE_VECTORS
#define NTESTS 6

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

struct workspace {
	uint8_t seed[128];
	struct lc_bike_pk pk;
	struct lc_bike_sk sk;
	struct lc_bike_ct ct;
	struct lc_bike_ss ss, ss2;
};

static int bike_tester_one(const struct lc_bike_testvector *vector,
			   struct workspace *ws)
{
	struct lc_static_rng_data static_data;
	int ret, rc = 0;
	LC_STATIC_DRNG_ON_STACK(sdrng, &static_data);

#ifdef GENERATE_VECTORS
	(void)vector;
	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, ws->seed,
			      sizeof(ws->seed)));
	static_data.seed = ws->seed;
	static_data.seedlen = sizeof(ws->seed);
#else
	static_data.seed = vector->seed;
	static_data.seedlen = sizeof(vector->seed);
#endif

	CKINT(lc_bike_keypair(&ws->pk, &ws->sk, &sdrng));
	CKINT(lc_bike_enc_internal(&ws->ct, &ws->ss, &ws->pk, &sdrng));
	CKINT(lc_bike_dec(&ws->ss2, &ws->ct, &ws->sk));

#ifdef GENERATE_VECTORS
	unsigned int j;

	printf("\t{\n\t\t.seed = {\n\t\t\t");
	for (j = 0; j < sizeof(ws->seed); j++) {
		printf("0x%02x, ", ws->seed[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n");
	printf("\t\t.pk = {\n\t\t\t");
	for (j = 0; j < sizeof(struct lc_bike_pk); j++) {
		printf("0x%02x, ", ((uint8_t *)(&ws->pk))[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n");
	printf("\t\t.sk = {\n\t\t\t");
	for (j = 0; j < sizeof(struct lc_bike_sk); ++j) {
		printf("0x%02x, ", ((uint8_t *)(&ws->sk))[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n");
	printf("\t\t.ct = {\n\t\t\t");
	for (j = 0; j < sizeof(struct lc_bike_ct); ++j) {
		printf("0x%02x, ", ((uint8_t *)(&ws->ct))[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n");
	printf("\t\t.ss = {\n\t\t\t");
	for (j = 0; j < sizeof(struct lc_bike_ss); ++j) {
		printf("0x%02x, ", ((uint8_t *)(&ws->ss))[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n\t}, ");
#else
	rc += lc_compare((uint8_t *)&ws->pk, vector->pk, sizeof(ws->pk),
			 "BIKE PK");
	rc += lc_compare((uint8_t *)&ws->sk, vector->sk, sizeof(ws->sk),
			 "BIKE SK");

	rc += lc_compare((uint8_t *)&ws->ct, vector->ct, sizeof(ws->ct),
			 "BIKE Enc CT");
	rc += lc_compare((uint8_t *)&ws->ss, vector->ss, sizeof(ws->ss),
			 "BIKE Enc SS");

	rc += lc_compare((uint8_t *)&ws->ss2, vector->ss, sizeof(ws->ss2),
			 "BIKE Dec SS");
#endif

out:
	if (ret == -EOPNOTSUPP)
		ret = 77;
	return ret ? ret : rc;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	unsigned int i, count = ARRAY_SIZE(bike_test);
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, LC_BIKE_ALIGN_BYTES);

	(void)argv;

#ifdef GENERATE_VECTORS
	printf("#pragma once\n"
	       "#include \"bike_type.h\"\n"
	       "struct lc_bike_testvector {\n"
	       "\tuint8_t seed[128];\n"
	       "\tuint8_t pk[sizeof(struct lc_bike_pk)];\n"
	       "\tuint8_t sk[sizeof(struct lc_bike_sk)];\n"
	       "\tuint8_t ct[sizeof(struct lc_bike_ct)];\n"
	       "\tuint8_t ss[sizeof(struct lc_bike_ss)];\n"
	       "};\n\n"
	       "static const struct lc_bike_testvector bike_test[] =\n"
	       "{\n");
	count = NTESTS;
#endif

	/* Disable any accelerations when there is one parameter */
	if (argc > 1)
		lc_cpu_feature_disable();

	for (i = 0; i < count; i++) {
		ret = bike_tester_one(&bike_test[i], ws);
		if (ret)
			break;
	}

#ifdef GENERATE_VECTORS
	printf("\n};\n");
#endif

	/* Disable any accelerations when there is one parameter */
	if (argc > 1)
		lc_cpu_feature_enable();

	LC_RELEASE_MEM(ws);
	return ret;
}
