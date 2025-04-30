/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include "hqc_internal.h"
#include "shake_prng.h"

#if (LC_HQC_TYPE == 128)
#include "hqc_tester_vectors_128.h"
#elif (LC_HQC_TYPE == 192)
#include "hqc_tester_vectors_192.h"
#elif (LC_HQC_TYPE == 256)
#include "hqc_tester_vectors_256.h"
#else
#error "Bad level, choose one of 128/192/256"
#endif

#include "compare.h"
#include "cpufeatures.h"
#include "lc_sha3.h"
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
	struct lc_hqc_pk pk;
	struct lc_hqc_sk sk;
	struct lc_hqc_ct ct;
	struct lc_hqc_ss ss, ss2;
};

/********************************* Test DRNG **********************************/

#define LC_SELFTEST_SHAKE256_DRNG_STATE_SIZE (LC_SHAKE_256_CTX_SIZE)
#define LC_SELFTEST_SHAKE256_DRNG_CTX_SIZE                                     \
	(sizeof(struct lc_rng) + LC_SELFTEST_SHAKE256_DRNG_STATE_SIZE)

extern const struct lc_rng *lc_selftest_shake256_drng;

#define LC_SELFTEST_SHAKE256_HASH_SET_CTX(name) LC_SHAKE_256_CTX((name))

#define LC_SELFTEST_SHAKE256_RNG_CTX(name)                                     \
	LC_RNG_CTX(name, lc_selftest_shake256_drng);                           \
	LC_SELFTEST_SHAKE256_HASH_SET_CTX(                                     \
		(struct lc_hash_ctx *)name->rng_state);                        \
	lc_rng_zero(name);                                                     \
	lc_hash_init(name->rng_state)

/*
 * The testing is based on the fact that,
 * - this "RNG" produces identical output
 *
 * WARNING: This RNG state is NOT meant to be used for any other purpose than
 * self tests!
 */
#define LC_SELFTEST_SHAKE256_DRNG_CTX_ON_STACK(name)                           \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		LC_ALIGNED_BUFFER(name##_ctx_buf,                              \
				  LC_SELFTEST_SHAKE256_DRNG_CTX_SIZE,          \
				  LC_HASH_COMMON_ALIGNMENT);                   \
	struct lc_rng_ctx *name = (struct lc_rng_ctx *)name##_ctx_buf;         \
	LC_SELFTEST_SHAKE256_RNG_CTX(name);                                    \
	_Pragma("GCC diagnostic pop")

/*
 * The selftest DRNG is a SHAKE256 state that is initialized to a zero state.
 * The Keccak squeeze operation generates data from the SHAKE state.
 */

static int selftest_rng_gen(void *_state, const uint8_t *addtl_input,
			    size_t addtl_input_len, uint8_t *out, size_t outlen)
{
	struct lc_hash_ctx *state = _state;

	(void)addtl_input;
	(void)addtl_input_len;

	lc_hash_set_digestsize(state, outlen);
	lc_hash_final(state, out);

	return 0;
}

static int selftest_rng_seed(void *_state, const uint8_t *seed, size_t seedlen,
			     const uint8_t *persbuf, size_t perslen)
{
	static const uint8_t domain = LC_HQC_PRNG_DOMAIN;
	struct lc_hash_ctx *state = _state;

	if (!state)
		return -EINVAL;

	lc_hash_init(state);
	lc_hash_update(state, seed, seedlen);
	lc_hash_update(state, persbuf, perslen);
	lc_hash_update(state, &domain, sizeof(domain));

	return 0;
}

static void selftest_rng_zero(void *_state)
{
	struct lc_hash_ctx *state = _state;

	if (!state)
		return;

	lc_hash_zero(state);
}

static const struct lc_rng _lc_selftest_shake256_drng = {
	.generate = selftest_rng_gen,
	.seed = selftest_rng_seed,
	.zero = selftest_rng_zero,
};
const struct lc_rng *lc_selftest_shake256_drng = &_lc_selftest_shake256_drng;

static int hqc_tester_one(const struct lc_hqc_testvector *vector,
			  struct workspace *ws)
{
	int ret, rc = 0;
	LC_SELFTEST_SHAKE256_DRNG_CTX_ON_STACK(sdrng);

#ifdef GENERATE_VECTORS
	(void)vector;
	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, ws->seed,
			      sizeof(ws->seed)));
	CKINT(lc_rng_seed(sdrng, ws->seed, sizeof(ws->seed), NULL, 0));
#else
	CKINT(lc_rng_seed(sdrng, vector->seed, sizeof(vector->seed), NULL, 0));
#endif

	CKINT_LOG(lc_hqc_keypair(&ws->pk, &ws->sk, sdrng),
		  "HQC keypair failed\n");
	CKINT_LOG(lc_hqc_enc_internal(&ws->ct, &ws->ss, &ws->pk, sdrng),
		  "HQC encapsulate failed\n");
	CKINT_LOG(lc_hqc_dec(&ws->ss2, &ws->ct, &ws->sk),
		  "HQC decapsulate failed\n");

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
	for (j = 0; j < sizeof(struct lc_hqc_pk); j++) {
		printf("0x%02x, ", ((uint8_t *)(&ws->pk))[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n");
	printf("\t\t.sk = {\n\t\t\t");
	for (j = 0; j < sizeof(struct lc_hqc_sk); ++j) {
		printf("0x%02x, ", ((uint8_t *)(&ws->sk))[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n");
	printf("\t\t.ct = {\n\t\t\t");
	for (j = 0; j < sizeof(struct lc_hqc_ct); ++j) {
		printf("0x%02x, ", ((uint8_t *)(&ws->ct))[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n");
	printf("\t\t.ss = {\n\t\t\t");
	for (j = 0; j < sizeof(struct lc_hqc_ss); ++j) {
		printf("0x%02x, ", ((uint8_t *)(&ws->ss))[j]);
		if (j && !((j + 1) % 8))
			printf("\n\t\t\t");
	}
	printf("},\n\t}, ");
#else
	rc += lc_compare((uint8_t *)&ws->pk, vector->pk, sizeof(ws->pk),
			 "HQC PK");
	rc += lc_compare((uint8_t *)&ws->sk, vector->sk, sizeof(ws->sk),
			 "HQC SK");

	rc += lc_compare((uint8_t *)&ws->ct, vector->ct, sizeof(ws->ct),
			 "HQC Enc CT");
	rc += lc_compare((uint8_t *)&ws->ss, vector->ss, sizeof(ws->ss),
			 "HQC Enc SS");

	rc += lc_compare((uint8_t *)&ws->ss2, vector->ss, sizeof(ws->ss2),
			 "HQC Dec SS");
#endif

out:
	if (ret == -EOPNOTSUPP)
		ret = 77;
	return ret ? ret : rc;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	unsigned int i, count = ARRAY_SIZE(hqc_test);
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, LC_HQC_ALIGN_BYTES);

	(void)argv;

#ifdef GENERATE_VECTORS
	printf("#pragma once\n"
	       "#include \"hqc_type.h\"\n"
	       "struct lc_hqc_testvector {\n"
	       "\tuint8_t seed[128];\n"
	       "\tuint8_t pk[sizeof(struct lc_hqc_pk)];\n"
	       "\tuint8_t sk[sizeof(struct lc_hqc_sk)];\n"
	       "\tuint8_t ct[sizeof(struct lc_hqc_ct)];\n"
	       "\tuint8_t ss[sizeof(struct lc_hqc_ss)];\n"
	       "};\n\n"
	       "static const struct lc_hqc_testvector hqc_test[] =\n"
	       "{\n");
	count = NTESTS;
#endif

	/* Disable any accelerations when there is one parameter */
	if (argc > 1)
		lc_cpu_feature_disable();

	for (i = 0; i < count; i++) {
		ret = hqc_tester_one(&hqc_test[i], ws);
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
