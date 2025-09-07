/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "alignment.h"
#include "build_bug_on.h"
#include "compare.h"
#include "lc_xdrbg.h"
#include "timecop.h"
#include "ret_checkers.h"
#include "test_helper_common.h"
#include "visibility.h"

static int xdrbg256_drng_selftest(struct lc_rng_ctx *xdrbg256_ctx)
{
	struct lc_xdrbg_drng_state *state = xdrbg256_ctx->rng_state;
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp1[] = {
		0x1a, 0xd2, 0xcb, 0x76, 0x3c, 0x71, 0x6d, 0xf0, 0x79, 0x2c,
		0xc0, 0x69, 0x7d, 0x56, 0x6a, 0x65, 0xb8, 0x36, 0xbe, 0x7d,
		0x09, 0x12, 0x7c, 0x65, 0x47, 0xfc, 0x30, 0x58, 0xaa, 0x24,
		0x39, 0x52, 0x29, 0xea, 0xce, 0x43, 0xdf, 0x16, 0x2c, 0x4f,
		0x1a, 0xed, 0xbd, 0x3f, 0xf5, 0x8e, 0xe6, 0x4d, 0x93, 0x07,
		0x3d, 0x7f, 0x3d, 0xd2, 0x50, 0x3c, 0xae, 0x04, 0x4a, 0x87,
		0x2c, 0x90, 0x30, 0xd4, 0x8e, 0xef, 0x5d, 0x53, 0x0f, 0xb2,
		0xdb, 0xec, 0x16, 0x39, 0x5a, 0xb5, 0x9a, 0xdc, 0x9d, 0x01,
		0x7e, 0xe2, 0xac, 0x7c, 0xe4, 0x3d, 0xfd, 0x93, 0xa6, 0x6c,
		0xc1, 0x22, 0x26, 0x64, 0xa0, 0x43, 0x52, 0x51, 0xf9, 0xb5,
		0xa4, 0x91, 0x54, 0x08, 0xf8, 0x8f, 0x16, 0x85, 0x54, 0xc0,
		0x9d, 0xce, 0xc9, 0xd5, 0xd7, 0xa9, 0x51, 0xc0, 0x06, 0x0c,
		0x04, 0x95, 0xcf, 0x7d, 0x27, 0x00, 0x7e, 0x48, 0x6d, 0x2e,
		0xbc, 0xf8, 0xa3, 0x71, 0x3d, 0xb0, 0x2b, 0x75, 0x2a, 0x48,
		0x1a, 0xd3, 0xed, 0xc9, 0xa3, 0x80, 0x88, 0x03, 0xc0, 0x27,
		0x75, 0xcc, 0xf5, 0xda, 0x56, 0x8d, 0x83, 0x36, 0xe6, 0x90,
		0x9c, 0xd5, 0x82, 0xfa, 0x70, 0xe9, 0xbf, 0x61, 0xec, 0x97,
		0xcc, 0xdd, 0xdc, 0x4e, 0xe1, 0x64, 0x9f, 0x1e, 0xb3, 0xfa,
		0x97, 0xa7, 0x02, 0x0a, 0x28, 0x01, 0x19, 0xd0, 0x45, 0xe9,
		0x21, 0x74, 0x52, 0x1a, 0xac, 0x5f, 0x58, 0x7c, 0x02, 0x47,
		0x45, 0x06, 0x17, 0x71, 0xc5, 0x2b, 0x0f, 0xa9, 0xed, 0x5c,
		0xd1, 0x46, 0x63, 0x57, 0xb5, 0x6a, 0x5c, 0x95, 0xd1, 0xa4,
		0xdf, 0x61, 0x62, 0x39, 0x41, 0x47, 0xb1, 0x4e, 0x91, 0x7c,
		0x50, 0x1f, 0xc0, 0x48, 0x42, 0xb6, 0xea, 0x16, 0x4c, 0x50,
		0x29, 0x12, 0xd0, 0x1c, 0x39, 0x9f, 0x79, 0x23, 0x63, 0x4f,
		0x9e, 0xa2, 0x56, 0x57, 0x26, 0xb2, 0xd3, 0xb3, 0xcc, 0xfe,
		0x58, 0x60, 0x0c, 0x5b, 0x59, 0x00, 0xff, 0xe2, 0xa5, 0x5a,
		0x50, 0x44, 0x02, 0x55, 0x6e, 0x87, 0x4f, 0x01, 0x50, 0x9a,
		0xd4, 0x0b, 0x96, 0x56, 0xb7, 0x6f, 0x13, 0x9d, 0xd7, 0x05,
		0xa4, 0xfb, 0xe7, 0xcc, 0x76, 0x94, 0x4b, 0x19, 0xc6, 0xc7,
		0xda, 0x0f, 0x88, 0x96, 0xb3, 0x9f, 0xbf, 0x6e, 0x46, 0x72,
		0xeb, 0xa9, 0x23, 0xaa, 0xf8, 0x6a, 0xb2, 0xfd, 0x01, 0xef,
		0x76, 0xf8, 0x9d, 0x29, 0x6e, 0xe2, 0x9f, 0xcc, 0xab, 0xc2,
		0x60, 0x7b, 0x8f, 0xae, 0x58, 0xe1, 0x9c, 0x79, 0x20, 0x85,
		0x66, 0xe3, 0x93, 0xd7, 0x7f
	};
	static const uint8_t exp83[] = { 0x39, 0x2b, 0x18, 0x96, 0x45,
					 0x81, 0x86, 0x84, 0xcf };
	static const uint8_t exp84[] = { 0xf0, 0x85, 0xd6, 0xc8, 0xd1,
					 0x76, 0xd7, 0x12, 0x39 };
	uint8_t act1[sizeof(exp1)] __align(sizeof(uint32_t)) = { 0 };
	uint8_t act2[sizeof(exp83)] __align(sizeof(uint32_t));
	uint8_t compare1[LC_XDRBG256_DRNG_KEYSIZE + sizeof(exp1)];
	int ret = 0;
	uint8_t encode;
	LC_HASH_CTX_ON_STACK(xdrbg256_compare, lc_shake256);

	printf("XDRBG256 ctx len %lu\n",
	       (unsigned long)LC_XDRBG256_DRNG_CTX_SIZE);

	/* Check the XDRBG operation */
	lc_rng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg256_ctx, NULL, 0, act1, sizeof(act1));
	ret += lc_compare(act1, exp1, sizeof(act1), "SHAKE DRNG");
	lc_rng_zero(xdrbg256_ctx);

	/* Verify the seeding operation to generate proper state */
	/* Prepare the state in the DRNG */
	lc_rng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	/* Prepare the state with native SHAKE operations */
	if (lc_hash_init(xdrbg256_compare))
		return 1;
	unpoison(seed, sizeof(seed));
	lc_hash_update(xdrbg256_compare, seed, sizeof(seed));
	encode = 0;
	lc_hash_update(xdrbg256_compare, &encode, sizeof(encode));
	lc_hash_set_digestsize(xdrbg256_compare, LC_XDRBG256_DRNG_KEYSIZE);
	lc_hash_final(xdrbg256_compare, compare1);
	unpoison(state->v, LC_XDRBG256_DRNG_KEYSIZE);
	ret += lc_compare(compare1, state->v, LC_XDRBG256_DRNG_KEYSIZE,
			  "SHAKE DRNG state generation");

	/* Verify the generate operation */
	/* Use the already generated state from above */

	/* First loop iteration */
	if (lc_hash_init(xdrbg256_compare))
		return 1;
	lc_hash_update(xdrbg256_compare, compare1, LC_XDRBG256_DRNG_KEYSIZE);
	encode = 2 * 85;
	lc_hash_update(xdrbg256_compare, &encode, sizeof(encode));
	/* First loop iteration: generate key */
	lc_hash_set_digestsize(xdrbg256_compare, LC_XDRBG256_DRNG_KEYSIZE);
	lc_hash_final(xdrbg256_compare, compare1);
	/* First loop iteratipn: generate data */
	lc_hash_set_digestsize(xdrbg256_compare, LC_XDRBG256_DRNG_MAX_CHUNK);
	lc_hash_final(xdrbg256_compare, compare1 + LC_XDRBG256_DRNG_KEYSIZE);

	/* 2nd loop round as output size is larger than chunk size */
	if (lc_hash_init(xdrbg256_compare))
		return 1;
	lc_hash_update(xdrbg256_compare, compare1, LC_XDRBG256_DRNG_KEYSIZE);
	encode = 2 * 85;
	lc_hash_update(xdrbg256_compare, &encode, sizeof(encode));
	/* Second loop iteratipn: generate key */
	lc_hash_set_digestsize(xdrbg256_compare, LC_XDRBG256_DRNG_KEYSIZE);
	lc_hash_final(xdrbg256_compare, compare1);
	/* Second loop iteratipn: generate data */
	lc_hash_set_digestsize(xdrbg256_compare,
			       sizeof(compare1) - LC_XDRBG256_DRNG_MAX_CHUNK -
				       LC_XDRBG256_DRNG_KEYSIZE);
	lc_hash_final(xdrbg256_compare, compare1 + LC_XDRBG256_DRNG_MAX_CHUNK +
						LC_XDRBG256_DRNG_KEYSIZE);

	ret += lc_compare(compare1 + LC_XDRBG256_DRNG_KEYSIZE, exp1,
			  sizeof(exp1), "SHAKE DRNG verification");

	lc_rng_zero(xdrbg256_ctx);

	/*
	 * Verify the generate operation with additional information of 83
	 * bytes.
	 */
	BUILD_BUG_ON(sizeof(exp1) < 85);
	lc_rng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg256_ctx, exp1, 83, act2, sizeof(act2));
	ret += lc_compare(act2, exp83, sizeof(act2),
			  "SHAKE DRNG with alpha 83 bytes");
	lc_rng_zero(xdrbg256_ctx);

	/*
	 * Verify the generate operation with additional information of 84
	 * bytes.
	 */
	lc_rng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg256_ctx, exp1, 84, act2, sizeof(act2));
	ret += lc_compare(act2, exp84, sizeof(act2),
			  "SHAKE DRNG with alpha 84 bytes");
	lc_rng_zero(xdrbg256_ctx);

	/*
	 * Verify the generate operation with additional information of 85
	 * bytes to be identical to 84 bytes due to the truncation of the
	 * additional data.
	 */
	lc_rng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg256_ctx, exp1, 85, act2, sizeof(act2));
	ret += lc_compare(act2, exp84, sizeof(act2),
			  "SHAKE DRNG with alpha 85 bytes");
	lc_rng_zero(xdrbg256_ctx);

	/* Verify the generate operation with additional data */
	if (lc_hash_init(xdrbg256_compare))
		return 1;

	/* Verify: Seeding operation of the DRBG */
	unpoison(seed, sizeof(seed));
	lc_hash_update(xdrbg256_compare, seed, sizeof(seed));
	encode = 0;
	lc_hash_update(xdrbg256_compare, &encode, sizeof(encode));

	/* Verify: Now get the key for the next operation */
	lc_hash_set_digestsize(xdrbg256_compare, LC_XDRBG256_DRNG_KEYSIZE);
	lc_hash_final(xdrbg256_compare, compare1);

	if (lc_hash_init(xdrbg256_compare))
		return 1;
	/* Verify: Generate operation of the DRBG: Insert key */
	lc_hash_update(xdrbg256_compare, compare1, LC_XDRBG256_DRNG_KEYSIZE);
	/* Verify: Generate operation of the DRBG: Insert alpha of 84 bytes */
	lc_hash_update(xdrbg256_compare, exp1, 84);

	encode = 2 * 85 + 84;
	/* Verify: Generate operation of the DRBG: n */
	lc_hash_update(xdrbg256_compare, &encode, sizeof(encode));

	/* Verify: Generate operation of the DRBG: generate data */
	lc_hash_set_digestsize(xdrbg256_compare,
			       LC_XDRBG256_DRNG_KEYSIZE + sizeof(act2));
	lc_hash_final(xdrbg256_compare, compare1);
	ret += lc_compare(compare1 + LC_XDRBG256_DRNG_KEYSIZE, exp84,
			  sizeof(exp84),
			  "SHAKE DRNG with alpha 84 bytes verification");

	lc_rng_zero(xdrbg256_ctx);

	lc_hash_zero(xdrbg256_compare);

	return ret;
}

static int xdrbg256_drng_test(void)
{
	struct lc_rng_ctx *xdrbg256_ctx_heap = NULL;
	int ret;
	LC_XDRBG256_DRNG_CTX_ON_STACK(xdrbg256_ctx);

	CKINT_LOG(xdrbg256_drng_selftest(xdrbg256_ctx),
		  "XDRBG256 DRNG self test failure: %d\n", ret);

	CKINT_LOG(lc_xdrbg256_drng_alloc(&xdrbg256_ctx_heap),
		  "XDRBG256 DRNG heap allocation failure: %d\n", ret);

	ret = xdrbg256_drng_selftest(xdrbg256_ctx_heap);

out:
	lc_rng_zero_free(xdrbg256_ctx_heap);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = xdrbg256_drng_test();

	if (lc_status_get_result(LC_ALG_STATUS_XDRBG256) !=
	    lc_alg_status_result_passed) {
		printf("XDRBG256 self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_XDRBG256));
		return 1;
	}

	if (lc_status_get_result(LC_ALG_STATUS_SHAKE) !=
	    lc_alg_status_result_passed) {
		printf("SHAKE self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_SHAKE));
		return 1;
	}

	ret += test_print_status();

	return ret;
}
