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

static int xdrbg512_drng_selftest(struct lc_rng_ctx *xdrbg512_ctx)
{
	struct lc_xdrbg_drng_state *state = xdrbg512_ctx->rng_state;
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp1[] = {
		0x18, 0x95, 0x64, 0xdd, 0x84, 0x9e, 0x4d, 0x24,
		0x68, 0x9f, 0xec, 0x3c, 0xd5, 0x4c, 0x0c, 0x76,
		0xbf, 0x99, 0xc9, 0xda, 0x84, 0xbc, 0x69, 0xd1,
		0xaf, 0x5b, 0xba, 0xfb, 0x10, 0x4b, 0x0f, 0x73,
		0x56, 0x41, 0x7a, 0x16, 0x2f, 0x34, 0x09, 0xc9,
		0x46, 0x79, 0x93, 0xa6, 0x0e, 0xc9, 0x6e, 0xba,
		0x0d, 0x20, 0x3a, 0x8a, 0xfd, 0x5c, 0x03, 0x94,
		0x30, 0x2c, 0xf5, 0x1e, 0x67, 0x25, 0xed, 0x55,
		0xdf, 0xf3, 0xdc, 0x3e, 0xe8, 0xf9, 0x2c, 0xd7,
		0x1c, 0x95, 0x0c, 0xda, 0xc9, 0x45, 0xdf, 0xe5,
		0xb5, 0x30, 0x76, 0x74, 0x1e, 0x48, 0xf5, 0x72,
		0x5d, 0x12, 0xa9, 0xd2, 0xfb, 0xd1, 0xd9, 0x43,
		0xc9, 0xc0, 0x80, 0x8f, 0x9b, 0x8c, 0x05, 0x83,
		0x62, 0xb0, 0xa6, 0xd3, 0x3b, 0xb6, 0x4e, 0xb0,
		0x41, 0x54, 0x77, 0xee, 0x26, 0xe6, 0x23, 0x8f,
		0xf3, 0x5b, 0x5f, 0x06, 0x2f, 0x49, 0x3a, 0x18,
		0x9c, 0xf3, 0x63, 0x7b, 0x5b, 0xc0, 0xce, 0xa0,
		0xe7, 0xb5, 0xc9, 0x33, 0x61, 0x95, 0xad, 0xb3,
		0x71, 0xeb, 0x7a, 0xe1, 0xba, 0x80, 0x62, 0x6a,
		0x90, 0x04, 0x07, 0x4d, 0xc4, 0x27, 0x79, 0x3a,
		0x19, 0xed, 0x1c, 0xbf, 0x50, 0x0a, 0x73, 0x56,
		0x44, 0xfb, 0x84, 0xe2, 0x26, 0xc5, 0x09, 0xb3,
		0x2a, 0x64, 0xfc, 0x66, 0x17, 0x54, 0x40, 0x9b,
		0xfc, 0x53, 0xd3, 0xfd, 0xa1, 0x7a, 0x28, 0x22,
		0x6b, 0xbf, 0xdb, 0x1d, 0x0d, 0xa7, 0x00, 0xb6,
		0xdc, 0x00, 0x23, 0x89, 0xcf, 0x81, 0x06, 0x9f,
		0x3f, 0xf6, 0x9b, 0x05, 0xf3, 0x87, 0x65, 0x79,
		0xbf, 0x16, 0x58, 0x99, 0x70, 0xfc, 0xc1, 0xa0,
		0x72, 0x38, 0x95, 0xfa, 0x12, 0xaf, 0x4b, 0xcc,
		0x08, 0xe5, 0x75, 0xd4, 0x4f, 0x76, 0x82, 0xf0,
		0x5c, 0x67, 0x62, 0x93, 0x18, 0x24, 0xee, 0x40,
		0x3b, 0x24, 0x56, 0x6e, 0x47, 0xda, 0x49, 0xcf,
		0x2c, 0x99, 0x25, 0xc4, 0x29, 0xcc, 0x5e, 0x57,
		0x88, 0xca, 0x33, 0x32, 0x2f, 0xa8, 0xd1, 0x59,
		0xc7, 0x07, 0x70, 0xc5, 0x88, 0xfc, 0x6d, 0x5a,
		0xeb, 0xf2, 0xf1, 0x7b, 0xfd, 0x70, 0x4c, 0x99,
		0x5a, 0xb1, 0x5e, 0x6b, 0x03, 0x0c, 0x7e, 0xe1,
		0x69, 0x74, 0x88, 0xa3, 0xe1, 0x77, 0xad, 0x0a,
		0x59, 0xd8, 0x2c, 0x28, 0x03, 0x0a, 0x9b, 0xda,
		0x33, 0x16, 0xb2, 0x0b, 0x2c, 0x49, 0xed, 0x9b,
		0xe6, 0x80, 0x6a, 0x08, 0x87, 0xe2, 0x4b, 0x11,
		0xd8, 0x6a, 0xcd, 0x3d, 0xd0, 0x49, 0xb8, 0xc4,
		0xe7, 0x9c, 0x4e, 0x20, 0x3e, 0x56, 0xb6, 0x38,
		0xe2,
	};
	static const uint8_t exp83[] = { 0x9c, 0xeb, 0x34, 0x74, 0x44, 0xb1,
					 0x5a, 0xa4, 0x40 };
	static const uint8_t exp84[] = { 0xc3, 0xf6, 0x47, 0xbf, 0x34, 0x0e,
					 0xf7, 0xb9, 0x6a };
	uint8_t act1[sizeof(exp1)] __align(sizeof(uint32_t)) = { 0 };
	uint8_t act2[sizeof(exp83)] __align(sizeof(uint32_t));
	uint8_t compare1[LC_XDRBG512_DRNG_KEYSIZE + sizeof(exp1)];
	int ret = 0;
	uint8_t encode;
	LC_HASH_CTX_ON_STACK(xdrbg512_compare, lc_shake512);

	printf("XDRBG512 ctx len %lu\n",
	       (unsigned long)LC_XDRBG512_DRNG_CTX_SIZE);

	/* Check the XDRBG operation */
	if (lc_rng_seed(xdrbg512_ctx, seed, sizeof(seed), NULL, 0))
		return 1;
	lc_rng_generate(xdrbg512_ctx, NULL, 0, act1, sizeof(act1));
	ret += lc_compare(act1, exp1, sizeof(act1), "SHAKE DRNG");
	lc_rng_zero(xdrbg512_ctx);

	/* Verify the seeding operation to generate proper state */
	/* Prepare the state in the DRNG */
	if (lc_rng_seed(xdrbg512_ctx, seed, sizeof(seed), NULL, 0))
		return 1;
	/* Prepare the state with native SHAKE operations */
	if (lc_hash_init(xdrbg512_compare))
		return 1;
	unpoison(seed, sizeof(seed));
	lc_hash_update(xdrbg512_compare, seed, sizeof(seed));
	encode = 0;
	lc_hash_update(xdrbg512_compare, &encode, sizeof(encode));
	lc_hash_set_digestsize(xdrbg512_compare, LC_XDRBG512_DRNG_KEYSIZE);
	lc_hash_final(xdrbg512_compare, compare1);
	unpoison(state->v, LC_XDRBG512_DRNG_KEYSIZE);
	ret += lc_compare(compare1, state->v, LC_XDRBG512_DRNG_KEYSIZE,
			  "SHAKE DRNG state generation");

	/* Verify the generate operation */
	/* Use the already generated state from above */

	/* First loop iteration */
	if (lc_hash_init(xdrbg512_compare))
		return 1;
	lc_hash_update(xdrbg512_compare, compare1, LC_XDRBG512_DRNG_KEYSIZE);
	encode = 2 * 85;
	lc_hash_update(xdrbg512_compare, &encode, sizeof(encode));
	/* First loop iteration: generate key */
	lc_hash_set_digestsize(xdrbg512_compare, LC_XDRBG512_DRNG_KEYSIZE);
	lc_hash_final(xdrbg512_compare, compare1);
	/* First loop iteratipn: generate data */
	lc_hash_set_digestsize(xdrbg512_compare, LC_XDRBG512_DRNG_MAX_CHUNK);
	lc_hash_final(xdrbg512_compare, compare1 + LC_XDRBG512_DRNG_KEYSIZE);

	/* 2nd loop round as output size is larger than chunk size */
	if (lc_hash_init(xdrbg512_compare))
		return 1;
	lc_hash_update(xdrbg512_compare, compare1, LC_XDRBG512_DRNG_KEYSIZE);
	encode = 2 * 85;
	lc_hash_update(xdrbg512_compare, &encode, sizeof(encode));
	/* Second loop iteratipn: generate key */
	lc_hash_set_digestsize(xdrbg512_compare, LC_XDRBG512_DRNG_KEYSIZE);
	lc_hash_final(xdrbg512_compare, compare1);
	/* Second loop iteratipn: generate data */
	lc_hash_set_digestsize(xdrbg512_compare,
			       sizeof(compare1) - LC_XDRBG512_DRNG_MAX_CHUNK -
				       LC_XDRBG512_DRNG_KEYSIZE);
	lc_hash_final(xdrbg512_compare, compare1 + LC_XDRBG512_DRNG_MAX_CHUNK +
						LC_XDRBG512_DRNG_KEYSIZE);

	ret += lc_compare(compare1 + LC_XDRBG512_DRNG_KEYSIZE, exp1,
			  sizeof(exp1), "SHAKE DRNG verification");

	lc_rng_zero(xdrbg512_ctx);

	/*
	 * Verify the generate operation with additional information of 83
	 * bytes.
	 */
	BUILD_BUG_ON(sizeof(exp1) < 85);
	if (lc_rng_seed(xdrbg512_ctx, seed, sizeof(seed), NULL, 0))
		return 1;
	lc_rng_generate(xdrbg512_ctx, exp1, 83, act2, sizeof(act2));
	ret += lc_compare(act2, exp83, sizeof(act2),
			  "SHAKE DRNG with alpha 83 bytes");
	lc_rng_zero(xdrbg512_ctx);

	/*
	 * Verify the generate operation with additional information of 84
	 * bytes.
	 */
	if (lc_rng_seed(xdrbg512_ctx, seed, sizeof(seed), NULL, 0))
		return 1;
	lc_rng_generate(xdrbg512_ctx, exp1, 84, act2, sizeof(act2));
	ret += lc_compare(act2, exp84, sizeof(act2),
			  "SHAKE DRNG with alpha 84 bytes");
	lc_rng_zero(xdrbg512_ctx);

	/*
	 * Verify the generate operation with additional information of 85
	 * bytes to be identical to 84 bytes due to the truncation of the
	 * additional data.
	 */
	if (lc_rng_seed(xdrbg512_ctx, seed, sizeof(seed), NULL, 0))
		return 1;
	lc_rng_generate(xdrbg512_ctx, exp1, 85, act2, sizeof(act2));
	ret += lc_compare(act2, exp84, sizeof(act2),
			  "SHAKE DRNG with alpha 85 bytes");
	lc_rng_zero(xdrbg512_ctx);

	/* Verify the generate operation with additional data */
	if (lc_hash_init(xdrbg512_compare))
		return 1;

	/* Verify: Seeding operation of the DRBG */
	unpoison(seed, sizeof(seed));
	lc_hash_update(xdrbg512_compare, seed, sizeof(seed));
	encode = 0;
	lc_hash_update(xdrbg512_compare, &encode, sizeof(encode));

	/* Verify: Now get the key for the next operation */
	lc_hash_set_digestsize(xdrbg512_compare, LC_XDRBG512_DRNG_KEYSIZE);
	lc_hash_final(xdrbg512_compare, compare1);

	if (lc_hash_init(xdrbg512_compare))
		return 1;
	/* Verify: Generate operation of the DRBG: Insert key */
	lc_hash_update(xdrbg512_compare, compare1, LC_XDRBG512_DRNG_KEYSIZE);
	/* Verify: Generate operation of the DRBG: Insert alpha of 84 bytes */
	lc_hash_update(xdrbg512_compare, exp1, 84);

	encode = 2 * 85 + 84;
	/* Verify: Generate operation of the DRBG: n */
	lc_hash_update(xdrbg512_compare, &encode, sizeof(encode));

	/* Verify: Generate operation of the DRBG: generate data */
	lc_hash_set_digestsize(xdrbg512_compare,
			       LC_XDRBG512_DRNG_KEYSIZE + sizeof(act2));
	lc_hash_final(xdrbg512_compare, compare1);
	ret += lc_compare(compare1 + LC_XDRBG512_DRNG_KEYSIZE, exp84,
			  sizeof(exp84),
			  "SHAKE DRNG with alpha 84 bytes verification");

	lc_rng_zero(xdrbg512_ctx);

	lc_hash_zero(xdrbg512_compare);

	return ret;
}

static int xdrbg512_drng_test(void)
{
	struct lc_rng_ctx *xdrbg512_ctx_heap = NULL;
	int ret;
	LC_XDRBG512_DRNG_CTX_ON_STACK(xdrbg512_ctx);

	CKINT_LOG(xdrbg512_drng_selftest(xdrbg512_ctx),
		  "XDRBG512 DRNG self test failure: %d\n", ret);

	CKINT_LOG(lc_xdrbg512_drng_alloc(&xdrbg512_ctx_heap),
		  "XDRBG512 DRNG heap allocation failure: %d\n", ret);

	ret = xdrbg512_drng_selftest(xdrbg512_ctx_heap);

out:
	lc_rng_zero_free(xdrbg512_ctx_heap);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = xdrbg512_drng_test();

	ret = test_validate_status(ret, LC_ALG_STATUS_XDRBG512);
#ifndef LC_FIPS140_DEBUG
	ret = test_validate_status(ret, LC_ALG_STATUS_SHAKE);
#endif
	ret += test_print_status();

	return ret;
}
