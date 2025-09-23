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

#include "alignment.h"
#include "build_bug_on.h"
#include "compare.h"
#include "lc_xdrbg.h"
#include "timecop.h"
#include "ret_checkers.h"
#include "test_helper_common.h"
#include "visibility.h"

static int xdrbg128_drng_selftest(struct lc_rng_ctx *xdrbg128_ctx)
{
	struct lc_xdrbg_drng_state *state = xdrbg128_ctx->rng_state;
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp1[] = {
		0x90, 0xfc, 0x06, 0x53, 0xfb, 0x53, 0xac, 0x68, 0xe9, 0x84,
		0xc5, 0x7f, 0x99, 0xdf, 0x5b, 0x33, 0x8d, 0xba, 0xcd, 0xcb,
		0x8b, 0x87, 0x07, 0x94, 0xe5, 0x36, 0x5e, 0x1c, 0xc1, 0x12,
		0x41, 0x9b, 0xc9, 0x78, 0x0a, 0x58, 0xc9, 0xbc, 0x65, 0x9a,
		0xec, 0xd0, 0xd9, 0xad, 0x6b, 0x56, 0xb0, 0xb5, 0xc5, 0x0a,
		0xbc, 0x87, 0x87, 0x5d, 0x94, 0x2b, 0x9e, 0xe3, 0xad, 0x5f,
		0xc3, 0xa8, 0x8c, 0xc6, 0x96, 0xac, 0x38, 0x08, 0x95, 0x58,
		0x41, 0xd3, 0xd8, 0xf0, 0x31, 0xcd, 0x27, 0xe5, 0x23, 0xfd,
		0x54, 0x7d, 0x65, 0x11, 0x1b, 0xa1, 0xdb, 0x09, 0xe1, 0xe9,
		0xb6, 0x47, 0xee, 0xa3, 0x9a, 0x7e, 0x15, 0xfd, 0xcf, 0xa0,
		0x08, 0xba, 0xce, 0x57, 0xa4, 0xa7, 0x03, 0x52, 0xf0, 0x78,
		0xf7, 0x2a, 0x7b, 0xd1, 0xa1, 0xd6, 0x9f, 0xb4, 0xc2, 0x6f,
		0x7d, 0x3e, 0xfc, 0x78, 0xf5, 0x3b, 0x25, 0x51, 0x56, 0x7e,
		0xe9, 0xb3, 0x4c, 0x0d, 0x2b, 0x1f, 0xef, 0xe1, 0xda, 0x13,
		0x2d, 0xd6, 0xf0, 0x32, 0x22, 0x12, 0x8b, 0x59, 0x3b, 0x97,
		0x28, 0x27, 0x09, 0xa1, 0x9c, 0x41, 0xb3, 0x5b, 0x21, 0x53,
		0x70, 0x3d, 0x02, 0xa1, 0x13, 0x81, 0x33, 0x69, 0x71, 0x7d,
		0x3b, 0x19, 0xa2, 0x9e, 0xbf, 0x64, 0xcd, 0xc6, 0x52, 0x9b,
		0xd3, 0x78, 0x6a, 0x29, 0x1a, 0x34, 0x50, 0xc0, 0x92, 0x1b,
		0x4b, 0x4d, 0xa9, 0xc2, 0x47, 0x72, 0xc4, 0xf2, 0xef, 0x32,
		0x0b, 0x4d, 0xb7, 0x4e, 0x78, 0x58, 0x20, 0x1d, 0xbd, 0x0d,
		0x23, 0x29, 0xfe, 0x1c, 0x36, 0x67, 0xa2, 0x8f, 0x2d, 0xba,
		0x4b, 0x69, 0xfd, 0x24, 0x2d, 0x3a, 0x36, 0xc2, 0xea, 0x5e,
		0x65, 0x21, 0x44, 0x23, 0xfc, 0x25, 0x2b, 0x07, 0x1e, 0xcf,
		0x55, 0x92, 0x3e, 0x6a, 0x8a, 0x21, 0xb1
	};
	static const uint8_t exp83[] = { 0x4e, 0x31, 0x33, 0xbd, 0x6e,
					 0xbc, 0xe5, 0x1d, 0x2f };
	static const uint8_t exp84[] = { 0xdc, 0x76, 0x9c, 0xd5, 0x0b,
					 0xca, 0x15, 0x71, 0x21 };
	uint8_t act1[sizeof(exp1)] __align(sizeof(uint32_t)) = { 0 };
	uint8_t act2[sizeof(exp83)] __align(sizeof(uint32_t));
	uint8_t compare1[LC_XDRBG128_DRNG_KEYSIZE + sizeof(exp1)];
	int ret = 0;
	uint8_t encode;
	LC_HASH_CTX_ON_STACK(xdrbg128_compare, lc_ascon_xof);

	printf("XDRBG128 ctx len %lu\n",
	       (unsigned long)LC_XDRBG128_DRNG_CTX_SIZE);

	/* Check the XDRBG operation */
	lc_rng_seed(xdrbg128_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg128_ctx, NULL, 0, act1, sizeof(act1));
	ret += lc_compare(act1, exp1, sizeof(act1), "Ascon DRNG");
	lc_rng_zero(xdrbg128_ctx);

	/* Verify the seeding operation to generate proper state */
	/* Prepare the state in the DRNG */
	lc_rng_seed(xdrbg128_ctx, seed, sizeof(seed), NULL, 0);
	/* Prepare the state with native Ascon operations */
	if (lc_hash_init(xdrbg128_compare))
		return 1;
	unpoison(seed, sizeof(seed));
	lc_hash_update(xdrbg128_compare, seed, sizeof(seed));
	encode = 0;
	lc_hash_update(xdrbg128_compare, &encode, sizeof(encode));
	lc_hash_set_digestsize(xdrbg128_compare, LC_XDRBG128_DRNG_KEYSIZE);
	lc_hash_final(xdrbg128_compare, compare1);
	unpoison(state->v, LC_XDRBG128_DRNG_KEYSIZE);
	ret += lc_compare(compare1, state->v, LC_XDRBG128_DRNG_KEYSIZE,
			  "Ascon DRNG state generation");

	/* Verify the generate operation */
	if (lc_hash_init(xdrbg128_compare))
		return 1;
	/* Use the already generated state from above */
	lc_hash_update(xdrbg128_compare, compare1, LC_XDRBG128_DRNG_KEYSIZE);
	encode = 2 * 85;
	lc_hash_update(xdrbg128_compare, &encode, sizeof(encode));
	lc_hash_set_digestsize(xdrbg128_compare, sizeof(compare1));
	lc_hash_final(xdrbg128_compare, compare1);
	ret += lc_compare(compare1 + LC_XDRBG128_DRNG_KEYSIZE, exp1,
			  sizeof(exp1), "Ascon DRNG verification");

	lc_rng_zero(xdrbg128_ctx);

	/*
	 * Verify the generate operation with additional information of 83
	 * bytes.
	 */
	BUILD_BUG_ON(sizeof(exp1) < 85);
	lc_rng_seed(xdrbg128_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg128_ctx, exp1, 83, act2, sizeof(act2));
	ret += lc_compare(act2, exp83, sizeof(act2),
			  "Ascon DRNG with alpha 83 bytes");
	lc_rng_zero(xdrbg128_ctx);

	/*
	 * Verify the generate operation with additional information of 84
	 * bytes.
	 */
	lc_rng_seed(xdrbg128_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg128_ctx, exp1, 84, act2, sizeof(act2));
	ret += lc_compare(act2, exp84, sizeof(act2),
			  "Ascon DRNG with alpha 84 bytes");
	lc_rng_zero(xdrbg128_ctx);

	/*
	 * Verify the generate operation with additional information of 85
	 * bytes to be identical to 84 bytes due to the truncation of the
	 * additional data.
	 */
	lc_rng_seed(xdrbg128_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg128_ctx, exp1, 85, act2, sizeof(act2));
	ret += lc_compare(act2, exp84, sizeof(act2),
			  "Ascon DRNG with alpha 85 bytes");
	lc_rng_zero(xdrbg128_ctx);

	/* Verify the generate operation with additional data */
	if (lc_hash_init(xdrbg128_compare))
		return 1;

	/* Verify: Seeding operation of the DRBG */
	unpoison(seed, sizeof(seed));
	lc_hash_update(xdrbg128_compare, seed, sizeof(seed));
	encode = 0;
	lc_hash_update(xdrbg128_compare, &encode, sizeof(encode));

	/* Verify: Now get the key for the next operation */
	lc_hash_set_digestsize(xdrbg128_compare, LC_XDRBG128_DRNG_KEYSIZE);
	lc_hash_final(xdrbg128_compare, compare1);

	if (lc_hash_init(xdrbg128_compare))
		return 1;
	/* Verify: Generate operation of the DRBG: Insert key */
	lc_hash_update(xdrbg128_compare, compare1, LC_XDRBG128_DRNG_KEYSIZE);
	/* Verify: Generate operation of the DRBG: Insert alpha of 84 bytes */
	lc_hash_update(xdrbg128_compare, exp1, 84);

	encode = 2 * 85 + 84;
	/* Verify: Generate operation of the DRBG: n */
	lc_hash_update(xdrbg128_compare, &encode, sizeof(encode));

	/* Verify: Generate operation of the DRBG: generate data */
	lc_hash_set_digestsize(xdrbg128_compare,
			       LC_XDRBG128_DRNG_KEYSIZE + sizeof(act2));
	lc_hash_final(xdrbg128_compare, compare1);
	ret += lc_compare(compare1 + LC_XDRBG128_DRNG_KEYSIZE, exp84,
			  sizeof(exp84),
			  "Ascon DRNG with alpha 84 bytes verification");

	lc_rng_zero(xdrbg128_ctx);

	lc_hash_zero(xdrbg128_compare);

	return ret;
}

static int xdrbg128_drng_test(void)
{
	struct lc_rng_ctx *xdrbg128_ctx_heap = NULL;
	int ret;
	LC_XDRBG128_DRNG_CTX_ON_STACK(xdrbg128_ctx);

	CKINT_LOG(xdrbg128_drng_selftest(xdrbg128_ctx),
		  "XDRBG128 DRNG self test failure: %d\n", ret);

	CKINT_LOG(lc_xdrbg128_drng_alloc(&xdrbg128_ctx_heap),
		  "XDRBG128 DRNG heap allocation failure: %d\n", ret);

	ret = xdrbg128_drng_selftest(xdrbg128_ctx_heap);

out:
	lc_rng_zero_free(xdrbg128_ctx_heap);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = xdrbg128_drng_test();

	ret = test_validate_status(ret, LC_ALG_STATUS_XDRBG128, 0);
#ifndef LC_FIPS140_DEBUG
	ret = test_validate_status(ret, LC_ALG_STATUS_ASCONXOF, 1);
#endif
	ret += test_print_status();

	return ret;
}
