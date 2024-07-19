/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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
#include "visibility.h"

static int xdrbg128_drng_selftest(struct lc_rng_ctx *xdrbg128_ctx)
{
	struct lc_xdrbg_drng_state *state = xdrbg128_ctx->rng_state;
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp1[] = {
		0xea, 0x7e, 0x9d, 0x67, 0x3b, 0x5f, 0xc7, 0x48, 0xdf, 0x9d,
		0xfa, 0x24, 0xe1, 0x13, 0xed, 0x32, 0x61, 0xc9, 0xb0, 0x23,
		0x88, 0x47, 0x17, 0x10, 0xb7, 0x53, 0x4d, 0x07, 0xcd, 0x70,
		0x02, 0xc4, 0x00, 0x75, 0xd1, 0xf4, 0x9a, 0x95, 0xec, 0x73,
		0xfe, 0x1c, 0xa2, 0xa7, 0x69, 0x18, 0xf8, 0xff, 0x62, 0x09,
		0x33, 0xf8, 0x7e, 0x46, 0xab, 0xb8, 0xb7, 0xe0, 0x9d, 0xaf,
		0x79, 0x38, 0x70, 0xaa, 0x54, 0xc7, 0xab, 0xf9, 0x31, 0xbf,
		0x5a, 0x50, 0x04, 0x2d, 0x9e, 0x37, 0xdb, 0xff, 0x81, 0x47,
		0x9c, 0x1e, 0xfc, 0xf9, 0x5e, 0x8b, 0x24, 0xaa, 0x74, 0xf9,
		0x64, 0xcd, 0x33, 0xcd, 0x22, 0x9e, 0x0c, 0xe1, 0x7d, 0xcc,
		0x8d, 0xd6, 0x76, 0x08, 0x5a, 0x46, 0x05, 0xfb, 0x0f, 0xb1,
		0x76, 0x49, 0xd8, 0x77, 0x5d, 0x0e, 0xae, 0x6f, 0xe5, 0x1b,
		0x64, 0x52, 0xf1, 0xf2, 0xaa, 0xb8, 0x72, 0x07, 0xb2, 0xae,
		0xa7, 0xff, 0x20, 0xee, 0xcb, 0xa3, 0x27, 0x51, 0xca, 0xb3,
		0x04, 0xcc, 0xfb, 0x25, 0x5a, 0xc5, 0x2e, 0x50, 0xad, 0x17,
		0xd4, 0xf3, 0x9b, 0x6b, 0x6f, 0x43, 0x12, 0x5e, 0xc6, 0xee,
		0xd7, 0x04, 0xba, 0x60, 0x75, 0x15, 0x85, 0x35, 0xc9, 0xdb,
		0xd3, 0xc9, 0x8a, 0x7c, 0xb2, 0x85, 0x9b, 0xb4, 0xe0, 0x6f,
		0x06, 0xa1, 0xd1, 0x74, 0xf7, 0xa6, 0x15, 0x05, 0x2b, 0x4f,
		0xd8, 0xcb, 0x5b, 0x86, 0x1a, 0x9b, 0x47, 0xa6, 0x1d, 0xa7,
		0xd0, 0xb0, 0x1e, 0x66, 0xa1, 0x1e, 0x63, 0x46, 0xad, 0x38,
		0xbe, 0xc1, 0x79, 0xc7, 0xf1, 0xd3, 0x50, 0x6a, 0x3e, 0x9a,
		0xda, 0xa5, 0xf3, 0xa1, 0xf6, 0x62, 0xd8, 0x43, 0xf5, 0xb4,
		0xb5, 0xca, 0x47, 0xd9, 0xec, 0x36, 0xa2, 0x13, 0x89, 0x1c,
		0x46, 0x2c, 0x43, 0x3c, 0xf9, 0x82, 0x23
	};
	static const uint8_t exp83[] = { 0x8a, 0x57, 0x1b, 0xc6, 0x18, 0x11,
					 0x2c, 0x17, 0xcd };
	static const uint8_t exp84[] = { 0x53, 0x47, 0x20, 0xf1, 0xba, 0x1c,
					 0xef, 0x9f, 0x48 };
	uint8_t act1[sizeof(exp1)] __align(sizeof(uint32_t));
	uint8_t act2[sizeof(exp83)] __align(sizeof(uint32_t));
	uint8_t compare1[LC_XDRBG128_DRNG_KEYSIZE + sizeof(exp1)];
	int ret = 0;
	uint8_t encode;
	LC_HASH_CTX_ON_STACK(xdrbg128_compare, lc_ascon_xof);

	printf("XDRBG128 ctx len %lu\n", LC_XDRBG128_DRNG_CTX_SIZE);

	/* Check the XDRBG operation */
	lc_rng_seed(xdrbg128_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg128_ctx, NULL, 0, act1, sizeof(act1));
	ret += lc_compare(act1, exp1, sizeof(act1), "Ascon DRNG");
	lc_rng_zero(xdrbg128_ctx);

	/* Verify the seeding operation to generate proper state */
	/* Prepare the state in the DRNG */
	lc_rng_seed(xdrbg128_ctx, seed, sizeof(seed), NULL, 0);
	/* Prepare the state with native Ascon operations */
	lc_hash_init(xdrbg128_compare);
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
	lc_hash_init(xdrbg128_compare);
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
	lc_hash_init(xdrbg128_compare);

	/* Verify: Seeding operation of the DRBG */
	unpoison(seed, sizeof(seed));
	lc_hash_update(xdrbg128_compare, seed, sizeof(seed));
	encode = 0;
	lc_hash_update(xdrbg128_compare, &encode, sizeof(encode));

	/* Verify: Now get the key for the next operation */
	lc_hash_set_digestsize(xdrbg128_compare, LC_XDRBG128_DRNG_KEYSIZE);
	lc_hash_final(xdrbg128_compare, compare1);

	lc_hash_init(xdrbg128_compare);
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
	struct lc_rng_ctx *xdrbg128_ctx_heap;
	int ret;
	LC_XDRBG128_DRNG_CTX_ON_STACK(xdrbg128_ctx);

	ret = xdrbg128_drng_selftest(xdrbg128_ctx);

	if (lc_xdrbg128_drng_alloc(&xdrbg128_ctx_heap))
		return 1;

	ret += xdrbg128_drng_selftest(xdrbg128_ctx_heap);

	lc_rng_zero_free(xdrbg128_ctx_heap);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return xdrbg128_drng_test();
}
