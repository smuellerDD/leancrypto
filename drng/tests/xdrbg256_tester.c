/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
#include "compare.h"
#include "lc_xdrbg256.h"
#include "visibility.h"

static int xdrbg256_drng_selftest(struct lc_rng_ctx *xdrbg256_ctx)
{
	struct lc_xdrbg256_drng_state *state = xdrbg256_ctx->rng_state;
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp1[] = {
		0xb6, 0x29, 0x62, 0x30, 0xc5, 0x98, 0x9a, 0x98, 0x42, 0xaf,
		0x9b, 0x67, 0x99, 0x37, 0xfb, 0x7e, 0x9d, 0xa8, 0xbd, 0xb2,
		0xc7, 0x82, 0xbd, 0xd0, 0xb6, 0x13, 0xed, 0x2c, 0x54, 0xe8,
		0x41, 0x84, 0x92, 0x84, 0x2b, 0xfa, 0xc2, 0xab, 0x70, 0xed,
		0x58, 0xf9, 0x67, 0x71, 0xf0, 0x22, 0x84, 0xb8, 0xad, 0x5e,
		0xf0, 0x2c, 0x79, 0x00, 0x29, 0xfe, 0x8b, 0xa2, 0x2b, 0x2b,
		0xff, 0xcf, 0x27, 0xce, 0x26, 0x35, 0xe8, 0xd8, 0x0d, 0x4d,
		0x4d, 0x29, 0xf2, 0x56, 0xb7, 0x6a, 0x18, 0x40, 0xbf, 0xf4,
		0xfe, 0xed, 0x0c, 0x11, 0x00, 0x35, 0xf1, 0xa7, 0xaf, 0x1c,
		0x00, 0x2d, 0x81, 0x6e, 0xa3, 0x44, 0x3a, 0x36, 0x43, 0xe5,
		0x9a, 0x91, 0xcb, 0xd5, 0xf4, 0xf3, 0x1e, 0x3f, 0x38, 0xdd,
		0xfe, 0xa2, 0xa8, 0xb1, 0xe0, 0x36, 0x0e, 0x43, 0x29, 0x5b,
		0x89, 0x44, 0x53, 0xbc, 0x58, 0xdb, 0xb8, 0x74, 0x76, 0xbd,
		0xdc, 0xfa, 0x57, 0x9d, 0x5b, 0xb0, 0x2c, 0x09, 0x4b, 0x3e,
		0x6a, 0x3d, 0xa7, 0xf3, 0x43, 0x4e, 0x3f, 0xa3, 0x43, 0xac,
		0x57, 0x55, 0xd3, 0xe7, 0x72, 0x61, 0x49, 0x90, 0xd6, 0xbb,
		0xcb, 0xc8, 0xfd, 0x64, 0xa6, 0x74, 0x2c, 0x90, 0x75, 0x11,
		0xc3, 0xdb, 0x48, 0x79, 0xf4, 0x0f, 0x04, 0xf9, 0xbc, 0x79,
		0x07, 0x6c, 0x0b, 0xd3, 0x7c, 0xa0, 0x57, 0x59, 0x97, 0xc1,
		0xdc, 0x41, 0xe3, 0xc1, 0x6b, 0x67, 0x99, 0x9a, 0xa9, 0x83,
		0xc8, 0x99, 0x67, 0xd5, 0x72, 0x92, 0x44, 0x87, 0x6c, 0x20,
		0xf9, 0xf0, 0xf3, 0x91, 0x6b, 0xfa, 0x53, 0x4c, 0xcb, 0x08,
		0xb4, 0x31, 0x25, 0xe9, 0xff, 0xb7, 0x8b, 0x81, 0x14, 0xa1,
		0x37, 0x3b, 0xa6, 0x85, 0x89, 0x30, 0x62, 0x05, 0xfc, 0x78,
		0x4b, 0xca, 0x6d, 0xe8, 0x5b, 0x28, 0x83
	};
	uint8_t act1[sizeof(exp1)] __align(sizeof(uint32_t));
	uint8_t compare1[LC_XDRBG256_DRNG_KEYSIZE + sizeof(exp1)];
	int ret = 0;
	uint8_t encode;
	LC_HASH_CTX_ON_STACK(xdrbg256_compare, lc_shake256);

	/* Check the XDRBG operation */
	lc_rng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(xdrbg256_ctx, NULL, 0, act1, sizeof(act1));
	ret += lc_compare(act1, exp1, sizeof(act1), "SHAKE DRNG");
	lc_rng_zero(xdrbg256_ctx);

	/* Verify the seeding operation to generate proper state */
	/* Prepare the state in the DRNG */
	lc_rng_seed(xdrbg256_ctx, seed, sizeof(seed), NULL, 0);
	/* Prepare the state with native SHAKE operations */
	lc_hash_init(xdrbg256_compare);
	lc_hash_update(xdrbg256_compare, seed, sizeof(seed));
	encode = 0;
	lc_hash_update(xdrbg256_compare, &encode, sizeof(encode));
	lc_hash_set_digestsize(xdrbg256_compare, LC_XDRBG256_DRNG_KEYSIZE);
	lc_hash_final(xdrbg256_compare, compare1);
	ret += lc_compare(compare1, state->v, LC_XDRBG256_DRNG_KEYSIZE,
			  "SHAKE DRNG state generation");

	/* Verify the generate operation */
	lc_hash_init(xdrbg256_compare);
	/* Use the already generated state from above */
	lc_hash_update(xdrbg256_compare, compare1, LC_XDRBG256_DRNG_KEYSIZE);
	encode = 2 * (LC_SHA3_512_SIZE_DIGEST + 1);
	lc_hash_update(xdrbg256_compare, &encode, sizeof(encode));
	lc_hash_set_digestsize(xdrbg256_compare, sizeof(compare1));
	lc_hash_final(xdrbg256_compare, compare1);
	ret += lc_compare(compare1 + LC_XDRBG256_DRNG_KEYSIZE, exp1,
			  sizeof(exp1), "SHAKE DRNG verification");

	lc_rng_zero(xdrbg256_ctx);

	/*
	 * Verify the seeding operation to generate proper state with large
	 * alpha.
	 */
	/* Seed the XDRBG with an alpha > 84 bytes */
	lc_rng_seed(xdrbg256_ctx, seed, sizeof(seed), exp1, sizeof(exp1));
	/* Prepare the state with native SHAKE operations */
	lc_hash_init(xdrbg256_compare);
	lc_hash_update(xdrbg256_compare, seed, sizeof(seed));
	/* Insert SHA3-512 hash of alpha */
	lc_hash(lc_sha3_512, exp1, sizeof(exp1), act1);
	lc_hash_update(xdrbg256_compare, act1, LC_SHA3_512_SIZE_DIGEST);
	encode = LC_SHA3_512_SIZE_DIGEST;
	lc_hash_update(xdrbg256_compare, &encode, sizeof(encode));
	lc_hash_set_digestsize(xdrbg256_compare, LC_XDRBG256_DRNG_KEYSIZE);
	lc_hash_final(xdrbg256_compare, compare1);
	ret += lc_compare(compare1, state->v, LC_XDRBG256_DRNG_KEYSIZE,
			  "SHAKE DRNG state generation with large alpha");

	lc_rng_zero(xdrbg256_ctx);
	lc_hash_zero(xdrbg256_compare);

	return ret;
}

static int xdrbg256_drng_test(void)
{
	struct lc_rng_ctx *xdrbg256_ctx_heap;
	int ret;
	LC_XDRBG256_DRNG_CTX_ON_STACK(xdrbg256_ctx);

	ret = xdrbg256_drng_selftest(xdrbg256_ctx);

	if (lc_xdrbg256_drng_alloc(&xdrbg256_ctx_heap))
		return 1;

	ret += xdrbg256_drng_selftest(xdrbg256_ctx_heap);

	lc_rng_zero_free(xdrbg256_ctx_heap);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return xdrbg256_drng_test();
}
