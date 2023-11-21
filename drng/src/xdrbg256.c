/* XDRBG with SHAKE256
 *
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
#include "build_bug_on.h"
#include "compare.h"
#include "lc_memcmp_secure.h"
#include "lc_xdrbg256.h"
#include "math_helper.h"
#include "visibility.h"

/********************************** Selftest **********************************/

static void xdrbg256_drng_selftest(int *tested, const char *impl)
{
	static const uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp[] = {
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
	uint8_t act[sizeof(exp)] __align(sizeof(uint32_t));

	LC_SELFTEST_RUN(tested);

	LC_XDRBG256_DRNG_CTX_ON_STACK(shake_ctx);

	lc_rng_seed(shake_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(shake_ctx, NULL, 0, act, sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
	lc_rng_zero(shake_ctx);
}

/*********************************** Helper ***********************************/

static inline void xdrbg256_shake_final(struct lc_hash_ctx *shake_ctx,
					uint8_t *digest, size_t digest_len)
{
	lc_hash_set_digestsize(shake_ctx, digest_len);
	lc_hash_final(shake_ctx, digest);
}

/* Maximum size of the input data to calculate the encode value */
#define LC_XDRBG256_DRNG_ENCODE_LENGTH 84

/*
 * The encoding is based on the XDRBG paper appendix B.2 with the following
 * properties:
 *
 *   * |V| == 512 which implies that the hash length should be >= 512 bits.
 *
 *   * The chosen hash shall not increase the required code size of the XDRBG
 *     implementation.
 *
 *   * Thus, the selected hash is, naturally SHA3-512 which uses the same Keccak
 *     implementation as SHAKE256.
 */
static void lc_xdrbg256_encode(struct lc_hash_ctx *shake_ctx, const uint8_t n,
			       const uint8_t *alpha, size_t alphalen)
{
	uint8_t encode[LC_SHA3_512_SIZE_DIGEST + 1];

	/* Ensure the prerequisite hash size >= |V| holds. */
	BUILD_BUG_ON(LC_XDRBG256_DRNG_KEYSIZE > LC_SHA3_512_SIZE_DIGEST);

	/* Ensure the prerequisite hash size <= 84 holds. */
	BUILD_BUG_ON(LC_SHA3_512_SIZE_DIGEST > LC_XDRBG256_DRNG_ENCODE_LENGTH);

	if (alphalen <= LC_XDRBG256_DRNG_ENCODE_LENGTH) {
		/* The alpha is sufficiently small to avoid hashing */

		/* Encode the length. */
		encode[0] =
			(uint8_t)(n * (LC_SHA3_512_SIZE_DIGEST + 1) + alphalen);

		/* Insert alpha and encode into the hash context. */
		lc_hash_update(shake_ctx, alpha, alphalen);
		lc_hash_update(shake_ctx, encode, 1);

		return;
	}

	/*
	 * The alpha is larger than the allowed size - perform hashing of
	 * alpha together with its size encoding.
	 */

	/* Hash alpha with the chosen hash mechanisms. */
	lc_hash(lc_sha3_512, alpha, alphalen, encode);

	/* Encode the length */
	encode[LC_SHA3_512_SIZE_DIGEST] =
		(uint8_t)(n * (LC_SHA3_512_SIZE_DIGEST + 1) +
			  LC_SHA3_512_SIZE_DIGEST);

	/*
	 * The buffer encode contains the concatentation of
	 * h(alpha) || (n * (hash_length + 1) + hash_length)
	 */
	lc_hash_update(shake_ctx, encode, sizeof(encode));

	/*
	 * Zeroization of encode is not considered to be necessary as alpha is
	 * considered to be known string.
	 */
}

/*
 * Fast-key-erasure initialization of the SHAKE context. The caller must
 * securely dispose of the initialized SHAKE context. Additional data
 * can be squeezed from the state using lc_hash_final.
 *
 * This function initializes the SHAKE context that can later be used to squeeze
 * random bits out of the SHAKE context. The initialization happens from the key
 * found in the state. Before any random bits can be created, the first 512
 * output bits that are generated is used to overwrite the key. This implies
 * an automatic backtracking resistance as the next round to generate random
 * numbers uses the already updated key.
 *
 * When this function completes, initialized SHAKE context can now be used
 * to generate random bits.
 */
static void xdrbg256_drng_fke_init_ctx(struct lc_xdrbg256_drng_state *state,
				       struct lc_hash_ctx *shake_ctx,
				       const uint8_t *alpha, size_t alphalen)
{
	lc_hash_init(shake_ctx);

	/* Insert V' into the SHAKE */
	lc_hash_update(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);

	/* Insert alpha into the SHAKE state together with its encoding. */
	lc_xdrbg256_encode(shake_ctx, 2, alpha, alphalen);

	/* Generate the V to store in the state and overwrite V'. */
	xdrbg256_shake_final(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);
}

/********************************** XDRB256 ***********************************/

/*
 * Generating random bits is performed by initializing a transient SHAKE state
 * with the key found in state. The initialization implies that the key in
 * the state variable is already updated before random bits are generated.
 *
 * The random bits are generated by performing a SHAKE final operation. The
 * generation operation is chunked to ensure that the fast-key-erasure updates
 * the key when large quantities of random bits are generated.
 *
 * This function implements the following functions from Algorithm 2  of the
 * XDRBG specification:
 *
 *   * GENERATE
 */
static int lc_xdrbg256_drng_generate(void *_state, const uint8_t *alpha,
				     size_t alphalen, uint8_t *out,
				     size_t outlen)
{
	struct lc_xdrbg256_drng_state *state = _state;
	LC_HASH_CTX_ON_STACK(shake_ctx, lc_shake256);

	if (!state)
		return -EINVAL;

	while (outlen) {
		size_t todo = min_size(outlen, LC_XDRBG256_DRNG_MAX_CHUNK);

		/*
		 * Instantiate SHAKE with V', and alpha with its encoding,
		 * and generate V.
		 */
		xdrbg256_drng_fke_init_ctx(state, shake_ctx, alpha, alphalen);

		/* Generate the requested amount of output bits */
		xdrbg256_shake_final(shake_ctx, out, todo);

		out += todo;
		outlen -= todo;
	}

	/* V is already in place. */

	/* Clear the SHAKE state which is not needed any more. */
	lc_hash_zero(shake_ctx);

	return 0;
}

/*
 * The DRNG is seeded by initializing a fast-key-erasure SHAKE context and add
 * the key into the SHAKE state. The SHAKE final operation replaces the key in
 * state.
 *
 * This function implements the following functions from Algorithm 2 of the
 * XDRBG specification:
 *
 *  * INSTANTIATE: The state is empty (either freshly allocated or zeroized with
 *                 lc_xdrbg256_drng_zero). In particular state->initially_seeded
 *                 is 0.
 *
 *  * RESEED: The state contains a working XDRBG state that was seeded before.
 *            In this case, state->initially_seeded is 1.
 */
static int lc_xdrbg256_drng_seed(void *_state, const uint8_t *seed,
				 size_t seedlen, const uint8_t *alpha,
				 size_t alphalen)
{
	static int tested = 0;
	struct lc_xdrbg256_drng_state *state = _state;
	uint8_t intially_seeded = state->initially_seeded;
	LC_HASH_CTX_ON_STACK(shake_ctx, lc_shake256);

	if (!state)
		return -EINVAL;

	xdrbg256_drng_selftest(&tested, "SHAKE DRNG");

	lc_hash_init(shake_ctx);

	/*
	 * During reseeding, insert V' into the SHAKE state. During initial
	 * seeding, V' does not yet exist and thus is not considered.
	 */
	if (intially_seeded)
		lc_hash_update(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);
	else
		state->initially_seeded = 1;

	/* Insert the seed data into the SHAKE state. */
	lc_hash_update(shake_ctx, seed, seedlen);

	/* Insert alpha into the SHAKE state together with its encoding. */
	lc_xdrbg256_encode(shake_ctx, intially_seeded, alpha, alphalen);

	/* Generate the V to store in the state and overwrite V'. */
	xdrbg256_shake_final(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);

	/* Clear the SHAKE state which is not needed any more. */
	lc_hash_zero(shake_ctx);

	return 0;
}

static void lc_xdrbg256_drng_zero(void *_state)
{
	struct lc_xdrbg256_drng_state *state = _state;

	if (!state)
		return;

	lc_memset_secure((uint8_t *)state, 0, LC_XDRBG256_DRNG_STATE_SIZE);
}

LC_INTERFACE_FUNCTION(int, lc_xdrbg256_drng_alloc, struct lc_rng_ctx **state)
{
	struct lc_rng_ctx *out_state = NULL;
	int ret;

	if (!state)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_HASH_COMMON_ALIGNMENT,
				      LC_XDRBG256_DRNG_CTX_SIZE);
	if (ret)
		return -ret;

	LC_XDRBG256_RNG_CTX(out_state);

	*state = out_state;

	return 0;
}

static const struct lc_rng _lc_xdrbg256_drng = {
	.generate = lc_xdrbg256_drng_generate,
	.seed = lc_xdrbg256_drng_seed,
	.zero = lc_xdrbg256_drng_zero,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *,
		    lc_xdrbg256_drng) = &_lc_xdrbg256_drng;
