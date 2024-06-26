/* XDRBG with SHAKE256
 *
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "timecop.h"
#include "visibility.h"

/********************************** Selftest **********************************/

static void xdrbg256_drng_selftest(int *tested, const char *impl)
{
	static const uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp[] = {
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
		0x29, 0x12, 0xd0, 0x1c, 0x39, 0x9f, 0x79,

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

static inline void lc_xdrbg256_shake_final(struct lc_hash_ctx *shake_ctx,
					   uint8_t *digest, size_t digest_len)
{
	lc_hash_set_digestsize(shake_ctx, digest_len);
	lc_hash_final(shake_ctx, digest);
}

/* Maximum size of the input data to calculate the encode value */
#define LC_XDRBG256_DRNG_ENCODE_LENGTH 84
#define LC_XDRBG256_DRNG_ENCODE_N(x) (x * 85)
#define LC_XDRBG256_DRNG_HASH_TYPE lc_shake256

/*
 * The encoding is based on the XDRBG paper appendix B.2 with the following
 * properties:
 *
 *   * length of the hash is set to be equal to |V|
 */
static void lc_xdrbg256_drng_encode(struct lc_hash_ctx *shake_ctx,
				    const uint8_t n, const uint8_t *alpha,
				    size_t alphalen)
{
	uint8_t encode;

	/* Ensure the prerequisite hash size <= 84 holds. */
	BUILD_BUG_ON(LC_XDRBG256_DRNG_KEYSIZE > LC_XDRBG256_DRNG_ENCODE_LENGTH);

	/*
	 * Only consider up to 84 left-most bytes of alpha. According to
	 * the XDRBG specification appendix B:
	 *
	 * """
	 * This encoding is efficient and flexible, but does require that the
	 * additional input string is no longer than 84 bytes–a constraint that
	 * seems very easy to manage in practice.
	 *
	 * For example, IPV6 addresses and GUIDs are 16 bytes long, Ethernet
	 * addresses are 12 bytes long, and the most demanding requirement for
	 * unique randomly-generated device identifiers can be met with a
	 * 32-byte random value. This is the encoding we recommend for XDRBG.
	 * """
	 */
	if (alphalen > 84)
		alphalen = 84;

	/* Encode the length. */
	encode = (uint8_t)(n + alphalen);

	/* Insert alpha and encode into the hash context. */
	lc_hash_update(shake_ctx, alpha, alphalen);
	lc_hash_update(shake_ctx, &encode, 1);

#if 0
	/*
	 * The alpha is larger than the allowed size - perform hashing of
	 * alpha together with its size encoding.
	 */
	static const uint8_t byte = 0xff;
	LC_HASH_CTX_ON_STACK(enc_hash_ctx, LC_XDRBG256_DRNG_HASH_TYPE);
	uint8_t encode[LC_XDRBG256_DRNG_KEYSIZE + 1];

	/* Hash alpha with the XOF. */
	lc_hash_init(enc_hash_ctx);
	lc_hash_update(enc_hash_ctx, alpha, alphalen);
	lc_hash_update(enc_hash_ctx, &byte, sizeof(byte));
	xdrbg256_shake_final(enc_hash_ctx, encode, LC_XDRBG256_DRNG_KEYSIZE);
	lc_hash_zero(enc_hash_ctx);

	/* Encode the length */
	encode[LC_XDRBG256_DRNG_KEYSIZE] = (uint8_t)((n * 85) + 84);

	/*
	 * The buffer encode contains the concatentation of
	 * h(alpha) || (n * (hash_length + 1) + hash_length)
	 */
	lc_hash_update(shake_ctx, encode, sizeof(encode));
#endif

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
static void lc_xdrbg256_drng_fke_init_ctx(struct lc_xdrbg256_drng_state *state,
					  struct lc_hash_ctx *shake_ctx,
					  const uint8_t *alpha, size_t alphalen)
{
	lc_hash_init(shake_ctx);

	/* Insert V' into the SHAKE */
	lc_hash_update(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);

	/* Insert alpha into the SHAKE state together with its encoding. */
	lc_xdrbg256_drng_encode(shake_ctx, LC_XDRBG256_DRNG_ENCODE_N(2), alpha,
				alphalen);

	/* Generate the V to store in the state and overwrite V'. */
	lc_xdrbg256_shake_final(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);
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
	LC_HASH_CTX_ON_STACK(shake_ctx, LC_XDRBG256_DRNG_HASH_TYPE);

	if (!state)
		return -EINVAL;

	while (outlen) {
		size_t todo = min_size(outlen, LC_XDRBG256_DRNG_MAX_CHUNK);

		/*
		 * Instantiate SHAKE with V', and alpha with its encoding,
		 * and generate V.
		 */
		lc_xdrbg256_drng_fke_init_ctx(state, shake_ctx, alpha,
					      alphalen);

		/* Generate the requested amount of output bits */
		lc_xdrbg256_shake_final(shake_ctx, out, todo);

		/* Timecop: out is not sensitive for side channels. */
		unpoison(out, todo);

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
	LC_HASH_CTX_ON_STACK(shake_ctx, LC_XDRBG256_DRNG_HASH_TYPE);

	/* Timecop: Seed is sensitive. */
	poison(seed, seedlen);

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
	lc_xdrbg256_drng_encode(shake_ctx,
				LC_XDRBG256_DRNG_ENCODE_N(intially_seeded),
				alpha, alphalen);

	/* Generate the V to store in the state and overwrite V'. */
	lc_xdrbg256_shake_final(shake_ctx, state->v, LC_XDRBG256_DRNG_KEYSIZE);

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
