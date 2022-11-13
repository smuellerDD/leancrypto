/* Fast-Key-Erasure KMAC256 DRNG
 *
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

/******************************************************************************
 * Abstract
 *
 * This specification defines a simple deterministic random number generator
 * (DRNG) which can be used to generate cryptographically secure random bit
 * strings for various use cases including symmetric and asymmetric key
 * generation services. The DRNG is based on the KECCAK Message Authentication
 * Code (KMAC) and is intended to support a wide range of applications and
 * requirements, and is conservative in its resource consumption.
 *
 * 1. Introduction
 *
 * A deterministic random number generator (DRNG), also called a pseudo-random
 * number generator (PRNG), is one of the pillars of cryptographic systems.
 * Its goal is to consume input data that is believed or defined to contain
 * entropy and to generate random bit streams from this seed that are
 * indistinguishable from perfect random numbers.
 *
 * This specification defines a simple deterministic random number generator
 * (DRNG) which can be used to generate cryptographically secure random bit
 * strings named KMAC DRNG. The DRNG is based on the KECCAK Message
 * Authentication Code (KMAC) as specified in [SP800-185].
 *
 * The KMAC algorithm is based on cSHAKE which in turn is based on KECCAK with
 * its sponge construction of the absorb phase and squeeze phase. The KMAC DRNG
 * uses the absorb phase to insert the KMAC DRNG key data believed to contain
 * entropy. In a second step, the KECCAK squeeze phase is applied to
 * generate a random bit stream of the size requested by the consumer.
 * The KECCAK squeeze phase generates a pseudorandom bit stream of the desired
 * length. The number of the output bits depend on the specific cryptographic
 * algorithms for which the random bit stream is needed.
 *
 * The KMAC key is generated with the seed operation that consumes the currently
 * used KMAC key and the seed data with a KMAC operation to generate a new
 * KMAC key. The use of the KMAC operation to process seed data ensures that
 * input data without a uniform distribution is converted into a KMAC key to be
 * uniformly distributed. This allows inserting seed data that only partially
 * contains entropy, including the insertion of nonces, personalization strings
 * or other data in any order the caller desires. Thus, the goal of the seed
 * operation is to compress the possibly dispersed entropy of the input data
 * into a cryptographically strong KMAC key which is used to generate random
 * bit streams from.
 *
 * The DRNG state management applies the fast-key-erasure mechanism as defined
 * in [FKE] to ensure "backtracking resistance" in NIST terminology (also called
 * "forward secrecy"). To ensure a key is only used for a limited amount of
 * generated random bits, the fast-key-erasure mechanism is applied at least
 * after generating of a hundred times the cSHAKE256 block size number of random
 * bits.
 *
 * The state to be maintained for the life-time of the KMAC DRNG is only its
 * key as the KMAC operation is transient in nature.
 *
 * The KMAC-DRNG conceptually is very similar to the extract and expand approach
 * of the HKDF algorithm specified in [RFC5869].
 *
 * 2. KMAC-based Deterministic Random Number Generator (KMAC-DRNG)
 *
 * 2.1 Notation
 *
 * The KMAC-hash denotes the KMACXOF256 function [SP800-185]
 * instantiated with cSHAKE 256 [FIPS202]. The KMAC-hash has 4 arguments:
 * the key K, the main input bit string X, the requested output length L in
 * bits, and an optional customization bit string S.
 *
 * The inputs to the KMAC-hash function are specified with references to these
 * parameters.
 *
 * 2.2 Seeding
 *
 * KMAC-Seeding(K(N), seed, personalization string) -> K(N + 1)
 *
 * Inputs:
 *   K(N): The current KMAC DRNG key used by the current instance of the
 *         KMAC DRNG. If the KMAC DRNG is initialized and therefore no current
 *         key exists, a zero string of 512 bits size is used.
 *
 *   seed: The caller-provided seed material that contains entropy.
 *
 * Output:
 *   K(N + 1): A new KMAC DRNG key that is used for instantiating the KMAC hash
 *             during the next generate or seed phase.
 *
 * The seeding of the KMAC DRNG is performed as follows:
 *
 * K(N + 1) = KMAC(K = K(N),
 *                 X = seed || personalization string,
 *                 L = 512
 *                 S = "KMAC-DRNG seed")
 *
 * 2.3. Generating One Block of Random Bit Stream
 *
 * KMAC-Generate(K(N), additional input, length) -> K(N + 1), random bit stream
 *
 * Inputs:
 *   K(N): The current KMAC DRNG key of 512 bits size.
 *
 *   additional input: The optional additional input may be used to further
 *                     alter the generated random bit stream.
 *
 *   length: The length of the random bit stream to be generated in bits. The
 *           length must be smaller or equal to 100 times the cSHAKE block
 *           size minus 512 (equals to 108,288 bits). This ensures that the
 *           entire maximum of data to be squeezed from KECCAK equals to a
 *           multiple of full cSHAKE blocks.
 *
 * Outputs:
 *   K(N + 1): A new KMAC DRNG key that is used for instantiating the KMAC hash
 *             during the next generate or seed operation.
 *
 *   random bit stream: Random bit stream of the requested length.
 *
 * The generation of one random bit stream block is performed as follows:
 *
 * T(0) = 512 left-most bits of R
 * T(1) = all right-most bits of R starting with the 512th bit
 * K(N + 1) = T(0)
 * random bit stream = T(1)
 *
 * where:
 * R = KMAC(K = K(N),
 *          X = additional input,
 *          L = 512 + length,
 *          S = "KMAC-DRNG generate")
 *
 * 2.4. Generating Random Bit Stream of Arbitrary Length
 *
 * Input:
 *   K(N): The KMAC key of 512 bits size generated with the previous generate or
 *         seed operation.
 *
 *   additional input: The optional additional input may be used to further
 *                     alter the generated random bit stream.
 *
 *   length: The length of the random bit stream to be generated in bits.
 *
 * Output
 *   K(N + 1): A new KMAC DRNG key that is used for instantiating the KMAC hash
 *             during the next generate or seed operation.
 *
 *   random bit stream: Random bit stream of the requested length.
 *
 * The generation of the random bit stream is performed as follows:
 *
 * B = 1088 * 100 - 512
 * N = ceil(length / B)
 * TMP_K(0) = K(N)
 * R = R(1) || R(2) || R(3) || ... || R(N)
 * random bit stream = first length bits of R
 * K(N + 1) = TMP_K(N)
 *
 * where:
 * (TMP_K(1), R(1)) = KMAC-Generate(TMP_K(0), additional input, B)
 * (TMP_K(2), R(2)) = KMAC-Generate(TMP_K(1), additional input, B)
 * ...
 * (TMP_K(N), R(N)) = KMAC-Generate(TMP_K(N - 1), additional input, B)
 *
 * 3. Rationale
 *
 * The KMAC DRNG key size of 512 bits is chosen based on the following
 * considerations:
 *
 * * During instantiation of KMAC the given key size allows the limitation of
 *   KECCAK operations to 2: The first KECCAK operation is due to the cSHAKE256
 *   initialization. Tne second KECCAK operation is caused by the KMAC
 *   initialization considering that the length of the key, the cSHAKE256
 *   customization string and the KMAC initialization encoding bytes together
 *   are less than the block size of cSHAKE256. This limits the number of
 *   KECCAK operations required based on the input to the absolute minimum
 *   possible based on the KMAC specification.
 *
 * * KMAC256 has a security strength of 256 bits. Thus a key size of 256 bits
 *   would be sufficient. Yet, considering that due to the fast-key-erasure
 *   mechanism the key is hashed to generate a new key, over time the repeated
 *   hash operation will decrease the amount of entropy in the key. To allow
 *   callers to insert more entropy than the security strength of KMAC256
 *   for offsetting this loss of entropy, the key size is set to 512 bits.
 *
 * 4. Normative References
 *
 * [FIPS202] FIPS PUB 202, SHA-3 Standard: Permutation-Based Hash and
 *           Extendable-Output Functions, August 2015
 *
 * [FKE] D. Bernstein, Fast-key-erasure random-number generators, 2017.07.23,
 *       https://blog.cr.yp.to/20170723-random.html
 *
 * [RFC5869] H. Krawczyk, P. Eronen, HMAC-based Extract-and-Expand Key
 *           Derivation Function (HKDF), RFC 5869, May 2010
 *
 * [SP800-185] John Kelsey, Shu-jen Chang, Ray Perlne, NIST Special Publication
 *             800-185 SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and
 *             ParallelHash, December 2016
 ******************************************************************************/

#include "build_bug_on.h"
#include "ext_headers.h"
#include "lc_kmac256_drng.h"
#include "math_helper.h"
#include "memcmp_secure.h"
#include "visibility.h"

#define LC_KMAC_DRNG_SEED_CUSTOMIZATION_STRING	"KMAC-DRNG seed"
#define LC_KMAC_DRNG_CTX_CUSTOMIZATION_STRING	"KMAC-DRNG generate"

/*
 * Fast-key-erasure initialization of the KMAC context. The caller must
 * securely dispose of the initialized KMAC context. Additional data
 * can be squeezed from the state using lc_kmac_final_xof_more.
 *
 * This function initializes the KMAC context that can later be used to squeeze
 * random bits out of the KMAC context. The initialization happens from the key
 * found in the state. Before any random bits can be created, the first 512
 * output bits that are generated is used to overwrite the key. This implies
 * an automatic backtracking resistance as the next round to generate random
 * numbers uses the already updated key.
 *
 * When this function completes, initialized KMAC context can now be used
 * to generate random bits.
 *
 * This generates T(0) and T(1) of size 1088 of the KMAC DRNG specification
 * section 2.3.
 */
static void
kmac256_drng_fke_init_ctx(struct lc_kmac256_drng_state *state,
			  struct lc_kmac_ctx *kmac_ctx,
			  const uint8_t *addtl_input, size_t addtl_input_len)
{
	/* Initialize the KMAC with K(N) and the cust. string. */
	lc_kmac_init(kmac_ctx, state->key, LC_KMAC256_DRNG_KEYSIZE,
		     (uint8_t *)LC_KMAC_DRNG_CTX_CUSTOMIZATION_STRING,
		     sizeof(LC_KMAC_DRNG_CTX_CUSTOMIZATION_STRING) - 1);

	/* Insert the additional data into the KMAC state. */
	lc_kmac_update(kmac_ctx, addtl_input, addtl_input_len);

	/* Generate the K(N + 1) to store in the state and overwrite K(N). */
	lc_kmac_final_xof(kmac_ctx, state->key, LC_KMAC256_DRNG_KEYSIZE);
}

/*
 * Generating random bits is performed by initializing a transient KMAC state
 * with the key found in state. The initialization implies that the key in
 * the state variable is already updated before random bits are generated.
 *
 * The random bits are generated by performing a KMAC XOF final operation. The
 * generation operation is chunked to ensure that the fast-key-erasure updates
 * the key when large quantities of random bits are generated.
 *
 * This generates R of the KMAC DRNG specification section 2.4.
 */
static int
lc_kmac256_drng_generate(void *_state,
			 const uint8_t *addtl_input, size_t addtl_input_len,
			 uint8_t *out, size_t outlen)
{
	struct lc_kmac256_drng_state *state = _state;
	LC_KMAC_CTX_ON_STACK(kmac_ctx, lc_cshake256);

	BUILD_BUG_ON(LC_KMAC256_DRNG_MAX_CHUNK % LC_SHA3_256_SIZE_BLOCK);

	if (!state)
		return -EINVAL;

	/* The loop generates R from KMAC DRNG specification section 2.4. */
	while (outlen) {
		/*
		 * This operation generates R(N) from the KMAC DRNG
		 * specification section 2.4.
		 */
		size_t todo = min_t(size_t, outlen, LC_KMAC256_DRNG_MAX_CHUNK -
						    LC_KMAC256_DRNG_KEYSIZE);

		/* Instantiate KMAC with TMP_K(N) and generate TMP_K(N + 1). */
		kmac256_drng_fke_init_ctx(state, kmac_ctx,
					  addtl_input, addtl_input_len);

		/* Generate the requested amount of output bits */
		lc_kmac_final_xof(kmac_ctx, out, todo);
		out += todo;
		outlen -= todo;
	}

	/* K(N + 1) is already in place as TMP(K) is stored in the key state. */

	/* Clear the KMAC state which is not needed any more. */
	lc_kmac_zero(kmac_ctx);

	return 0;
}

/*
 * The DRNG is seeded by initializing a fast-key-erasure KMAC context and add
 * the key into the KMAC state. The KMAC XOF final operation replaces the
 * key in state.
 *
 * This applies the KMAC DRNG specification section 2.2.
 */
static int
lc_kmac256_drng_seed(void *_state,
		     const uint8_t *seed, size_t seedlen,
		     const uint8_t *persbuf, size_t perslen)
{
	struct lc_kmac256_drng_state *state = _state;
	LC_KMAC_CTX_ON_STACK(kmac_ctx, lc_cshake256);

	if (!state)
		return -EINVAL;

	/*
	 * Initialize the KMAC with K(N) and the cust. string. During initial
	 * seeding K(N) is a zero buffer.
	 */
	lc_kmac_init(kmac_ctx, state->key, LC_KMAC256_DRNG_KEYSIZE,
		     (uint8_t *)LC_KMAC_DRNG_SEED_CUSTOMIZATION_STRING,
		     sizeof(LC_KMAC_DRNG_SEED_CUSTOMIZATION_STRING) - 1);

	/* Insert the seed data into the KMAC state. */
	lc_kmac_update(kmac_ctx, seed, seedlen);

	/* Insert the personalization string into the KMAC state. */
	lc_kmac_update(kmac_ctx, persbuf, perslen);

	/* Generate the K(N + 1) to store in the state and overwrite K(N). */
	lc_kmac_final_xof(kmac_ctx, state->key, LC_KMAC256_DRNG_KEYSIZE);

	/* Clear the KMAC state which is not needed any more. */
	lc_kmac_zero(kmac_ctx);

	return 0;
}

static void lc_kmac256_drng_zero(void *_state)
{
	struct lc_kmac256_drng_state *state = _state;

	if (!state)
		return;

	memset_secure((uint8_t *)state, 0, LC_KMAC256_DRNG_STATE_SIZE);
}

LC_INTERFACE_FUNCTION(
int, lc_kmac256_drng_alloc, struct lc_rng_ctx **state)
{
	struct lc_rng_ctx *out_state = NULL;
	int ret;

	if (!state)
		return -EINVAL;

	ret = posix_memalign((void *)&out_state, sizeof(uint64_t),
			     LC_KMAC256_DRNG_CTX_SIZE);
	if (ret)
		return -ret;

	/* prevent paging out of the memory state to swap space */
	ret = mlock(out_state, sizeof(*out_state));
	if (ret && errno != EPERM && errno != EAGAIN) {
		int errsv = errno;

		free(out_state);
		return -errsv;
	}

	LC_KMAC256_RNG_CTX(out_state);

	lc_kmac256_drng_zero(out_state->rng_state);

	*state = out_state;

	return 0;
}

static const struct lc_rng _lc_kmac256_drng = {
	.generate	= lc_kmac256_drng_generate,
	.seed		= lc_kmac256_drng_seed,
	.zero		= lc_kmac256_drng_zero,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *, lc_kmac256_drng) = &_lc_kmac256_drng;
