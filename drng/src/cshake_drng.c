/* Fast-Key-Erasure cSHAKE256 DRNG
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
 * generation services. The DRNG is based on the customizable extendable output
 * function cSHAKE which in turn is based on the KECCAK algorithm. The
 * deterministic random number generator is intended to support a wide range of
 * applications and requirements, and is conservative in its resource
 * consumption.
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
 * strings named cSHAKE DRNG. The DRNG is based on the customizable extendable
 * output function cSHAKE which in turn is based on the KECCAK algorithm as
 * specified in [SP800-185].
 *
 * The cSHAKE algorithm is a customizable version of SHAKE which in turn is
 * based on KECCAK with its sponge construction of the absorb phase and squeeze
 * phase. The cSHAKE DRNG uses the absorb phase to insert the cSHAKE DRNG key
 * data believed to contain entropy. In a second step, the KECCAK squeeze phase
 * is applied to generate a random bit stream of the size requested by the
 * consumer. The KECCAK squeeze phase generates a pseudorandom bit stream of the
 * desired length. The number of the output bits depend on the specific
 * cryptographic algorithms for which the random bit stream is needed.
 *
 * The cSHAKE key is generated with the seed operation that consumes the
 * currently used cSHAKE key and the seed data with a cSHAKE operation to
 * generate a new cSHAKE key. The use of the cSHAKE operation to process seed
 * data ensures that input data without a uniform distribution is converted into
 * a cSHAKE key to be uniformly distributed. This allows inserting seed data
 * that only partially contains entropy, including the insertion of nonces,
 * personalization strings or other data in any order the caller desires. Thus,
 * the goal of the seed operation is to compress the possibly dispersed entropy
 * of the input data into a cryptographically strong cSHAKE key which is used to
 * generate random bit streams from.
 *
 * The DRNG state management applies the fast-key-erasure mechanism as defined
 * in [FKE] to ensure "backtracking resistance" in NIST terminology (also called
 * "forward secrecy"). To ensure a key is only used for a limited amount of
 * generated random bits, the fast-key-erasure mechanism is applied at least
 * after generating of a hundred times the cSHAKE256 block size number of random
 * bits.
 *
 * The state to be maintained for the life-time of the cSHAKE DRNG is only its
 * key as the cSHAKE operation is transient in nature.
 *
 * The cSHAKE DRNG conceptually is very similar to the extract and expand
 * approach of the HKDF algorithm specified in [RFC5869].
 *
 * 2. cSHAKE-based Deterministic Random Number Generator (cSHAKE-DRNG)
 *
 * 2.1 Notation
 *
 * The cSHAKE-hash denotes the cSHAKE256 function [SP800-185]. The cSHAKE-hash
 * has 4 arguments: the main input bit string X, the requested output length L
 * in bits, a function-name bit string, and an optional customization bit
 * string S.
 *
 * The inputs to the cSHAKE-hash function are specified with references to these
 * parameters.
 *
 * 2.2 Seeding
 *
 * cSHAKE-Seeding(K(N), seed, personalization string) -> K(N + 1)
 *
 * Inputs:
 *   K(N): The current cSHAKE DRNG key used by the current instance of the
 *         cSHAKE DRNG. If the cSHAKE DRNG is initialized and therefore no current
 *         key exists, a zero string of 512 bits size is used.
 *
 *   seed: The caller-provided seed material that contains entropy.
 *
 * Output:
 *   K(N + 1): A new cSHAKE DRNG key that is used for instantiating the cSHAKE hash
 *             during the next generate or seed phase.
 *
 * The seeding of the cSHAKE DRNG is performed as follows:
 *
 * K(N + 1) = cSHAKE(N = "cSHAKE-DRNG seed",
 *                   X = seed || personalization string,
 *                   L = 512
 *                   S = K(N))
 *
 * 2.3. Generating One Block of Random Bit Stream
 *
 * cSHAKE-Generate(K(N), additional input, length) -> K(N + 1), random bit stream
 *
 * Inputs:
 *   K(N): The current cSHAKE DRNG key of 512 bits size.
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
 *   K(N + 1): A new cSHAKE DRNG key that is used for instantiating the cSHAKE
 *             hash during the next generate or seed operation.
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
 * R = cSHAKE(N = "cSHAKE-DRNG generate",
 *            X = additional input,
 *            L = 512 + length,
 *            S = K(N))
 *
 * 2.4. Generating Random Bit Stream of Arbitrary Length
 *
 * Input:
 *   K(N): The cSHAKE key of 512 bits size generated with the previous generate
 *         or seed operation.
 *
 *   additional input: The optional additional input may be used to further
 *                     alter the generated random bit stream.
 *
 *   length: The length of the random bit stream to be generated in bits.
 *
 * Output
 *   K(N + 1): A new cSHAKE DRNG key that is used for instantiating the cSHAKE
 *             hash during the next generate or seed operation.
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
 * (TMP_K(1), R(1)) = cSHAKE-Generate(TMP_K(0), additional input, B)
 * (TMP_K(2), R(2)) = cSHAKE-Generate(TMP_K(1), additional input, B)
 * ...
 * (TMP_K(N), R(N)) = cSHAKE-Generate(TMP_K(N - 1), additional input, B)
 *
 * 3. Rationale
 *
 * The cSHAKE DRNG key size of 512 bits is chosen based on the following
 * considerations:
 *
 * * During instantiation of cSHAKE the given key size allows the limitation of
 *   KECCAK operations to one: The KECCAK operation is caused by the cSHAKE
 *   initialization considering that the length of the key, the cSHAKE256
 *   customization string and the cSHAKE initialization encoding bytes together
 *   are less than the block size of cSHAKE256. This limits the number of
 *   KECCAK operations required based on the input to the absolute minimum
 *   possible based on the cSHAKE specification.
 *
 * * cSHAKE256 has a security strength of 256 bits. Thus a key size of 256 bits
 *   would be sufficient. Yet, considering that due to the fast-key-erasure
 *   mechanism the key is hashed to generate a new key, over time the repeated
 *   hash operation will decrease the amount of entropy in the key. To allow
 *   callers to insert more entropy than the security strength of cSHAKE256
 *   for offsetting this loss of entropy, the key size is set to 512 bits.
 *
 * The selection of cSHAKE as a DRNG is based on the statement in [SP800-185]
 * declaring Keccak is usable as a pseudorandom function.
 *
 * 4. Comparison with KMAC DRNG
 *
 * The cSHAKE DRNG is completely identical with the exception that the cSHAKE
 * DRNG uses cSHAKE256 and the KMAC DRNG uses KMACXOF256 as central functions.
 * The difference of the customization string is irrelevant to the cryptographic
 * strength of both.
 *
 * The handling of the key is also very similar:
 *
 * * The cSHAKE DRNG sets the key as part of the N input - the N and X input are
 *   concatenated and padded by cSHAKE to bring the entire string into multiples
 *   of a cSHAKE block. This data is inserted into the SHAKE algorithm which
 *   implies that the insertion triggers as many KECCAK operations as cSHAKE
 *   blocks are present based on the input. The cSHAKE DRNG data implies that
 *   only one cSHAKE block is present and thus one KECCAK operation is
 *   performed.
 *
 * * The KMAC DRNG sets the key compliant to the KMAC definition. KMAC sets
 *   two well-defined strings as part of the cSHAKE initialization. The cSHAKE
 *   initialization concatenates and pads the input strings to bring the entire
 *   string into multiples of a cSHAKE block. This data is inserted into the
 *   SHAKE algorithm which implies that the insertion triggers as many KECCAK
 *   operations as cSHAKE blocks are present on the input. The KMAC DRNG data
 *   implies that only one cSHAKE block is present and thus one KECCAK operation
 *   is performed. In addition, KMAC pads the key data into a string that is
 *   also multiples of a cSHAKE block in size. Again, this data is inserted
 *   into the SHAKE algorithm which again triggers as many KECCAK operations
 *   as cSHAKE blocks are present with the key-based input. The KMAC DRNG
 *   specification implies again, that only one KECCAK operation is performed.
 *
 * The rationale shows that for both, the cSHAKE DRNG and the KMAC DRNG the
 * data believed to hold entropy, the key, is inserted into the SHAKE state.
 * The additional data inserted with the KMAC operation does not contain any
 * entropy and only mixes the SHAKE state further without affecting the existing
 * entropy. Therefore, with respect to the entropy management, the cSHAKE DRNG
 * and the KMAC DRNG are considered equal.
 *
 * Considering that the cSHAKE DRNG requires only one KECCAK operation during
 * initialization whereas the KMAC DRNG requires two operations, the cSHAKE
 * DRNG requires in total only 2 KECCAK operations for generating a random
 * bit stream of 1088 - 512 = 576 bits (or less). When comparing this to the
 * KMAC DRNG, in total 3 KECCAK operations are required for generating the same
 * 576 bits (or less). This implies that the cSHAKE DRNG requires only 2/3 of
 * the processing time compared to a KMAC DRNG. It is expected that the
 * majority of all requests will be less than 576 bits, e.g. commonly 256 bits
 * for symmetric keys.
 *
 * Thus, the cSHAKE DRNG has a higher performance with a equal entropy
 * management comparing to the KMAC DRNG.
 *
 * 5. Normative References
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
 *             800-185 SHA-3 Derived Functions: cSHAKE, CSHAKE, TupleHash and
 *             ParallelHash, December 2016
 ******************************************************************************/

#include "alignment.h"
#include "build_bug_on.h"
#include "compare.h"
#include "lc_cshake256_drng.h"
#include "lc_memcmp_secure.h"
#include "math_helper.h"
#include "visibility.h"

#define LC_CSHAKE_DRNG_SEED_CUSTOMIZATION_STRING	"cSHAKE-DRNG seed"
#define LC_CSHAKE_DRNG_CTX_CUSTOMIZATION_STRING		"cSHAKE-DRNG generate"

static void cshake256_drng_selftest(int *tested, const char *impl)
{
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	static const uint8_t exp[] = {
		0xea, 0x0e, 0x76, 0x4e, 0xaa, 0x38, 0x4e, 0x67,
		0x0e, 0x8e, 0x71, 0xb9, 0xe9, 0x06, 0xc0, 0x8f,
		0x5e, 0xe8, 0x6e, 0x24, 0x09, 0x10, 0xf4, 0x81,
		0x39, 0x46, 0x71, 0x37, 0xdc, 0xa7, 0x7d, 0xab,
		0xd7, 0x51, 0x20, 0x91, 0x6f, 0xf8, 0x8a, 0x8a,
		0x49, 0x68, 0xe0, 0x82, 0x8c, 0x12, 0x9b, 0xc3,
		0xe3, 0x0b, 0x9e, 0xfc, 0x27, 0xc8, 0x66, 0xfd,
		0xfd, 0x58, 0x3d, 0x47, 0x1a, 0xb9, 0xbc, 0x7d,
		0x7e, 0x6c, 0x61, 0x86, 0x08, 0x1a, 0x90, 0x1f,
		0x54, 0x43, 0x17, 0x4a, 0x09, 0x70, 0xfb, 0x9c,
		0xac, 0x33, 0x27, 0xa4, 0x10, 0x29, 0xd0, 0x9a,
		0xd7, 0xa0, 0x69, 0x8c, 0x70, 0x95, 0x6d, 0xdc,
		0x34, 0x38, 0x85, 0xcf, 0x49, 0x12, 0x6d, 0xc9,
		0xe5, 0xdd, 0x58, 0x3b, 0xf0, 0x79, 0x11, 0x9d,
		0x54, 0xb3, 0x55, 0x06, 0xa0, 0x7f, 0xba, 0x8d,
		0x56, 0xa6, 0xa3, 0x85, 0xc3, 0xf3, 0xf0, 0x9e,
		0xff, 0x6f, 0x8c, 0x95, 0x5b, 0xb1, 0xb5, 0xfe,
		0x82, 0x7b, 0xbc, 0xbe, 0x39, 0x2d, 0x50, 0x20,
		0xe9, 0xf5, 0x79, 0x99, 0x3e, 0x47, 0xb2, 0xbc,
		0xc0, 0x03, 0x54, 0xeb, 0x0e, 0x51, 0x72, 0xf0,
		0x8d, 0x03, 0xec, 0xfe, 0xc2, 0x56, 0x90, 0x8d,
		0x34, 0xdf, 0xb0, 0xeb, 0x9f, 0xbb, 0x11, 0x40,
		0x90, 0xd9, 0xaf, 0x9e, 0xd9, 0xe8, 0xef, 0xb2,
		0x5c, 0x68, 0x4c, 0x17, 0x04, 0xd0, 0x27, 0x42,
		0xf2, 0x41, 0xbb, 0xab, 0x53, 0x6d, 0x54, 0x79,
		0xc8, 0x1c, 0x9e, 0xc9, 0xcf, 0x9e, 0x1a, 0xc6,
		0x8b, 0x86, 0xcd, 0x2c, 0x95, 0x11, 0xf6, 0xb3,
		0x91, 0xf7, 0xf0, 0xc4, 0xae, 0xb2, 0x3f, 0x4a,
		0x62, 0xff, 0x2a, 0xaf, 0xeb, 0xfa, 0x74, 0x63,
		0x5d, 0x3a, 0x61, 0x73, 0xc0, 0x9f, 0xba, 0x6c,
		0xcd, 0xc1, 0xc9, 0xd8, 0x91, 0xc0, 0xff, 0xf9,
		0xad, 0x31, 0xdc, 0x67, 0x7c, 0x80, 0x46, 0x6d,
		0x20, 0x06, 0x6a, 0x9d, 0xa0, 0x70, 0x59, 0x53,
		0xb0, 0xc0, 0x56, 0x92, 0x08, 0x81, 0x8f, 0xf7,
		0x05, 0xc2, 0xcc, 0x08, 0x81, 0xdc, 0x4e, 0x05,
		0x18, 0x1c, 0x4e, 0xd3, 0x3b, 0x2a, 0x00, 0x07,
		0x31, 0x4b, 0x16, 0xe7, 0xf3, 0x9b, 0x28, 0xbb,
		0x72, 0x5e, 0x4e, 0x2b, 0x08, 0x22, 0xcc, 0x09,
		0x2d, 0x81

	};
	uint8_t act[sizeof(exp)] __align(sizeof(uint32_t));

	LC_SELFTEST_RUN(tested);

	LC_CSHAKE256_DRNG_CTX_ON_STACK(cshake_ctx);

	lc_rng_seed(cshake_ctx, seed, sizeof(seed), NULL, 0);
	lc_rng_generate(cshake_ctx, NULL, 0, act, sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
	lc_rng_zero(cshake_ctx);
}

/*
 * Fast-key-erasure initialization of the cSHAKE context. The caller must
 * securely dispose of the initialized cSHAKE context. Additional data
 * can be squeezed from the state using lc_cshake_final_xof_more.
 *
 * This function initializes the cSHAKE context that can later be used to squeeze
 * random bits out of the cSHAKE context. The initialization happens from the key
 * found in the state. Before any random bits can be created, the first 512
 * output bits that are generated is used to overwrite the key. This implies
 * an automatic backtracking resistance as the next round to generate random
 * numbers uses the already updated key.
 *
 * When this function completes, initialized cSHAKE context can now be used
 * to generate random bits.
 *
 * This generates T(0) and T(1) of size 1088 of the cSHAKE DRNG specification
 * section 2.3.
 */
static void
cshake256_drng_fke_init_ctx(struct lc_cshake256_drng_state *state,
			    struct lc_hash_ctx *cshake_ctx,
			    const uint8_t *addtl_input, size_t addtl_input_len)
{
	/* Initialize the cSHAKE with K(N) and the cust. string. */
	lc_cshake_init(cshake_ctx,
		       (uint8_t *)LC_CSHAKE_DRNG_CTX_CUSTOMIZATION_STRING,
		       sizeof(LC_CSHAKE_DRNG_CTX_CUSTOMIZATION_STRING) - 1,
		       state->key, LC_CSHAKE256_DRNG_KEYSIZE);

	/* Insert the additional data into the cSHAKE state. */
	lc_hash_update(cshake_ctx, addtl_input, addtl_input_len);

	/* Generate the K(N + 1) to store in the state and overwrite K(N). */
	lc_cshake_final(cshake_ctx, state->key, LC_CSHAKE256_DRNG_KEYSIZE);
}

/*
 * Generating random bits is performed by initializing a transient cSHAKE state
 * with the key found in state. The initialization implies that the key in
 * the state variable is already updated before random bits are generated.
 *
 * The random bits are generated by performing a cSHAKE final operation. The
 * generation operation is chunked to ensure that the fast-key-erasure updates
 * the key when large quantities of random bits are generated.
 *
 * This generates R of the cSHAKE DRNG specification section 2.4.
 */
static int
lc_cshake256_drng_generate(void *_state,
			   const uint8_t *addtl_input, size_t addtl_input_len,
			   uint8_t *out, size_t outlen)
{
	struct lc_cshake256_drng_state *state = _state;
	LC_HASH_CTX_ON_STACK(cshake_ctx, lc_cshake256);

	BUILD_BUG_ON(LC_CSHAKE256_DRNG_MAX_CHUNK % LC_SHA3_256_SIZE_BLOCK);

	if (!state)
		return -EINVAL;

	/* The loop generates R from cSHAKE DRNG specification section 2.4. */
	while (outlen) {
		/*
		 * This operation generates R(N) from the cSHAKE DRNG
		 * specification section 2.4.
		 */
		size_t todo = min_size(outlen,
				       LC_CSHAKE256_DRNG_MAX_CHUNK -
				       LC_CSHAKE256_DRNG_KEYSIZE);

		/* Instantiate cSHAKE with TMP_K(N), generate TMP_K(N + 1). */
		cshake256_drng_fke_init_ctx(state, cshake_ctx,
					    addtl_input, addtl_input_len);

		/* Generate the requested amount of output bits */
		lc_cshake_final(cshake_ctx, out, todo);

		out += todo;
		outlen -= todo;
	}

	/* K(N + 1) is already in place as TMP(K) is stored in the key state. */

	/* Clear the cSHAKE state which is not needed any more. */
	lc_hash_zero(cshake_ctx);

	return 0;
}

/*
 * The DRNG is seeded by initializing a fast-key-erasure cSHAKE context and add
 * the key into the cSHAKE state. The cSHAKE final operation replaces the key in
 * state.
 *
 * This applies the cSHAKE DRNG specification section 2.2.
 */
static int
lc_cshake256_drng_seed(void *_state,
		       const uint8_t *seed, size_t seedlen,
		       const uint8_t *persbuf, size_t perslen)
{
	static int tested = 0;
	struct lc_cshake256_drng_state *state = _state;
	LC_HASH_CTX_ON_STACK(cshake_ctx, lc_cshake256);

	if (!state)
		return -EINVAL;

	cshake256_drng_selftest(&tested, "cSHAKE DRNG");

	/*
	 * Initialize the cSHAKE with K(N) and the cust. string. During initial
	 * seeding K(N) is a zero buffer.
	 */
	lc_cshake_init(cshake_ctx,
		       (uint8_t *)LC_CSHAKE_DRNG_SEED_CUSTOMIZATION_STRING,
		       sizeof(LC_CSHAKE_DRNG_SEED_CUSTOMIZATION_STRING) - 1,
		       state->key, LC_CSHAKE256_DRNG_KEYSIZE);

	/* Insert the seed data into the cSHAKE state. */
	lc_hash_update(cshake_ctx, seed, seedlen);

	/* Insert the personalization string into the cSHAKE state. */
	lc_hash_update(cshake_ctx, persbuf, perslen);

	/* Generate the K(N + 1) to store in the state and overwrite K(N). */
	lc_cshake_final(cshake_ctx, state->key, LC_CSHAKE256_DRNG_KEYSIZE);

	/* Clear the cSHAKE state which is not needed any more. */
	lc_hash_zero(cshake_ctx);

	return 0;
}

static void lc_cshake256_drng_zero(void *_state)
{
	struct lc_cshake256_drng_state *state = _state;

	if (!state)
		return;

	lc_memset_secure((uint8_t *)state, 0, LC_CSHAKE256_DRNG_STATE_SIZE);
}

LC_INTERFACE_FUNCTION(
int, lc_cshake256_drng_alloc, struct lc_rng_ctx **state)
{
	struct lc_rng_ctx *out_state = NULL;
	int ret;

	if (!state)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_HASH_COMMON_ALIGNMENT,
				      LC_CSHAKE256_DRNG_CTX_SIZE);
	if (ret)
		return -ret;

	LC_CSHAKE256_RNG_CTX(out_state);

	*state = out_state;

	return 0;
}

static const struct lc_rng _lc_cshake256_drng = {
	.generate	= lc_cshake256_drng_generate,
	.seed		= lc_cshake256_drng_seed,
	.zero		= lc_cshake256_drng_zero,
};
LC_INTERFACE_SYMBOL(
	const struct lc_rng *, lc_cshake256_drng) = &_lc_cshake256_drng;
