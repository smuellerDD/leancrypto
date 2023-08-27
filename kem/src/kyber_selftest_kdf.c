/*
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

#include "compare.h"
#include "kyber_selftest.h"
#include "lc_kyber.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"

#if LC_KYBER_K == 2
#include "kyber_selftest_kdf_vector_512.h"
#elif LC_KYBER_K == 3
#include "kyber_selftest_kdf_vector_768.h"
#elif LC_KYBER_K == 4
#include "kyber_selftest_kdf_vector_1024.h"
#endif

static int _kyber_kem_enc_kdf_selftest(
	const char *impl,
	int (*_lc_kyber_enc_kdf)(struct lc_kyber_ct *ct, uint8_t *ss,
				 size_t ss_len, const struct lc_kyber_pk *pk,
				 struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_kyber_ct ct;
		struct lc_kyber_ss key_b;
	};
	struct rand_state rand_state;

	/*
	 * The testing is based on the fact that,
	 * - this "RNG" produces identical output
	 * - the signature generation is performed with deterministic
	 *   behavior (i.e. rng_ctx is NULL)
	 */
	struct lc_rng_ctx kyber_rng = { .rng = &kyber_drng,
					.rng_state = &rand_state };
	char str[25];
	uint8_t discard[2 * LC_KYBER_SYMBYTES];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake128);
#pragma GCC diagnostic pop

	rand_state.rng_hash_ctx = hash_ctx;

	/* Make sure to have the same rng state as the test case */
	lc_hash_init(hash_ctx);
	/* The test vector RNG state served a keygen before enc */
	lc_rng_generate(&kyber_rng, NULL, 0, discard, sizeof(discard));

	// Encapsulation
	_lc_kyber_enc_kdf(&ws->ct, ws->key_b.ss, LC_KYBER_SSBYTES,
			  &kyber_testvectors[0].pk, &kyber_rng);
	snprintf(str, sizeof(str), "%s CT", impl);
	lc_compare_selftest(ws->ct.ct, kyber_testvectors[0].ct.ct,
			    LC_CRYPTO_CIPHERTEXTBYTES, str);
	snprintf(str, sizeof(str), "%s SS", impl);
	lc_compare_selftest(ws->key_b.ss, kyber_testvectors[0].ss.ss,
			    LC_KYBER_SSBYTES, str);

	LC_RELEASE_MEM(ws);
	lc_hash_zero(hash_ctx);
	return 0;
}

void kyber_kem_enc_kdf_selftest(
	int *tested, const char *impl,
	int (*_lc_kyber_kdf_enc)(struct lc_kyber_ct *ct, uint8_t *ss,
				 size_t ss_len, const struct lc_kyber_pk *pk,
				 struct lc_rng_ctx *rng_ctx))
{
	LC_SELFTEST_RUN(tested);

	if (_kyber_kem_enc_kdf_selftest(impl, _lc_kyber_kdf_enc))
		lc_compare_selftest((uint8_t *)"test", (uint8_t *)"fail", 4,
				    impl);
}

static int _kyber_kem_dec_kdf_selftest(
	const char *impl,
	int (*_lc_kyber_dec_kdf)(uint8_t *ss, size_t ss_len,
				 const struct lc_kyber_ct *ct,
				 const struct lc_kyber_sk *sk))
{
	struct lc_kyber_ss key_a;
	char str[25];

	// Decapsulation
	_lc_kyber_dec_kdf(key_a.ss, LC_KYBER_SSBYTES, &kyber_testvectors[0].ct,
			  &kyber_testvectors[0].sk);
	snprintf(str, sizeof(str), "%s SS", impl);
	lc_compare_selftest(key_a.ss, kyber_testvectors[0].ss.ss,
			    LC_KYBER_SSBYTES, str);

	return 0;
}

void kyber_kem_dec_kdf_selftest(
	int *tested, const char *impl,
	int (*_lc_kyber_kdf_dec)(uint8_t *ss, size_t ss_len,
				 const struct lc_kyber_ct *ct,
				 const struct lc_kyber_sk *sk))
{
	LC_SELFTEST_RUN(tested);

	if (_kyber_kem_dec_kdf_selftest(impl, _lc_kyber_kdf_dec))
		lc_compare_selftest((uint8_t *)"test", (uint8_t *)"fail", 4,
				    impl);
}
