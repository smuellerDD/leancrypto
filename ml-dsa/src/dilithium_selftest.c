/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "dilithium_selftest.h"
#include "fips_mode.h"
#include "selftest_rng.h"
#include "small_stack_support.h"

/*
 * Use rejection test vector which will cover all rejection code paths
 * as generated with the dilithium_edge_case_tester.
 *
 * For FIPS 140: The test vectors cover the requirements of IG 10.3.A.
 */
#if LC_DILITHIUM_MODE == 2
#include "../tests/dilithium_pure_rejection_vectors_44.h"
#elif LC_DILITHIUM_MODE == 3
#include "../tests/dilithium_pure_rejection_vectors_65.h"
#elif LC_DILITHIUM_MODE == 5
#include "../tests/dilithium_pure_rejection_vectors_87.h"
#endif

static int _dilithium_keypair_tester(int (*_lc_dilithium_keypair_from_seed)(
				      struct lc_dilithium_pk *pk,
				      struct lc_dilithium_sk *sk,
				      const uint8_t *seed, size_t seedlen))
{
	struct workspace {
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sk sk;
	};
	const struct dilithium_rejection_testvector *tc =
		&dilithium_rejection_testvectors[0];
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	_lc_dilithium_keypair_from_seed(&ws->pk, &ws->sk, tc->seed,
					sizeof(tc->seed));

	/*
	 * IG 10.3.A: it is not required to validate pk as it is part of sk.
	 */
#if 0
	if (lc_compare_selftest(LC_ALG_STATUS_MLDSA_KEYGEN, ws->pk.pk, tc->pk,
				LC_DILITHIUM_PUBLICKEYBYTES, "ML-DSA keygen PK")
		goto out;
#endif

	lc_compare_selftest(LC_ALG_STATUS_MLDSA_KEYGEN, ws->sk.sk, tc->sk,
			    LC_DILITHIUM_SECRETKEYBYTES, "ML-DSA keygen SK");

	LC_RELEASE_MEM(ws);
	return 0;
}

void dilithium_keypair_tester(int (*_lc_dilithium_keypair_from_seed)(
				      struct lc_dilithium_pk *pk,
				      struct lc_dilithium_sk *sk,
				      const uint8_t *seed, size_t seedlen))
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_MLDSA_KEYGEN);
	_dilithium_keypair_tester(_lc_dilithium_keypair_from_seed);
}

static int _dilithium_siggen_tester(
	int (*_lc_dilithium_sign)(struct lc_dilithium_sig *sig,
				  struct lc_dilithium_ctx *ctx,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_dilithium_sig sig;
	};
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	const struct dilithium_rejection_testvector *tc =
		&dilithium_rejection_testvectors[0];
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	_lc_dilithium_sign(&ws->sig, ctx, tc->msg, sizeof(tc->msg),
			   (struct lc_dilithium_sk *)tc->sk, NULL);
	lc_compare_selftest(LC_ALG_STATUS_MLDSA_SIGGEN, ws->sig.sig, tc->sig,
			    LC_DILITHIUM_CRYPTO_BYTES, "ML-DSA siggen");

	LC_RELEASE_MEM(ws);
	lc_dilithium_ctx_zero(ctx);
	return 0;
}

void dilithium_siggen_tester(
	int (*_lc_dilithium_sign)(struct lc_dilithium_sig *sig,
				  struct lc_dilithium_ctx *ctx,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx))
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_MLDSA_SIGGEN);
	_dilithium_siggen_tester(_lc_dilithium_sign);
}

void dilithium_sigver_tester(
	int (*_lc_dilithium_verify)(const struct lc_dilithium_sig *sig,
				    struct lc_dilithium_ctx *ctx,
				    const uint8_t *m, size_t mlen,
				    const struct lc_dilithium_pk *pk))
{
	int ret, exp;
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	const struct dilithium_rejection_testvector *tc =
		&dilithium_rejection_testvectors[0];

	LC_SELFTEST_RUN(LC_ALG_STATUS_MLDSA_SIGVER);

	exp = 0;
	ret = _lc_dilithium_verify((struct lc_dilithium_sig *)tc->sig, ctx,
				   tc->msg, sizeof(tc->msg),
				   (struct lc_dilithium_pk *)tc->pk);
	lc_dilithium_ctx_zero(ctx);

	lc_compare_selftest(LC_ALG_STATUS_MLDSA_SIGVER, (uint8_t *)&ret,
			    (uint8_t *)&exp, sizeof(ret), "ML-DSA sigver");
}
