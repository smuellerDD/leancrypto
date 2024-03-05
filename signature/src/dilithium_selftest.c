/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "selftest_rng.h"
#include "small_stack_support.h"

#if LC_DILITHIUM_MODE == 2
#include "dilithium_selftest_vector_44.h"
#elif LC_DILITHIUM_MODE == 3
#include "dilithium_selftest_vector_65.h"
#else
#include "dilithium_selftest_vector_87.h"
#endif

static int _dilithium_keypair_tester(
	const char *impl,
	int (*_lc_dilithium_keypair)(struct lc_dilithium_pk *pk,
				     struct lc_dilithium_sk *sk,
				     struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_dilithium_pk pk;
		struct lc_dilithium_sk sk;
	};
	char str[25];
	uint8_t discard[32];
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	/* The test vector RNG state served a message gen before keygen */
	lc_rng_generate(selftest_rng, NULL, 0, discard, sizeof(discard));

	_lc_dilithium_keypair(&ws->pk, &ws->sk, selftest_rng);
	snprintf(str, sizeof(str), "%s PK", impl);
	lc_compare_selftest(ws->pk.pk, vector.pk.pk,
			    LC_DILITHIUM_PUBLICKEYBYTES, str);
	snprintf(str, sizeof(str), "%s SK", impl);
	lc_compare_selftest(ws->sk.sk, vector.sk.sk,
			    LC_DILITHIUM_PUBLICKEYBYTES, str);

	LC_RELEASE_MEM(ws);
	lc_rng_zero(selftest_rng);
	return 0;
}

void dilithium_keypair_tester(
	int *tested, const char *impl,
	int (*_lc_dilithium_keypair)(struct lc_dilithium_pk *pk,
				     struct lc_dilithium_sk *sk,
				     struct lc_rng_ctx *rng_ctx))
{
	LC_SELFTEST_RUN(tested);

	if (_dilithium_keypair_tester(impl, _lc_dilithium_keypair))
		lc_compare_selftest((uint8_t *)"test", (uint8_t *)"fail", 4,
				    impl);
}

static int _dilithium_siggen_tester(
	const char *impl,
	int (*_lc_dilithium_sign)(struct lc_dilithium_sig *sig,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_dilithium_sig sig;
	};
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	_lc_dilithium_sign(&ws->sig, vector.m, sizeof(vector.m), &vector.sk,
			   NULL);
	lc_compare_selftest(ws->sig.sig, vector.sig.sig,
			    LC_DILITHIUM_CRYPTO_BYTES, impl);

	LC_RELEASE_MEM(ws);
	return 0;
}

void dilithium_siggen_tester(
	int *tested, const char *impl,
	int (*_lc_dilithium_sign)(struct lc_dilithium_sig *sig,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx))
{
	LC_SELFTEST_RUN(tested);

	if (_dilithium_siggen_tester(impl, _lc_dilithium_sign))
		lc_compare_selftest((uint8_t *)"test", (uint8_t *)"fail", 4,
				    impl);
}

void dilithium_sigver_tester(
	int *tested, const char *impl,
	int (*_lc_dilithium_verify)(const struct lc_dilithium_sig *sig,
				    const uint8_t *m, size_t mlen,
				    const struct lc_dilithium_pk *pk))
{
	int ret, exp;

	LC_SELFTEST_RUN(tested);

	exp = 0;
	ret = _lc_dilithium_verify(&vector.sig, vector.m, sizeof(vector.m),
				   &vector.pk);

	lc_compare_selftest((uint8_t *)&ret, (uint8_t *)&exp, sizeof(ret),
			    impl);
}
