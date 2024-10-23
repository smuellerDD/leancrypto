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

#include "compare.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "sphincs_selftest.h"
#include "static_rng.h"

/*
 * Define the tests symbol rename at this location only to limit the renaming
 * to the library internal code. The reason is that the test code uses this
 * symbol too which would cause symbol duplication if the rename is applied
 * in the test as well.
 */
#define tests SPHINCS_F(tests)

#ifdef LC_SPHINCS_TYPE_128F
#include "lc_sphincs_shake_128f.h"
#include "../tests/sphincs_tester_vectors_shake_128f.h"
#elif defined(LC_SPHINCS_TYPE_128S)
#include "lc_sphincs_shake_128s.h"
#include "../tests/sphincs_tester_vectors_shake_128s.h"
#elif defined(LC_SPHINCS_TYPE_192F)
#include "lc_sphincs_shake_192f.h"
#include "../tests/sphincs_tester_vectors_shake_192f.h"
#elif defined(LC_SPHINCS_TYPE_192S)
#include "lc_sphincs_shake_192s.h"
#include "../tests/sphincs_tester_vectors_shake_192s.h"
#elif defined(LC_SPHINCS_TYPE_256F)
#include "lc_sphincs_shake_256f.h"
#include "../tests/sphincs_tester_vectors_shake_256f.h"
#else
#include "lc_sphincs_shake_256s.h"
#include "../tests/sphincs_tester_vectors_shake_256s.h"
#endif

static inline int _sphincs_selftest_keygen(void)
{
	struct workspace {
		struct lc_sphincs_pk pk;
		struct lc_sphincs_sk sk;
	};
	const struct lc_sphincs_test *tc = &tests[0];
	int ret;
	struct lc_static_rng_data s_rng_state;
	LC_STATIC_DRNG_ON_STACK(s_drng, &s_rng_state);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	s_rng_state.seed = tc->seed;
	s_rng_state.seedlen = sizeof(tc->seed);
	CKINT(lc_sphincs_keypair(&ws->pk, &ws->sk, &s_drng));

	lc_compare_selftest((uint8_t *)&ws->pk, tc->pk, sizeof(tc->pk), "PK");
	lc_compare_selftest((uint8_t *)&ws->sk, tc->sk, sizeof(tc->sk), "SK");

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

void sphincs_selftest_keygen(int *tested)
{
	LC_SELFTEST_RUN(tested);

	if (_sphincs_selftest_keygen())
		lc_compare_selftest((uint8_t *)"test", (uint8_t *)"fail", 4,
				    "Return code");
}

static inline int _sphincs_selftest_siggen(void)
{
	struct workspace {
		struct lc_sphincs_sig sig;
	};
	const struct lc_sphincs_test *tc = &tests[0];
	int ret;
	LC_SPHINCS_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/*
	 * The entire test data derived from the upstream reference
	 * implementation covers the internal testing only.
	 */
	ctx->slh_dsa_internal = 1;

	CKINT(lc_sphincs_sign_ctx(&ws->sig, ctx, tc->msg, sizeof(tc->msg),
				  (struct lc_sphincs_sk *)tc->sk, NULL));
	lc_compare((uint8_t *)&ws->sig, tc->sig, sizeof(tc->sig), "SIG");

out:
	lc_sphincs_ctx_zero(ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

void sphincs_selftest_siggen(int *tested)
{
	LC_SELFTEST_RUN(tested);

	if (_sphincs_selftest_siggen())
		lc_compare_selftest((uint8_t *)"test", (uint8_t *)"fail", 4,
				    "Return code");
}

static inline int _sphincs_selftest_sigver(void)
{
	struct workspace {
		struct lc_sphincs_pk pk;
		struct lc_sphincs_sk sk;
		struct lc_sphincs_sig sig;
	};
	const struct lc_sphincs_test *tc = &tests[0];
	int ret;
	LC_SPHINCS_CTX_ON_STACK(ctx);

	/*
	 * The entire test data derived from the upstream reference
	 * implementation covers the internal testing only.
	 */
	ctx->slh_dsa_internal = 1;

	CKINT(lc_sphincs_verify_ctx((struct lc_sphincs_sig *)tc->sig, ctx,
				    tc->msg, sizeof(tc->msg),
				    (struct lc_sphincs_pk *)tc->pk));

out:
	lc_sphincs_ctx_zero(ctx);
	return ret;
}

void sphincs_selftest_sigver(int *tested)
{
	LC_SELFTEST_RUN(tested);

	if (_sphincs_selftest_sigver())
		lc_compare_selftest((uint8_t *)"test", (uint8_t *)"fail", 4,
				    "Return code");
}
