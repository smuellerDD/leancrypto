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
#include "cpufeatures.h"
#include "small_stack_support.h"
#include "sphincs_type.h"
#include "ret_checkers.h"
#include "visibility.h"

#ifdef LC_SPHINCS_TYPE_128F
#include "lc_sphincs_shake_128f.h"
#include "sphincs_tester_vectors_shake_128f.h"
#elif defined(LC_SPHINCS_TYPE_128S)
#include "lc_sphincs_shake_128s.h"
#include "sphincs_tester_vectors_shake_128s.h"
#elif defined(LC_SPHINCS_TYPE_192F)
#include "lc_sphincs_shake_192f.h"
#include "sphincs_tester_vectors_shake_192f.h"
#elif defined(LC_SPHINCS_TYPE_192S)
#include "lc_sphincs_shake_192s.h"
#include "sphincs_tester_vectors_shake_192s.h"
#elif defined(LC_SPHINCS_TYPE_256F)
#include "lc_sphincs_shake_256f.h"
#include "sphincs_tester_vectors_shake_256f.h"
#else
#include "lc_sphincs_shake_256s.h"
#include "sphincs_tester_vectors_shake_256s.h"
#endif

enum lc_sphincs_test_type {
	LC_SPHINCS_REGRESSION,
	LC_SPHINCS_PERF_KEYGEN,
	LC_SPHINCS_PERF_SIGN,
	LC_SPHINCS_PERF_VERIFY,
};

static int lc_sphincs_test(struct lc_sphincs_test *tc,
			   enum lc_sphincs_test_type t)
{
	struct workspace {
		struct lc_sphincs_pk pk;
		struct lc_sphincs_sk sk;
		struct lc_sphincs_sig sig;
	};
	unsigned int rounds, i;
	int ret;
	LC_SPHINCS_CTX_ON_STACK(ctx);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/*
	 * The entire test data derived from the upstream reference
	 * implementation covers the internal testing only.
	 */
	ctx->slh_dsa_internal = 1;

	if (t == LC_SPHINCS_REGRESSION || t == LC_SPHINCS_PERF_KEYGEN) {
		rounds = (t == LC_SPHINCS_PERF_KEYGEN) ? 100 : 1;

		for (i = 0; i < rounds; i++) {
			CKINT(lc_sphincs_keypair_from_seed(
				&ws->pk, &ws->sk, tc->seed, sizeof(tc->seed)));
		}
		lc_compare((uint8_t *)&ws->pk, tc->pk, sizeof(tc->pk), "PK");
		lc_compare((uint8_t *)&ws->sk, tc->sk, sizeof(tc->sk), "SK");
	}

	if (t == LC_SPHINCS_REGRESSION || t == LC_SPHINCS_PERF_SIGN) {
		rounds = (t == LC_SPHINCS_PERF_SIGN) ? 10 : 1;

		for (i = 0; i < rounds; i++) {
			CKINT(lc_sphincs_sign_ctx(
				&ws->sig, ctx, tc->msg, sizeof(tc->msg),
				(struct lc_sphincs_sk *)tc->sk, NULL));
		}
		lc_compare((uint8_t *)&ws->sig, tc->sig, sizeof(tc->sig),
			   "SIG");
	}

	if (t == LC_SPHINCS_REGRESSION || t == LC_SPHINCS_PERF_VERIFY) {
		rounds = (t == LC_SPHINCS_PERF_VERIFY) ? 1000 : 1;

		for (i = 0; i < rounds; i++) {
			CKINT(lc_sphincs_verify_ctx(
				(struct lc_sphincs_sig *)tc->sig, ctx, tc->msg,
				sizeof(tc->msg),
				(struct lc_sphincs_pk *)tc->pk));
		}
	}

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	enum lc_sphincs_test_type t = LC_SPHINCS_REGRESSION;
	int ret = 0, rc = 0;
	int feat_disabled = 0;

	if (argc >= 2) {
		if (argv[1][0] == 'k')
			t = LC_SPHINCS_PERF_KEYGEN;
		if (argv[1][0] == 's')
			t = LC_SPHINCS_PERF_SIGN;
		if (argv[1][0] == 'v')
			t = LC_SPHINCS_PERF_VERIFY;
		if (argv[1][0] == 'c') {
			lc_cpu_feature_disable();
			feat_disabled = 1;
		}
	}

	if (argc >= 3) {
		if (argv[2][0] == 'c') {
			lc_cpu_feature_disable();
			feat_disabled = 1;
		}
	}

#ifdef LC_SPHINCS_TESTER_C
	lc_cpu_feature_disable();
	feat_disabled = 1;
#endif

	CKINT(lc_sphincs_test(&tests[0], t));
	rc += ret;

out:
	if (feat_disabled)
		lc_cpu_feature_enable();
	return ret ? -ret : rc;
}
