/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include "lc_rng.h"
#include "lc_sntrup.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

struct workspace {
	struct lc_sntrup_pk pk;
	struct lc_sntrup_sk sk;
	struct lc_sntrup_ct ct;
	struct lc_sntrup_ss ss, ss2;
};

static int sntrup_tester_perf_one(struct workspace *ws,
				  enum lc_sntrup_type sntrup_type)
{
	int ret;

	CKINT_LOG(lc_sntrup_keypair(&ws->pk, &ws->sk, lc_seeded_rng,
				    sntrup_type),
		  "SNTRUP keypair failed: %d\n", ret);
	CKINT_LOG(lc_sntrup_enc(&ws->ct, &ws->ss, &ws->pk),
		  "SNTRUP encapsulation failed: %d\n", ret);
	CKINT_LOG(lc_sntrup_dec(&ws->ss2, &ws->ct, &ws->sk),
		  "SNTRUP decapsulation failed: %d\n", ret);

out:
	if (ret == -EOPNOTSUPP)
		ret = 77;
	return ret;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-larger-than="
LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	unsigned long type;
	unsigned int i;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (argc < 1) {
		printf("TInvoke tester with parameter type\n");
		return -EOPNOTSUPP;
	}

	type = strtoul(argv[1], NULL, 10);
	if (type > 10) {
		printf("TInvoke tester with parameter type\n");
		return -EOPNOTSUPP;
	}

	/* Disable any accelerations when there is one parameter */
	if (argc > 2)
		lc_cpu_feature_disable();

	for (i = 0; i < 10000; i++) {
		ret = sntrup_tester_perf_one(ws, (enum lc_sntrup_type)type);
		if (ret)
			break;
	}

	/* Enable any accelerations when there is one parameter */
	if (argc > 2)
		lc_cpu_feature_enable();

	LC_RELEASE_MEM(ws);
	return ret;
}
#pragma GCC diagnostic pop
