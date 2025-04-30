/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "lc_hqc.h"
#include "lc_rng.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "timecop.h"
#include "visibility.h"

static int hqc_official(enum lc_hqc_type type)
{
	struct workspace {
		struct lc_hqc_sk sk;
		struct lc_hqc_pk pk;
		struct lc_hqc_ct ct;
		struct lc_hqc_ss ss, ss2;
		uint8_t ss3[10], ss4[10];
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_hqc_keypair(&ws->pk, &ws->sk, lc_seeded_rng, type));

	if (ws->pk.hqc_type != type || ws->sk.hqc_type != type) {
		printf("HQC type error pk/sk\n");
		goto out;
	}

	// if (lc_hqc_pct(&ws->pk, &ws->sk)) {
	// 	printf("HQC PCT failed\n");
	// 	goto out;
	// }

	/* modify type to get error */
	ws->pk.hqc_type = 123;
	if (lc_hqc_enc(&ws->ct, &ws->ss, &ws->pk) != -EOPNOTSUPP) {
		printf("Unexpected error enc 1\n");
		ret = 1;
		goto out;
	}

	/* positive operation */
	ws->pk.hqc_type = type;
	CKINT_LOG(lc_hqc_enc(&ws->ct, &ws->ss, &ws->pk),
		  "Unexpected error enc 2\n");

	if (ws->ct.hqc_type != type) {
		printf("HQC type error ct\n");
		ret = 1;
		goto out;
	}

	/* positive operation */
	ws->sk.hqc_type = type;
	CKINT_LOG(lc_hqc_dec(&ws->ss2, &ws->ct, &ws->sk),
		  "Unexpected error dec 2\n");

	unpoison(&ws->ss, sizeof(ws->ss));
	unpoison(&ws->ss2, sizeof(ws->ss));
	if (memcmp(&ws->ss, &ws->ss2, sizeof(ws->ss))) {
		printf("Shared secrets do not match\n");
		ret = 1;
		goto out;
	}

	/* positive operation */
	ws->pk.hqc_type = type;
	CKINT_LOG(lc_hqc_enc_kdf(&ws->ct, ws->ss3, sizeof(ws->ss3), &ws->pk),
		  "Unexpected error enc 3\n");

	if (ws->ct.hqc_type != type) {
		printf("HQC type error ct\n");
		ret = 1;
		goto out;
	}

	/* positive operation */
	ws->sk.hqc_type = type;
	CKINT_LOG(lc_hqc_dec_kdf(ws->ss4, sizeof(ws->ss4), &ws->ct, &ws->sk),
		  "Unexpected error dec 3\n");

	unpoison(ws->ss3, sizeof(ws->ss3));
	unpoison(ws->ss4, sizeof(ws->ss4));
	if (memcmp(&ws->ss3, &ws->ss4, sizeof(ws->ss3))) {
		printf("Shared secrets from KDF do not match\n");
		ret = 1;
		goto out;
	}

out:
	LC_RELEASE_MEM(ws);
	if (ret == -EOPNOTSUPP)
		return 77;
	return !!ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0, rc;

	(void)argc;
	(void)argv;

#ifdef LC_HQC_256_ENABLED
	rc = hqc_official(LC_HQC_256);
	if (rc == 77)
		return rc;
	ret += rc;
#endif
#ifdef LC_HQC_192_ENABLED
	rc += hqc_official(LC_HQC_192);
	if (rc == 77)
		return rc;
	ret += rc;
#endif
#ifdef LC_HQC_128_ENABLED
	rc += hqc_official(LC_HQC_128);
	if (rc == 77)
		return rc;
	ret += rc;
#endif

	return ret;
}
