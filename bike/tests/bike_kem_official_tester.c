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
#include "lc_bike.h"
#include "lc_rng.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "timecop.h"
#include "visibility.h"

static int bike_official(enum lc_bike_type type)
{
	struct workspace {
		struct lc_bike_sk sk;
		struct lc_bike_pk pk;
		struct lc_bike_ct ct;
		struct lc_bike_ss ss, ss2;
		uint8_t ss3[10], ss4[10];
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_bike_keypair(&ws->pk, &ws->sk, lc_seeded_rng, type));

	if (ws->pk.bike_type != type || ws->sk.bike_type != type) {
		printf("BIKE type error pk/sk\n");
		goto out;
	}

	// if (lc_bike_pct(&ws->pk, &ws->sk)) {
	// 	printf("BIKE PCT failed\n");
	// 	goto out;
	// }

	/* modify type to get error */
	ws->pk.bike_type = 123;
	if (lc_bike_enc(&ws->ct, &ws->ss, &ws->pk) != -EOPNOTSUPP) {
		printf("Unexpected error enc 1\n");
		ret = 1;
		goto out;
	}

	/* positive operation */
	ws->pk.bike_type = type;
	CKINT_LOG(lc_bike_enc(&ws->ct, &ws->ss, &ws->pk),
		  "Unexpected error enc 2\n");

	if (ws->ct.bike_type != type) {
		printf("BIKE type error ct\n");
		ret = 1;
		goto out;
	}

	/* positive operation */
	ws->sk.bike_type = type;
	CKINT_LOG(lc_bike_dec(&ws->ss2, &ws->ct, &ws->sk),
		  "Unexpected error dec 2\n");

	unpoison(&ws->ss, sizeof(ws->ss));
	unpoison(&ws->ss2, sizeof(ws->ss));
	if (memcmp(&ws->ss, &ws->ss2, sizeof(ws->ss))) {
		printf("Shared secrets do not match\n");
		ret = 1;
		goto out;
	}

	/* positive operation */
	ws->pk.bike_type = type;
	CKINT_LOG(lc_bike_enc_kdf(&ws->ct, ws->ss3, sizeof(ws->ss3), &ws->pk),
		  "Unexpected error enc 3\n");

	if (ws->ct.bike_type != type) {
		printf("BIKE type error ct\n");
		ret = 1;
		goto out;
	}

	/* positive operation */
	ws->sk.bike_type = type;
	CKINT_LOG(lc_bike_dec_kdf(ws->ss4, sizeof(ws->ss4), &ws->ct, &ws->sk),
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
	int ret = 0;

	(void)argc;
	(void)argv;

#ifdef LC_BIKE_5_ENABLED
	ret += bike_official(LC_BIKE_5);
#endif
#ifdef LC_BIKE_3_ENABLED
	ret += bike_official(LC_BIKE_3);
#endif
#ifdef LC_BIKE_1_ENABLED
	ret += bike_official(LC_BIKE_1);
#endif

	return ret;
}
