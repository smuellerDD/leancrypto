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

#include "bike_internal.h"

#include "compare.h"
#include "cpufeatures.h"
#include "lc_rng.h"
#include "ret_checkers.h"
#include "visibility.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static int bike_tester_perf_one(void)
{
	struct lc_bike_pk pk;
	struct lc_bike_sk sk;
	struct lc_bike_ct ct;
	struct lc_bike_ss ss, ss2;
	int ret;

	CKINT(lc_bike_keypair(&pk, &sk, lc_seeded_rng));
	CKINT(lc_bike_enc(&ct, &ss, &pk));
	CKINT(lc_bike_dec(&ss2, &ct, &sk));

out:
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	unsigned int i;
	int ret = 0;

	(void)argv;

	/* Disable any accelerations when there is one parameter */
	if (argc > 1)
		lc_cpu_feature_disable();

	for (i = 0; i < 200; i++) {
		ret += bike_tester_perf_one();
	}

	return ret;
}
