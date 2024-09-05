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

#include "bike_tester_vectors_l1.h"
#include "compare.h"
#include "static_rng.h"
#include "ret_checkers.h"
#include "visibility.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static int bike_tester_one(const struct lc_bike_testvector *vector)
{
	struct lc_bike_pk pk;
	struct lc_bike_sk sk;
	struct lc_bike_ct ct;
	struct lc_bike_ss ss, ss2;
	struct lc_static_rng_data static_data = {
		.seed = vector->seed,
		.seedlen = sizeof(vector->seed),
	};
	int ret, rc = 0;
	LC_STATIC_DRNG_ON_STACK(sdrng, &static_data);

	//memcpy(&pk, vector->pk, sizeof(pk));
	//memcpy(&sk, vector->sk, sizeof(sk));
	//memcpy(&ct, vector->ct, sizeof(ct));
	//memcpy(&ss, vector->ss, sizeof(ss));

	CKINT(lc_bike_keypair(&pk, &sk, &sdrng));

	rc += lc_compare((uint8_t *)&pk, vector->pk, sizeof(pk), "BIKE PK");
	rc += lc_compare((uint8_t *)&sk, vector->sk, sizeof(sk), "BIKE SK");

	CKINT(lc_bike_enc(&ct, &ss, &pk, &sdrng));
	rc += lc_compare((uint8_t *)&ct, vector->ct, sizeof(ct), "BIKE Enc CT");
	rc += lc_compare((uint8_t *)&ss, vector->ss, sizeof(ss), "BIKE Enc SS");

	CKINT(lc_bike_dec(&ss2, &ct, &sk));
	rc += lc_compare((uint8_t *)&ss2, vector->ss, sizeof(ss2), "BIKE Dec SS");

out:
	return ret ? ret : rc;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	unsigned int i;
	int ret = 0;

	(void)argc;
	(void)argv;

	for (i = 0; i < ARRAY_SIZE(bike_test); i++) {
		ret += bike_tester_one(&bike_test[i]);
	}

	return ret;
}
