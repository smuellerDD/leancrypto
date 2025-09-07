/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "cpufeatures.h"
#include "ext_headers_internal.h"
#include "lc_x448.h"
#include "compare.h"
#include "ret_checkers.h"
#include "static_rng.h"
#include "visibility.h"

static int x448_keygen_tester(void)
{
	/* Test vector obtained from RFC 7748 section 6.2. */
	static const struct lc_x448_sk sk_orig = {
		.sk = { 0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
			0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
			0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
			0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
			0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
			0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
			0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b }
	};
	static const struct lc_x448_pk pk_orig = {
		.pk = { 0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
			0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
			0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
			0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
			0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
			0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
			0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0 }
	};
	struct lc_static_rng_data static_data = {
		.seed = sk_orig.sk,
		.seedlen = LC_X448_SECRETKEYBYTES,
	};
	LC_STATIC_DRNG_ON_STACK(static_drng, &static_data);
	struct lc_x448_pk pk;
	struct lc_x448_sk sk;
	int ret;

	CKINT(lc_x448_keypair(&pk, &sk, &static_drng));

	lc_compare(sk.sk, sk_orig.sk, sizeof(sk.sk),
		   "X448 key generation secret key\n");
	lc_compare(pk.pk, pk_orig.pk, sizeof(pk.pk),
		   "X448 key generation public key\n");

out:
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	char status[900];
	unsigned int cpu_feature_enable = 0;
	int argc_p = 1;
	int ret = 0;

	while (argc_p < argc) {
		/* c */
		if (*argv[argc_p] == 0x63) {
			lc_cpu_feature_disable();
			cpu_feature_enable = 1;
		}

		argc_p++;
	}

	ret |= x448_keygen_tester();

	if (cpu_feature_enable)
		lc_cpu_feature_enable();

	if (lc_status_get_result(LC_ALG_STATUS_X448_KEYKEN) !=
	    lc_alg_status_result_passed) {
		printf("X448 keygen self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_X448_KEYKEN));
		return 1;
	}

	memset(status, 0, sizeof(status));
	lc_status(status, sizeof(status));
	if (strlen(status) == 0)
		ret = 1;
	printf("Status information from leancrypto:\n%s", status);


	return ret;
}
