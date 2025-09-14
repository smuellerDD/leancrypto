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
#include "lc_x25519.h"
#include "compare.h"
#include "ret_checkers.h"
#include "static_rng.h"
#include "test_helper_common.h"
#include "visibility.h"

static int x25519_keygen_tester(void)
{
	static const struct lc_x25519_sk sk_orig = {
		.sk = { 0x80, 0x52, 0x03, 0x03, 0x76, 0xd4, 0x71, 0x12,
			0xbe, 0x7f, 0x73, 0xed, 0x7a, 0x01, 0x92, 0x93,
			0xdd, 0x12, 0xad, 0x91, 0x0b, 0x65, 0x44, 0x55,
			0x79, 0x8b, 0x46, 0x67, 0xd7, 0x3d, 0xe1, 0x66 }
	};
	static const struct lc_x25519_pk pk_orig = {
		.pk = { 0xf1, 0x81, 0x4f, 0x0e, 0x8f, 0xf1, 0x04, 0x3d,
			0x8a, 0x44, 0xd2, 0x5b, 0xab, 0xff, 0x3c, 0xed,
			0xca, 0xe6, 0xc2, 0x2c, 0x3e, 0xda, 0xa4, 0x8f,
			0x85, 0x7a, 0xe7, 0x0d, 0xe2, 0xba, 0xae, 0x50 }
	};
	struct lc_static_rng_data static_data = {
		.seed = sk_orig.sk,
		.seedlen = LC_X25519_SECRETKEYBYTES,
	};
	LC_STATIC_DRNG_ON_STACK(static_drng, &static_data);
	struct lc_x25519_pk pk;
	struct lc_x25519_sk sk;
	int ret;

	CKINT(lc_x25519_keypair(&pk, &sk, &static_drng));

	if (lc_compare(sk.sk, sk_orig.sk, sizeof(sk.sk),
		       "X25519 key generation secret key\n"))
		goto out;
	lc_compare(pk.pk, pk_orig.pk, sizeof(pk.pk),
		   "X25519 key generation public key\n");

out:
	return !!ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
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

	ret |= x25519_keygen_tester();

	if (cpu_feature_enable)
		lc_cpu_feature_enable();

	ret = test_validate_status(ret, LC_ALG_STATUS_X25519_KEYGEN);
	ret += test_print_status();

	return ret;
}
