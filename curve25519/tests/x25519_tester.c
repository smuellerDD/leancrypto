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

/* Test vector obtained from RFC 7748 section 5.2 */
static int x25519_ss_tester(unsigned int loops)
{
	static const struct lc_x25519_pk pk = {
		.pk = { 0x72, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
			0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
			0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
			0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0xea }
	};
	static const struct lc_x25519_ss ss = {
		.ss = { 0x03, 0xad, 0x40, 0x80, 0xc2, 0x91, 0x0b, 0x5e,
			0x0b, 0xe2, 0x2f, 0x6c, 0x5f, 0x7c, 0x7e, 0x08,
			0xe6, 0x42, 0x46, 0x2e, 0xf0, 0xec, 0x93, 0xa6,
			0x54, 0xc5, 0xc3, 0x4d, 0xc9, 0x5b, 0x55, 0x6d }
	};
	static const struct lc_x25519_sk
		sk = { .sk = {
			       0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		       } };
	struct lc_x25519_ss act;
	unsigned int i;
	int ret = 0;

	for (i = 0; i < loops; i++)
		CKINT_LOG(lc_x25519_ss(&act, &pk, &sk),
			  "X25519 scalar multiplication failed\n");
out:
	lc_compare(act.ss, ss.ss, sizeof(ss.ss),
		   "X25519 scalar multiplication\n");

	return !!ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	unsigned int loops = 1;
	unsigned int cpu_feature_enable = 0;
	int argc_p = 1;
	int ret = 0;

	while (argc_p < argc) {
		/* p */
		if (*argv[argc_p] == 0x70)
			loops = 100000;
		/* c */
		if (*argv[argc_p] == 0x63) {
			lc_cpu_feature_disable();
			cpu_feature_enable = 1;
		}

		argc_p++;
	}

	ret |= x25519_ss_tester(loops);

#ifdef LINUX_KERNEL
	lc_cpu_feature_disable();
	cpu_feature_enable = 1;
	ret |= x25519_ss_tester(loops);
#endif

	if (cpu_feature_enable)
		lc_cpu_feature_enable();

	ret = test_validate_status(ret, LC_ALG_STATUS_X25519_SS);
	ret += test_print_status();

	return ret;
}
