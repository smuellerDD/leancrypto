/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_internal.h"
#include "lc_sha3.h"
#include "lc_hmac.h"
#include "lc_status.h"
#include "test_helper_common.h"
#include "visibility.h"

/*
 * Test to rerun the self test.
 *
 * This test is designed to verify the FIPS integrity check in failure mode.
 */
static int rerun_selftest_tester(void)
{
	uint8_t buf[LC_SHA_MAX_SIZE_DIGEST];
	int ret = 0;

	/*
	 * In the Linux kernel there may be other callers that already
	 * triggered self-tests before.
	 */

	ret += test_validate_status(ret, LC_ALG_STATUS_LIB, 0);
#ifndef LINUX_KERNEL

#ifdef LC_FIPS140_DEBUG
	ret += test_validate_status(ret, LC_ALG_STATUS_SHA3, 1);
#else
	/* SHA3 is passed due to FIPS integrity test */
	ret += test_validate_expected_status(ret, LC_ALG_STATUS_SHA3,
					     lc_alg_status_result_pending, 1);
#endif

	ret += test_validate_expected_status(ret, LC_ALG_STATUS_HMAC,
					     lc_alg_status_result_pending, 1);

	ret += test_print_status();
#endif

	printf("Attempt to calculate HMAC\n");
	if (lc_hmac(lc_sha3_512, buf, sizeof(buf), NULL, 0, buf) !=
#ifdef LC_FIPS140_DEBUG
	    -EOPNOTSUPP
#else
	    0
#endif
	    )
		ret +=1;

	ret += test_validate_status(ret, LC_ALG_STATUS_LIB, 0);
	ret += test_validate_status(ret, LC_ALG_STATUS_SHA3, 1);
	ret += test_validate_status(ret, LC_ALG_STATUS_HMAC, 1);
	ret += test_print_status();

	printf("Rerun self tests\n");
	lc_rerun_selftests();

	ret += test_validate_status(ret, LC_ALG_STATUS_LIB, 0);

#ifdef LC_FIPS140_DEBUG
	ret += test_validate_status(ret, LC_ALG_STATUS_SHA3, 1);
#else
	/* SHA3 is passed due to FIPS integrity test */
	ret += test_validate_expected_status(ret, LC_ALG_STATUS_SHA3,
					     lc_alg_status_result_pending, 1);
#endif

	ret += test_validate_expected_status(ret, LC_ALG_STATUS_HMAC,
					     lc_alg_status_result_pending, 1);
	ret += test_print_status();

	printf("Attempt to calculate HMAC\n");
	if (lc_hmac(lc_sha3_512, buf, sizeof(buf), NULL, 0, buf) !=
#ifdef LC_FIPS140_DEBUG
	    -EOPNOTSUPP
#else
	    0
#endif
	    )
		ret +=1;

	ret += test_validate_status(ret, LC_ALG_STATUS_LIB, 0);
	ret += test_validate_status(ret, LC_ALG_STATUS_SHA3, 1);
	ret += test_validate_status(ret, LC_ALG_STATUS_HMAC, 1);
	ret += test_print_status();

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return rerun_selftest_tester();
}
