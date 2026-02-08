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
#include "fips_mode.h"
#include "lc_sha256.h"
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
	unsigned int lib_approved = 0;

	if (lc_lib_alg_status() & lc_alg_status_fips_approved)
		lib_approved = 1;

	ret += test_validate_status(ret, lc_lib_alg_status(),
				    lib_approved);

	/*
	 * In the Linux kernel there may be other callers that already
	 * triggered self-tests before.
	 */
#ifndef LINUX_KERNEL

#ifdef LC_FIPS140_DEBUG
	ret += test_validate_status(ret, lc_hash_alg_status(lc_sha3_256), 1);
#else
	/* SHA3 is passed due to FIPS integrity test */
	if (lc_lib_alg_status() & lc_alg_status_fips_approved) {
		ret += test_validate_status(ret,
					    lc_hash_alg_status(lc_sha3_256), 1);
	} else {
		ret += test_validate_expected_status(
			ret, lc_hash_alg_status(lc_sha3_256),
			lc_alg_status_unknown, 1);
	}
#endif

	/*
	 * Note, even though this call checks for "pending", when
	 * LC_FIPS140_DEBUG is enabled, the service function checks for the
	 * presence of the failure state.
	 */
	ret += test_validate_expected_status(ret, lc_hmac_alg_status(lc_sha256),
					     lc_alg_status_unknown, 1);

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
		ret += 1;

	ret += test_validate_status(ret, lc_lib_alg_status(),
				    lib_approved);
	ret += test_validate_status(ret, lc_hash_alg_status(lc_sha3_256), 1);
	ret += test_validate_status(ret, lc_hmac_alg_status(lc_sha256), 1);
	ret += test_print_status();

	printf("Rerun self tests\n");
	lc_rerun_selftests();

	ret += test_validate_status(ret, lc_lib_alg_status(),
				    lib_approved);

#ifdef LC_FIPS140_DEBUG
	ret += test_validate_status(ret, lc_hash_alg_status(lc_sha3_256), 1);
#else
	/* SHA3 is passed due to FIPS integrity test */
	if (lc_lib_alg_status() & lc_alg_status_fips_approved) {
		ret += test_validate_status(ret,
					    lc_hash_alg_status(lc_sha3_256), 1);
	} else {
		ret += test_validate_expected_status(
			ret, lc_hash_alg_status(lc_sha3_256),
			lc_alg_status_unknown, 1);
	}
#endif

	ret += test_validate_expected_status(ret, lc_hmac_alg_status(lc_sha256),
					     lc_alg_status_unknown, 1);
	ret += test_print_status();

	printf("Attempt to calculate HMAC\n");
	if (lc_hmac(lc_sha3_512, buf, sizeof(buf), NULL, 0, buf) !=
#ifdef LC_FIPS140_DEBUG
	    -EOPNOTSUPP
#else
	    0
#endif
	)
		ret += 1;

	ret += test_validate_status(ret, lc_lib_alg_status(),
				    lib_approved);
	ret += test_validate_status(ret, lc_hash_alg_status(lc_sha3_256), 1);
	ret += test_validate_status(ret, lc_hmac_alg_status(lc_sha256), 1);
	ret += test_print_status();

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return rerun_selftest_tester();
}
