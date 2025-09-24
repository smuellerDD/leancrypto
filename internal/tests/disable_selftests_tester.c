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
#include "lc_status.h"
#include "test_helper_common.h"
#include "visibility.h"

/*
 * Test to disable the self test.
 */
static int disable_selftest_tester(void)
{
	int ret = 0;

	ret += test_validate_status(ret, LC_ALG_STATUS_LIB, 0);
	ret += test_validate_expected_status(ret, LC_ALG_STATUS_SHA3,
					     lc_alg_status_result_pending, 1);
	ret += test_validate_expected_status(ret, LC_ALG_STATUS_HMAC,
					     lc_alg_status_result_pending, 1);

	ret += test_print_status();

	printf("Disable selftests\n");

	if (lc_alg_disable_selftests())
		ret += 1;

	ret += test_validate_expected_status(ret, LC_ALG_STATUS_HMAC,
					     lc_alg_status_result_passed, 1);
	ret += test_validate_expected_status(ret, LC_ALG_STATUS_SHA3,
					     lc_alg_status_result_passed, 1);

	ret += test_print_status();

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return disable_selftest_tester();
}
