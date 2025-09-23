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

#ifndef TEST_HELPER_H
#define TEST_HELPER_H

#include "ret_checkers.h"
#include "lc_status.h"
#include "small_stack_support.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline int
test_validate_expected_status(int ret, uint64_t algorithm,
			      enum lc_alg_status_result expected,
			      unsigned int is_fips)
{
	if (!!(lc_alg_status(algorithm) & lc_alg_status_fips_approved) !=
	    is_fips) {
		printf("FIPS approved marker %u does not match expected marker %u for algorithm %llu\n",
		       lc_alg_status(algorithm), is_fips,
		       (unsigned long long)algorithm);
#ifdef LC_FIPS140_DEBUG
		ret -= 1;
#else
		ret += 1;
#endif
	} else {
		printf("FIPS approved marker matches expected marker\n");
	}

#ifdef LC_FIPS140_DEBUG
	/* Set any recorded result to zero */
	if (ret > 0)
		ret = 0;
	expected = lc_alg_status_result_failed;
#endif

	if (lc_status_get_result(algorithm) != expected) {
#ifdef LC_FIPS140_DEBUG
		ret -= 1;
		printf("FIPS negative test: ");
#else
		ret += 1;
#endif
		printf("Self test status for algorithm %llu unexpected: %u\n",
		       (unsigned long long)algorithm,
		       lc_status_get_result(algorithm));
	}
#ifdef LC_FIPS140_DEBUG
	else {
		printf("FIPS negative test: Self test status for algorithm %llu failed as expected\n",
		       (unsigned long long)algorithm);
	}
#endif

	return ret;
}

static inline int test_validate_status(int ret, uint64_t algorithm,
				       unsigned int is_fips)
{
	return test_validate_expected_status(
		ret, algorithm, lc_alg_status_result_passed, is_fips);
}

static inline int test_print_status(void)
{
	struct workspace {
		char status[2000];
	};
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, 8);

	lc_status(ws->status, sizeof(ws->status));
	if (strlen(ws->status) == 0) {
		ret += 1;
		goto out;
	}
	printf("Status information from leancrypto:\n%s", ws->status);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* TEST_HELPER_H */
