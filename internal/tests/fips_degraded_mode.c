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
#include "status_algorithms.h"
#include "visibility.h"

static int fips_degraded_mode(void)
{
	uint8_t buf[LC_SHA_MAX_SIZE_DIGEST];

	/*
	 * In the Linux kernel there may be other callers that already
	 * triggered self-tests before.
	 */
#ifndef LINUX_KERNEL
	if (lc_status_get_result(LC_ALG_STATUS_SHA3) !=
	    lc_alg_status_result_pending) {
		printf("SHA3-512 self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_SHA3));
		return 1;
	}

	if (lc_status_get_result(LC_ALG_STATUS_HMAC) !=
	    lc_alg_status_result_pending) {
		printf("HMAC self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_HMAC));
		return 1;
	}
#endif

	if (lc_hmac(lc_sha3_512, buf, sizeof(buf), NULL, 0, buf))
		return 1;

	/* Check that all self tests are executed */
	if (lc_status_get_result(LC_ALG_STATUS_SHA3) !=
	    lc_alg_status_result_passed) {
		printf("SHA3-512 self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_SHA3));
		return 1;
	}

	if (lc_status_get_result(LC_ALG_STATUS_HMAC) !=
	    lc_alg_status_result_passed) {
		printf("HMAC self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_HMAC));
		return 1;
	}

	/* Trigger a self test error on SHA-3 */
	alg_status_set_result(lc_alg_status_result_failed, LC_ALG_STATUS_SHA3);

	/* SHA-3 must be in failed state */
	if (lc_status_get_result(LC_ALG_STATUS_SHA3) !=
	    lc_alg_status_result_failed) {
		printf("SHA3-512 self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_SHA3));
		return 1;
	}

	/* HMAC self test status must be pending */
	if (lc_status_get_result(LC_ALG_STATUS_HMAC) !=
	    lc_alg_status_result_passed) {
		printf("HMAC self test status %u unexpected\n",
		       lc_status_get_result(LC_ALG_STATUS_HMAC));
		return 1;
	}

	return 0;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return fips_degraded_mode();
}
