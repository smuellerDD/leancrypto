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

#ifndef LC_STATUS_H
#define LC_STATUS_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup Status Status Information About Leancrypto
 *
 * Concept of status in leancrypto
 *
 * The library maintains a status for each algorithm indicating the information
 * given in \p lc_alg_status_val. For each algorithm type, a query function
 * is provided that returns the respective inforamtion.
 *
 * The status information can be obtained with the different
 * `lc_<type>_ctx_alg_status` and `lc_<type>_alg_status` functions.
 */

/**
 * @ingroup Status
 * @brief (Re-)run the self tests
 *
 * If the self tests were already executed for a given algorithm, they are
 * triggered again.
 *
 * This API is only allowed to be used in non-FIPS mode. This is due to the
 * requirements of FIPS that when triggering a rerun, e.g. after a failure,
 * *all* self tests have to be executed immediately instead of lazily. This
 * is not implemented.
 */
void lc_rerun_selftests(void);

/**
 * @ingroup Status
 * @brief (re-)run a self test for one algorithm
 *
 * @param [in] flag Algorithm reference of one of the LC_ALG_STATUS_* flagsc
 */
void lc_rerun_one_selftest(uint64_t flag);

enum lc_alg_status_val {
	/** Unknown status  */
	lc_alg_status_unknown = 0,
	/** Algorithm is FIPS approved */
	lc_alg_status_fips_approved = (1 << 1),
	/** Algorithm self-test passed */
	lc_alg_status_self_test_passed = (1 << 2),
	/** Algorithm self-test failed */
	lc_alg_status_self_test_failed = (1 << 3),
};

/**
 * @ingroup Status
 * @brief Return status information about library itself
 *
 * @return status
 */
enum lc_alg_status_val lc_lib_alg_status(void);

/**
 * @ingroup Status
 * @brief Re-run the FIPS 140 integrity test
 *
 * \note This API is only present in the FIPS module instance of leancrypto.
 *
 * \warning In FIPS mode, this call gates all algorithms. I.e. they return an
 *	    error code during initialization.
 */
void lc_fips_integrity_checker(void);

/**
 * @ingroup Status
 * @brief Status information about leancrypto
 *
 * @param [in] outbuf Buffer to be filled with status information, allocated by
 *		      caller
 * @param [in] outlen Size of the output buffer
 *
 * @return 0 on success; < 0 on error
 */
int lc_status(char *outbuf, size_t outlen);

/*
 * Test status flag
 */
enum lc_alg_status_result {
	/** Testing is pending for given algorithm */
	lc_alg_status_result_pending = 0x0,
	/** Testing ongoing for given algorithm */
	lc_alg_status_result_ongoing = 0x1,
	/** Testing passed for given algorithm */
	lc_alg_status_result_passed = 0x3,
	/** Testing failed for given algorithm */
	lc_alg_status_result_failed = 0x7,
};

/**
 * @ingroup Status
 * @brief Return the self test status for the algorithm
 *
 * @param [in] algorithm Specify the algorithm(s) for which the self test status
 *	       shall be returned.
 */
enum lc_alg_status_result lc_status_get_result(uint64_t algorithm);

/**
 * @ingroup Status
 * @brief Disable all algorithm startup self tests
 *
 * At runtime, before the first use of any algorithm, an algorithm-spedific
 * self test is performed to verify that the cryptographic algorithm operates
 * correctly. With this API call, the caller can prevent the execution of all
 * future algorithm self tests.
 *
 * This call effectively marks all self tests as passed. If a self test failed
 * before this API call for a given algorithm, the algorithm will remain in
 * failure mode.
 *
 * \note The caller should understand the implications of the call and only
 * perform this call if it is truly intended.
 *
 * \note Disabling of self tests in FIPS mode is not allowed and returns an
 * error.
 *
 * @return 0 on success, < 0 on error
 */
int lc_alg_disable_selftests(void);

#ifdef __cplusplus
}
#endif

#endif /* LC_STATUS_H */
