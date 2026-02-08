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
#include "lc_status.h"
#include "status_algorithms.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(void, lc_rerun_one_selftest, uint64_t flag)
{
	/*
	 * This API is capable of getting a failed self test back to operational
	 * mode by unseting the status flag and thus trigger a re-execution
	 * of the known-answer self test before next use.
	 *
	 * FIPS 140-3 "Degraded operation" states in order to leave the
	 * degraded mode, only the preoperational self test needs to be
	 * performed. Thus, we do that here. Note, due to the way the integrity
	 * checker is designed, in FIPS mode, this causes all self tests to be
	 * rerun after the completion of the integrity test. I.e. the library
	 * acts like after a power-on.
	 */
	if (fips140_mode_enabled())
		lc_fips_integrity_checker();
	else
		alg_status_unset_result(flag);
}

LC_INTERFACE_FUNCTION(enum lc_alg_status_result, lc_status_get_result,
		      uint64_t algorithm)
{
	return alg_status_get_result(algorithm);
}

LC_INTERFACE_FUNCTION(void, lc_rerun_selftests, void)
{
	/* See rationale on the FIPS mode above */
	if (fips140_mode_enabled())
		lc_fips_integrity_checker();
	else
		alg_status_unset_result_all();
}

enum lc_alg_status_val lc_alg_status(uint64_t algorithm)
{
	return alg_status(algorithm);
}

LC_INTERFACE_FUNCTION(enum lc_alg_status_val, lc_lib_alg_status, void)
{
	return alg_status(LC_ALG_STATUS_LIB);
}

LC_INTERFACE_FUNCTION(int, lc_alg_disable_selftests, void)
{
	if (fips140_mode_enabled())
		return -EOPNOTSUPP;

	alg_status_set_all_passed_state();
	return 0;
}
