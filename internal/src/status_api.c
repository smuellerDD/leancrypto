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
	 * The caller may trigger a complete new round of self tests. However,
	 * this API is currently disabled in FIPS mode, because the FIPS 140-3
	 * standard mandates that to leave the degraded mode, all self tests
	 * must instantaneously be executed. This is not implemented in
	 * `leancrypto-fips.so` (and I have no desire to honor such nonsensical
	 * requirement). With ISO 19790:2025 this requirement is changed so that
	 * only the offending algorithm requires a rerun of the self test to
	 * leave the degraded mode, provided that the error is local - which is
	 * clearly the case for a self test error. Thus, once the ISO 19790:2025
	 * is enacted, the API can be enabled in FIPS mode to leave the degraded
	 * mode of operation.
	 */
	if (!fips140_mode_enabled())
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
	if (!fips140_mode_enabled())
		alg_status_unset_result_all();
}
