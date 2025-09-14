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
#include "dilithium_tester.h"
#include "lc_status.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "status_algorithms.h"
#include "test_helper_common.h"
#include "visibility.h"

static int _dilithium_tester_common(unsigned int rounds, unsigned int internal,
				    unsigned int prehashed,
				    unsigned int external_mu)
{
	return _dilithium_tester(rounds, 1, internal, prehashed, external_mu,
				 lc_dilithium_keypair,
				 lc_dilithium_keypair_from_seed,
				 lc_dilithium_sign_ctx,
				 lc_dilithium_verify_ctx);
}

static int dilithium_tester_common(void)
{
	int ret = 0;

	ret += _dilithium_tester_common(0, 0, 0, 0);
	ret += _dilithium_tester_common(0, 1, 0, 0);
	ret += _dilithium_tester_common(0, 0, 1, 0);
	ret += _dilithium_tester_common(0, 0, 0, 1);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	int ret = 0;

	(void)argv;

#ifdef LC_FIPS140_DEBUG
	/*
	 * Both algos are used for the random number generation as part of
	 * the key generation. Thus we need to enable them for executing the
	 * test.
	 */
	alg_status_set_result(lc_alg_status_result_passed, LC_ALG_STATUS_SHAKE);
#endif

	if (argc != 2) {
		ret = dilithium_tester_common();
	} else {
		ret = _dilithium_tester_common(10000, 0, 0, 0);
	}

	ret = test_validate_status(ret, LC_ALG_STATUS_MLDSA_KEYGEN);
	ret = test_validate_status(ret, LC_ALG_STATUS_MLDSA_SIGGEN);
	ret = test_validate_status(ret, LC_ALG_STATUS_MLDSA_SIGVER);
#ifndef LC_FIPS140_DEBUG
	ret = test_validate_status(ret, LC_ALG_STATUS_SHAKE);
#endif
	ret += test_print_status();

	return ret;
}
