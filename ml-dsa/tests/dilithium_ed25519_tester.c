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

#include "dilithium_tester.h"
#include "lc_sha512.h"
#include "lc_status.h"
#include "ret_checkers.h"
#include "selftest_rng.h"
#include "small_stack_support.h"
#include "status_algorithms.h"
#include "test_helper_common.h"
#include "visibility.h"

static int dilithium_ed25519_tester(int failcheck)
{
	struct workspace {
		struct lc_dilithium_ed25519_sk sk;
		struct lc_dilithium_ed25519_pk pk;
		struct lc_dilithium_ed25519_sig sig;
	};
	static const uint8_t msg[] = { 0x00, 0x01, 0x02 };
	static const uint8_t msg2[] = { 0x00, 0x01, 0x03 };
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	ret = lc_dilithium_ed25519_keypair(&ws->pk, &ws->sk, selftest_rng);
	ret |= lc_dilithium_ed25519_sign(&ws->sig, msg, sizeof(msg), &ws->sk,
					 selftest_rng);
	ret |= lc_dilithium_ed25519_verify(&ws->sig, msg, sizeof(msg), &ws->pk);

	if (ret)
		goto out;

	if (!failcheck)
		goto out;

	/* modify msg */
	if (lc_dilithium_ed25519_verify(&ws->sig, msg2, sizeof(msg2),
					&ws->pk) != -EBADMSG) {
		ret = 1;
		goto out;
	}

	/* modify Dilithium key */
	ws->pk.pk.pk[0] = (uint8_t)((ws->pk.pk.pk[0] + 0x01) & 0xff);
	if (lc_dilithium_ed25519_verify(&ws->sig, msg, sizeof(msg), &ws->pk) !=
	    -EBADMSG) {
		ret = 1;
		goto out;
	}
	ws->pk.pk.pk[0] = (uint8_t)((ws->pk.pk.pk[0] - 0x01) & 0xff);

	/* modify ED25519 key */
	ws->pk.pk_ed25519.pk[0] =
		(uint8_t)((ws->pk.pk_ed25519.pk[0] + 0x01) & 0xff);
	ret = lc_dilithium_ed25519_verify(&ws->sig, msg, sizeof(msg), &ws->pk);
	if (ret != -EBADMSG && ret != -EINVAL) {
		ret = 1;
		goto out;
	}
	ws->pk.pk_ed25519.pk[0] =
		(uint8_t)((ws->pk.pk_ed25519.pk[0] - 0x01) & 0xff);

	ret = 0;

out:
	if (ret < 0)
		ret = 1;
	LC_RELEASE_MEM(ws);
	return !!ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	size_t count;
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
		ret = dilithium_ed25519_tester(1);
	} else {
		for (count = 0; count < 10000; count++)
			ret += dilithium_ed25519_tester(0);
	}

	ret = test_validate_status(
		ret,
		lc_dilithium_alg_status(LC_DILITHIUM_44,
					lc_alg_operation_dilithium_keygen),
		1);
#ifndef LC_FIPS140_DEBUG
	ret = test_validate_status(
		ret,
		lc_dilithium_alg_status(LC_DILITHIUM_65,
					lc_alg_operation_dilithium_siggen),
		1);
	ret = test_validate_status(
		ret,
		lc_dilithium_alg_status(LC_DILITHIUM_87,
					lc_alg_operation_dilithium_sigver),
		1);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_shake256), 1);
	ret = test_validate_status(
		ret, lc_ed25519_alg_status(lc_alg_operation_ed25519_keygen), 1);
	ret = test_validate_status(
		ret, lc_ed25519_alg_status(lc_alg_operation_ed25519_siggen), 1);
	ret = test_validate_status(
		ret, lc_ed25519_alg_status(lc_alg_operation_ed25519_sigver), 1);
	ret = test_validate_status(ret, lc_hash_alg_status(lc_sha512), 1);
#endif
	ret += test_print_status();

	return ret;
}
