/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "compare.h"
#include "ext_headers.h"
#include "kyber_x25519_internal.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "selftest_rng.h"
#include "small_stack_support.h"
#include "visibility.h"

static int kyber_kex_tester(void)
{
	struct workspace {
		struct lc_kyber_x25519_pk pk_r;
		struct lc_kyber_x25519_sk sk_r;

		struct lc_kyber_x25519_pk pk_i;
		struct lc_kyber_x25519_sk sk_i;

		struct lc_kyber_x25519_pk pk_e_i;
		struct lc_kyber_x25519_ct ct_e_r, ct_e_i, ct_e_r_1, ct_e_r_2;
		struct lc_kyber_x25519_sk sk_e;

		struct lc_kyber_x25519_ss tk;

		uint8_t ss_r[LC_KYBER_SSBYTES], ss_i[LC_KYBER_SSBYTES],
			zero[LC_KYBER_SSBYTES];
	};
	unsigned int i;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	for (i = 0; i < LC_KYBER_SSBYTES; i++)
		ws->zero[i] = 0;

	// Generate static key for Bob
	CKINT(lc_kyber_x25519_keypair(&ws->pk_r, &ws->sk_r, selftest_rng));

	// Generate static key for Alice
	CKINT(lc_kyber_x25519_keypair(&ws->pk_i, &ws->sk_i, selftest_rng));

	// Perform unilaterally authenticated key exchange

	// Run by Bob
	CKINT(lc_kex_x25519_uake_initiator_init_internal(
		&ws->pk_e_i, &ws->ct_e_i, &ws->tk, &ws->sk_e, &ws->pk_r,
		selftest_rng));

	// Run by Alice
	CKINT(lc_kex_x25519_uake_responder_ss_internal(
		&ws->ct_e_r, ws->ss_r, sizeof(ws->ss_r), NULL, 0, &ws->pk_e_i,
		&ws->ct_e_i, &ws->sk_r, selftest_rng));

	// Run by Bob
	CKINT(lc_kex_x25519_uake_initiator_ss(ws->ss_i, sizeof(ws->ss_i), NULL,
					      0, &ws->ct_e_r, &ws->tk,
					      &ws->sk_e));

	if (memcmp(ws->ss_i, ws->ss_r, sizeof(ws->ss_r))) {
		printf("Error in UAKE\n");
		ret = 1;
		goto out;
	}

	if (!memcmp(ws->ss_i, ws->zero, sizeof(ws->ss_i))) {
		printf("Error: UAKE produces zero key\n");
		ret = 1;
		goto out;
	}

	// Perform mutually authenticated key exchange

	// Run by Bob
	CKINT(lc_kex_x25519_ake_initiator_init_internal(
		&ws->pk_e_i, &ws->ct_e_i, &ws->tk, &ws->sk_e, &ws->pk_r,
		selftest_rng));

	// Run by Alice
	CKINT(lc_kex_x25519_ake_responder_ss_internal(
		&ws->ct_e_r_1, &ws->ct_e_r_2, ws->ss_r, sizeof(ws->ss_r), NULL,
		0, &ws->pk_e_i, &ws->ct_e_i, &ws->sk_r, &ws->pk_i,
		selftest_rng));

	// Run by Bob
	CKINT(lc_kex_x25519_ake_initiator_ss(ws->ss_i, sizeof(ws->ss_i), NULL,
					     0, &ws->ct_e_r_1, &ws->ct_e_r_2,
					     &ws->tk, &ws->sk_e, &ws->sk_i));

	if (memcmp(ws->ss_i, ws->ss_r, sizeof(ws->ss_r))) {
		printf("Error in AKE\n");
		ret = 1;
		goto out;
	}

	if (!memcmp(ws->ss_i, ws->zero, sizeof(ws->ss_i))) {
		printf("Error: AKE produces zero key\n");
		ret = 1;
		goto out;
	}

	ret = 0;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return kyber_kex_tester();
}
