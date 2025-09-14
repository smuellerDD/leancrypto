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

#include "kyber_type.h"

#include "compare.h"
#include "kyber_selftest.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "timecop.h"
#include "selftest_rng.h"

#if LC_KYBER_K == 2
#include "kyber_selftest_vector_512.h"
#elif LC_KYBER_K == 3
#include "kyber_selftest_vector_768.h"
#elif LC_KYBER_K == 4
#include "kyber_selftest_vector_1024.h"
#endif

static int _kyber_kem_keygen_selftest(
	int (*_lc_kyber_keypair)(struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
				 struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_kyber_pk pk;
		struct lc_kyber_sk sk;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	_lc_kyber_keypair(&ws->pk, &ws->sk, selftest_rng);

	/*
	 * IG 10.3.A: it is not required to validate ek as it is part of dk.
	 */
#if 0
	if (lc_compare_selftest(LC_ALG_STATUS_MLKEM_KEYGEN, ws->pk.pk,
				kyber_testvectors[0].pk.pk,
				LC_CRYPTO_PUBLICKEYBYTES, "ML-KEM keygen PK");
		goto out;
#endif

out:
	/* Timecop: Selftest does not contain secrets */
	unpoison(&ws->sk.sk, LC_CRYPTO_SECRETKEYBYTES);
	lc_compare_selftest(LC_ALG_STATUS_MLKEM_KEYGEN, ws->sk.sk,
			    kyber_testvectors[0].sk.sk,
			    LC_CRYPTO_SECRETKEYBYTES, "ML-KEM keygen SK");

	LC_RELEASE_MEM(ws);
	lc_rng_zero(selftest_rng);

	return ret;
}

void kyber_kem_keygen_selftest(
	int (*_lc_kyber_keypair)(struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
				 struct lc_rng_ctx *rng_ctx))
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_MLKEM_KEYGEN);
	_kyber_kem_keygen_selftest(_lc_kyber_keypair);
}

static int _kyber_kem_enc_selftest(int (*_lc_kyber_enc)(
	struct lc_kyber_ct *ct, struct lc_kyber_ss *ss,
	const struct lc_kyber_pk *pk, struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_kyber_ct ct;
		struct lc_kyber_ss key_b;
	};
	uint8_t discard[2 * LC_KYBER_SYMBYTES];
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	/* The test vector RNG state served a keygen before enc */
	lc_rng_generate(selftest_rng, NULL, 0, discard, sizeof(discard));

	// Encapsulation
	_lc_kyber_enc(&ws->ct, &ws->key_b, &kyber_testvectors[0].pk,
		      selftest_rng);

	/* Timecop: Selftest does not contain secrets */
	unpoison(&ws->ct.ct, LC_CRYPTO_CIPHERTEXTBYTES);
	if (lc_compare_selftest(LC_ALG_STATUS_MLKEM_ENC, ws->ct.ct,
				kyber_testvectors[0].ct.ct,
				LC_CRYPTO_CIPHERTEXTBYTES, "ML-KEM enc CT"))
		goto out2;

out:
	/* Timecop: Selftest does not contain secrets */
	unpoison(&ws->key_b.ss, LC_KYBER_SSBYTES);
	lc_compare_selftest(LC_ALG_STATUS_MLKEM_ENC, ws->key_b.ss,
			    kyber_testvectors[0].ss.ss, LC_KYBER_SSBYTES,
			    "ML-KEM enc SS");

out2:
	LC_RELEASE_MEM(ws);
	lc_rng_zero(selftest_rng);
	return ret;
}

void kyber_kem_enc_selftest(int (*_lc_kyber_enc)(struct lc_kyber_ct *ct,
						 struct lc_kyber_ss *ss,
						 const struct lc_kyber_pk *pk,
						 struct lc_rng_ctx *rng_ctx))
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_MLKEM_ENC);
	_kyber_kem_enc_selftest(_lc_kyber_enc);
}

void kyber_kem_dec_selftest(int (*_lc_kyber_dec)(struct lc_kyber_ss *ss,
						 const struct lc_kyber_ct *ct,
						 const struct lc_kyber_sk *sk))

{
	struct lc_kyber_ss key_a;

	LC_SELFTEST_RUN(LC_ALG_STATUS_MLKEM_DEC);

	// Decapsulation
	_lc_kyber_dec(&key_a, &kyber_testvectors[0].ct,
		      &kyber_testvectors[0].sk);

	/* Timecop: Selftest does not contain secrets */
	unpoison(key_a.ss, LC_KYBER_SSBYTES);
	if (lc_compare_selftest(LC_ALG_STATUS_MLKEM_DEC, key_a.ss,
				kyber_testvectors[0].ss.ss, LC_KYBER_SSBYTES,
				"ML-KEM dec SS"))
		return;

	/* Implicit rejection testing */
	_lc_kyber_dec(&key_a, &kyber_testvectors[1].ct,
		      &kyber_testvectors[0].sk);

	/* Timecop: Selftest does not contain secrets */
	unpoison(key_a.ss, LC_KYBER_SSBYTES);
	lc_compare_selftest(LC_ALG_STATUS_MLKEM_DEC, key_a.ss,
			    kyber_testvectors[1].ss.ss, LC_KYBER_SSBYTES,
			    "ML-KEM dec SS rejection");
}
