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
#include "selftest_rng.h"
#include "timecop.h"

#if LC_KYBER_K == 2
#include "kyber_selftest_kdf_vector_512.h"
#elif LC_KYBER_K == 3
#include "kyber_selftest_kdf_vector_768.h"
#elif LC_KYBER_K == 4
#include "kyber_selftest_kdf_vector_1024.h"
#endif

static int _kyber_kem_enc_kdf_selftest(
	int (*_lc_kyber_enc_kdf)(struct lc_kyber_ct *ct, uint8_t *ss,
				 size_t ss_len, const struct lc_kyber_pk *pk,
				 struct lc_rng_ctx *rng_ctx))
{
	struct workspace {
		struct lc_kyber_ct ct;
		struct lc_kyber_ss key_b;
	};
	int ret;
	uint8_t discard[2 * LC_KYBER_SYMBYTES];
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	/* The test vector RNG state served a keygen before enc */
	lc_rng_generate(selftest_rng, NULL, 0, discard, sizeof(discard));

	// Encapsulation
	_lc_kyber_enc_kdf(&ws->ct, ws->key_b.ss, LC_KYBER_SSBYTES,
			  &kyber_testvectors[0].pk, selftest_rng);

	/* Timecop: Selftest does not contain secrets */
	unpoison(&ws->ct, LC_CRYPTO_CIPHERTEXTBYTES);
	if (lc_compare_selftest(LC_ALG_STATUS_MLKEM_ENC_KDF, ws->ct.ct,
				kyber_testvectors[0].ct.ct,
				LC_CRYPTO_CIPHERTEXTBYTES, "ML-KEM enc KDF CT"))
		goto out2;

out:
	/* Timecop: Selftest does not contain secrets */
	unpoison(&ws->key_b.ss, LC_KYBER_SSBYTES);
	lc_compare_selftest(LC_ALG_STATUS_MLKEM_ENC_KDF, ws->key_b.ss,
			    kyber_testvectors[0].ss.ss, LC_KYBER_SSBYTES,
			    "ML-KEM enc KDF SS");

out2:
	LC_RELEASE_MEM(ws);
	lc_rng_zero(selftest_rng);
	return 0;
}

void kyber_kem_enc_kdf_selftest(
	int (*_lc_kyber_enc_kdf)(struct lc_kyber_ct *ct, uint8_t *ss,
				 size_t ss_len, const struct lc_kyber_pk *pk,
				 struct lc_rng_ctx *rng_ctx))
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_MLKEM_ENC_KDF);
	_kyber_kem_enc_kdf_selftest(_lc_kyber_enc_kdf);
}

void kyber_kem_dec_kdf_selftest(
	int (*_lc_kyber_dec_kdf)(uint8_t *ss, size_t ss_len,
				 const struct lc_kyber_ct *ct,
				 const struct lc_kyber_sk *sk))
{
	struct lc_kyber_ss key_a;

	LC_SELFTEST_RUN(LC_ALG_STATUS_MLKEM_DEC_KDF);

	// Decapsulation
	_lc_kyber_dec_kdf(key_a.ss, LC_KYBER_SSBYTES, &kyber_testvectors[0].ct,
			  &kyber_testvectors[0].sk);

	/* Timecop: Selftest does not contain secrets */
	unpoison(key_a.ss, LC_KYBER_SSBYTES);
	lc_compare_selftest(LC_ALG_STATUS_MLKEM_DEC_KDF, key_a.ss,
			    kyber_testvectors[0].ss.ss, LC_KYBER_SSBYTES,
			    "ML-KEM dec KDF SS");
}
