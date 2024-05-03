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

#include "kyber_type.h"
#include "kyber_debug.h"
#include "kyber_indcpa_armv8.h"
#include "kyber_kem.h"
#include "kyber_kem_armv8.h"
#include "kyber_selftest.h"
#include "kyber_verify.h"
#include "lc_hash.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_kyber_keypair_armv8, struct lc_kyber_pk *pk,
		      struct lc_kyber_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	static int tester = LC_KYBER_TEST_INIT;

	kyber_kem_keygen_selftest(&tester, "Kyber KEM keypair ARMv8",
				  lc_kyber_keypair_armv8);
	return _lc_kyber_keypair(pk, sk, rng_ctx, indcpa_keypair_armv8);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_enc_armv8, struct lc_kyber_ct *ct,
		      struct lc_kyber_ss *ss, const struct lc_kyber_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
	static int tester = LC_KYBER_TEST_INIT;

	kyber_kem_enc_selftest(&tester, "Kyber KEM enc ARMv8",
			       lc_kyber_enc_armv8);
	return _lc_kyber_enc(ct, ss, pk, rng_ctx, indcpa_enc_armv8);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_enc_kdf_armv8, struct lc_kyber_ct *ct,
		      uint8_t *ss, size_t ss_len, const struct lc_kyber_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
	static int tester = LC_KYBER_TEST_INIT;

	kyber_kem_enc_kdf_selftest(&tester, "Kyber KEM enc KDF ARMv8",
				   lc_kyber_enc_kdf_armv8);
	return _lc_kyber_enc_kdf(ct, ss, ss_len, pk, rng_ctx, indcpa_enc_armv8);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_dec_armv8, struct lc_kyber_ss *ss,
		      const struct lc_kyber_ct *ct,
		      const struct lc_kyber_sk *sk)
{
	static int tester = LC_KYBER_TEST_INIT;

	kyber_kem_dec_selftest(&tester, "Kyber KEM dec ARMv8",
			       lc_kyber_dec_armv8);
	return _lc_kyber_dec(ss, ct, sk, indcpa_dec_armv8, indcpa_enc_armv8);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_dec_kdf_armv8, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_ct *ct,
		      const struct lc_kyber_sk *sk)
{
	static int tester = LC_KYBER_TEST_INIT;

	kyber_kem_dec_kdf_selftest(&tester, "Kyber KEM dec KDF ARMv8",
				   lc_kyber_dec_kdf_armv8);
	return _lc_kyber_dec_kdf(ss, ss_len, ct, sk, indcpa_dec_armv8,
				 indcpa_enc_armv8);
}
