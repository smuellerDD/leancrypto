/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "kyber_indcpa.h"
#include "kyber_kem.h"
#include "kyber_kem_c.h"
#include "kyber_selftest.h"
#include "kyber_verify.h"
#include "lc_hash.h"
#include "lc_kyber.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_kyber_keypair_c, struct lc_kyber_pk *pk,
		      struct lc_kyber_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	static int tester = 0;

	kyber_kem_keygen_selftest(&tester, "Kyber KEM keypair C",
				  lc_kyber_keypair_c);
	return _lc_kyber_keypair(pk, sk, rng_ctx, indcpa_keypair);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_enc_c, struct lc_kyber_ct *ct,
		      struct lc_kyber_ss *ss, const struct lc_kyber_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
	static int tester = 0;

	kyber_kem_enc_selftest(&tester, "Kyber KEM enc C", lc_kyber_enc_c);
	return _lc_kyber_enc(ct, ss->ss, pk, rng_ctx, indcpa_enc);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_enc_kdf_c, struct lc_kyber_ct *ct,
		      uint8_t *ss, size_t ss_len, const struct lc_kyber_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
	static int tester = 0;

	kyber_kem_enc_kdf_selftest(&tester, "Kyber KEM enc KDF C",
				   lc_kyber_enc_kdf_c);
	return _lc_kyber_enc_kdf(ct, ss, ss_len, pk, rng_ctx, indcpa_enc);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_dec_c, struct lc_kyber_ss *ss,
		      const struct lc_kyber_ct *ct,
		      const struct lc_kyber_sk *sk)
{
	static int tester = 0;

	kyber_kem_dec_selftest(&tester, "Kyber KEM dec C", lc_kyber_dec_c);
	return _lc_kyber_dec(ss->ss, ct, sk, indcpa_dec, indcpa_enc);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_dec_kdf_c, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_ct *ct,
		      const struct lc_kyber_sk *sk)
{
	static int tester = 0;

	kyber_kem_dec_kdf_selftest(&tester, "Kyber KEM dec KDF C",
				   lc_kyber_dec_kdf_c);
	return _lc_kyber_dec_kdf(ss, ss_len, ct, sk, indcpa_dec, indcpa_enc);
}
