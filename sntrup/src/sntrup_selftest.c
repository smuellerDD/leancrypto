/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
#include "lc_sntrup.h"
#include "lc_rng.h"
#include "params.h"
#include "ret_checkers.h"
#include "selftest_rng.h"
#include "small_stack_support.h"
#include "sntrup_kem.h"
#include "sntrup_selftest_kat.h"
#include "timecop.h"

static int _sntrup_selftest_keygen(void)
{
	struct workspace {
		struct CRYPTO_NAMESPACE(pk) pk;
		struct CRYPTO_NAMESPACE(sk) sk;
	};
	int ret;
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(CRYPTO_NAMESPACE(kem_keypair_internal)(&ws->pk, &ws->sk, selftest_rng));

	/*
	 * IG 10.3.A: it is not required to validate ek as it is part of dk.
	 */
#if 1
	if (lc_compare_selftest(LC_ALG_STATUS_SNTRUP_KEYGEN, ws->pk.pk,
				sntrup_testvectors[0].pk.pk,
				sntrup_kem_PUBLICKEYBYTES, "SNTRUP keygen PK"))
		goto out;
#endif

	/* Timecop: Selftest does not contain secrets */
	unpoison(&ws->sk.sk, sntrup_kem_SECRETKEYBYTES);
	lc_compare_selftest(LC_ALG_STATUS_SNTRUP_KEYGEN, ws->sk.sk,
			    sntrup_testvectors[0].sk.sk,
			    sntrup_kem_SECRETKEYBYTES, "SNTRUP keygen SK");


out:
	LC_RELEASE_MEM(ws);
	lc_rng_zero(selftest_rng);
	return ret;
}

void sntrup_selftest_keygen(void)
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_SNTRUP_KEYGEN);
	_sntrup_selftest_keygen();
}

static int _sntrup_selftest_enc(void)
{
	struct workspace {
		struct CRYPTO_NAMESPACE(ct) ct;
		struct CRYPTO_NAMESPACE(ss) ss;
	};
	int ret;
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(CRYPTO_NAMESPACE(kem_enc_internal)(
		&ws->ct, &ws->ss,
		&sntrup_testvectors[0].pk, selftest_rng));

	/* Timecop: Selftest does not contain secrets */
	unpoison(&ws->ct.ct, sntrup_kem_CIPHERTEXTBYTES);
	if (lc_compare_selftest(LC_ALG_STATUS_SNTRUP_ENC, ws->ct.ct,
				sntrup_testvectors[0].ct.ct,
				sntrup_kem_CIPHERTEXTBYTES, "SNTRUP enc CT"))
		goto out2;

	/* Timecop: Selftest does not contain secrets */
	unpoison(&ws->ss.ss, sntrup_kem_BYTES);
	lc_compare_selftest(LC_ALG_STATUS_SNTRUP_ENC, ws->ss.ss,
			    sntrup_testvectors[0].ss.ss, sntrup_kem_BYTES,
			    "SNTRUP enc SS");

out2:
	LC_RELEASE_MEM(ws);
	lc_rng_zero(selftest_rng);
	return ret;

out:
	LC_RELEASE_MEM(ws);
	lc_rng_zero(selftest_rng);
	return ret;
}

void sntrup_selftest_enc(void)
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_SNTRUP_ENC);
	_sntrup_selftest_enc();
}

static int _sntrup_selftest_dec(void)
{
	struct workspace {
		struct CRYPTO_NAMESPACE(ss) ss;
	};
	int ret;
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(CRYPTO_NAMESPACE(kem_dec_internal)(&ws->ss, &sntrup_testvectors[0].ct,
				    &sntrup_testvectors[0].sk));

	/* Timecop: Selftest does not contain secrets */
	unpoison(ws->ss.ss, sntrup_kem_BYTES);
	if (lc_compare_selftest(LC_ALG_STATUS_SNTRUP_DEC, ws->ss.ss,
				sntrup_testvectors[0].ss.ss, sntrup_kem_BYTES,
				"SNTRUP dec SS"))

out:
	LC_RELEASE_MEM(ws);
	lc_rng_zero(selftest_rng);
	return ret;
}

void sntrup_selftest_dec(void)
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_SNTRUP_DEC);
	_sntrup_selftest_dec();
}
