/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef ED25519_PCT_H
#define ED25519_PCT_H

#include "fips_mode.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_ed25519_sign_internal(
	struct lc_ed25519_sig *sig, int prehash, const uint8_t *msg,
	size_t mlen, const struct lc_ed25519_sk *sk, struct lc_rng_ctx *rng_ctx,
	struct lc_dilithium_ed25519_ctx *composite_ml_dsa_ctx);
int lc_ed25519_verify_internal(
	const struct lc_ed25519_sig *sig, int prehash, const uint8_t *msg,
	size_t mlen, const struct lc_ed25519_pk *pk,
	struct lc_dilithium_ed25519_ctx *composite_ml_dsa_ctx);

static inline int _lc_ed25519_pct_fips(const struct lc_ed25519_pk *pk,
				       const struct lc_ed25519_sk *sk)
{
	struct workspace {
		uint8_t m[32];
		struct lc_ed25519_sig sig;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_ed25519_sign_internal(&ws->sig, 0, ws->m, sizeof(ws->m), sk,
				       lc_seeded_rng, NULL));
	if (pk) {
		CKINT(lc_ed25519_verify_internal(&ws->sig, 0, ws->m,
						 sizeof(ws->m), pk, NULL));
	} else {
		struct lc_ed25519_pk *pk_sk;

		/* The PK is the trailing part of the SK */
		pk_sk = (struct lc_ed25519_pk *)(sk->sk + 32);
		CKINT(lc_ed25519_verify_internal(&ws->sig, 0, ws->m,
						 sizeof(ws->m), pk_sk, NULL));
	}

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static inline int lc_ed25519_pct_fips(const struct lc_ed25519_pk *pk,
				      const struct lc_ed25519_sk *sk)
{
	FIPS140_PCT_LOOP(_lc_ed25519_pct_fips(pk, sk),
			 LC_ALG_STATUS_ED25519_KEYGEN)

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* ED25519_PCT_H */
