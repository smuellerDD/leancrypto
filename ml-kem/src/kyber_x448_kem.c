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

#include "lc_kmac.h"
#include "kyber_internal.h"
#include "kyber_x448_internal.h"
#include "kyber_x448_kdf.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "lc_x448.h"

LC_INTERFACE_FUNCTION(int, lc_kyber_x448_keypair, struct lc_kyber_x448_pk *pk,
		      struct lc_kyber_x448_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKINT(lc_kyber_keypair(&pk->pk, &sk->sk, rng_ctx));
	CKINT(lc_x448_keypair(&pk->pk_x448, &sk->sk_x448, rng_ctx));

out:
	return ret;
}

int lc_kyber_x448_enc_internal(struct lc_kyber_x448_ct *ct,
			       struct lc_kyber_x448_ss *ss,
			       const struct lc_kyber_x448_pk *pk,
			       struct lc_rng_ctx *rng_ctx)
{
	struct lc_x448_sk sk_x448;
	int ret;

	CKINT(lc_kyber_enc_internal(&ct->ct, &ss->ss, &pk->pk, rng_ctx));

	CKINT(lc_x448_keypair(&ct->pk_x448, &sk_x448, rng_ctx));
	CKINT(lc_x448_ss(&ss->ss_x448, &pk->pk_x448, &sk_x448));

out:
	lc_memset_secure(&sk_x448, 0, sizeof(sk_x448));
	return ret;
}

int lc_kyber_x448_enc_kdf_internal(struct lc_kyber_x448_ct *ct, uint8_t *ss,
				   size_t ss_len,
				   const struct lc_kyber_x448_pk *pk,
				   struct lc_rng_ctx *rng_ctx)
{
	struct lc_kyber_x448_ss ss_k_x;
	int ret;

	CKINT(lc_kyber_x448_enc_internal(ct, &ss_k_x, pk, rng_ctx));

	kyber_x448_ss_kdf(ss, ss_len, ct, &ss_k_x);

out:
	lc_memset_secure(&ss_k_x, 0, sizeof(ss_k_x));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x448_enc_kdf, struct lc_kyber_x448_ct *ct,
		      uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_x448_pk *pk)
{
	return lc_kyber_x448_enc_kdf_internal(ct, ss, ss_len, pk,
					      lc_seeded_rng);
}

int lc_kyber_x448_dec_internal(struct lc_kyber_x448_ss *ss,
			       const struct lc_kyber_x448_ct *ct,
			       const struct lc_kyber_x448_sk *sk)
{
	int ret;

	CKINT(lc_kyber_dec(&ss->ss, &ct->ct, &sk->sk));
	CKINT(lc_x448_ss(&ss->ss_x448, &ct->pk_x448, &sk->sk_x448));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x448_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_x448_ct *ct,
		      const struct lc_kyber_x448_sk *sk)
{
	struct lc_kyber_x448_ss ss_k_x;
	int ret;

	CKINT(lc_kyber_x448_dec_internal(&ss_k_x, ct, sk));

	kyber_x448_ss_kdf(ss, ss_len, ct, &ss_k_x);

out:
	lc_memset_secure(&ss_k_x, 0, sizeof(ss_k_x));
	return ret;
}
