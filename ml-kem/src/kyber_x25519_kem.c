/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "kyber_x25519_internal.h"
#include "kyber_x25519_kdf.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "lc_x25519.h"

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_keypair,
		      struct lc_kyber_x25519_pk *pk,
		      struct lc_kyber_x25519_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKINT(lc_kyber_keypair(&pk->pk, &sk->sk, rng_ctx));
	CKINT(lc_x25519_keypair(&pk->pk_x25519, &sk->sk_x25519, rng_ctx));

out:
	return ret;
}

int lc_kyber_x25519_enc_internal(struct lc_kyber_x25519_ct *ct,
				 struct lc_kyber_x25519_ss *ss,
				 const struct lc_kyber_x25519_pk *pk,
				 struct lc_rng_ctx *rng_ctx)
{
	struct lc_x25519_sk sk_x25519;
	int ret;

	CKINT(lc_kyber_enc_internal(&ct->ct, &ss->ss, &pk->pk, rng_ctx));

	CKINT(lc_x25519_keypair(&ct->pk_x25519, &sk_x25519, rng_ctx));
	CKINT(lc_x25519_ss(&ss->ss_x25519, &pk->pk_x25519, &sk_x25519));

out:
	lc_memset_secure(&sk_x25519, 0, sizeof(sk_x25519));
	return ret;
}

int lc_kyber_x25519_enc_kdf_internal(struct lc_kyber_x25519_ct *ct, uint8_t *ss,
				     size_t ss_len,
				     const struct lc_kyber_x25519_pk *pk,
				     struct lc_rng_ctx *rng_ctx)
{
	struct lc_kyber_x25519_ss ss_k_x;
	int ret;

	CKINT(lc_kyber_x25519_enc_internal(ct, &ss_k_x, pk, rng_ctx));

	kyber_x25519_ss_kdf(ss, ss_len, ct, &ss_k_x);

out:
	lc_memset_secure(&ss_k_x, 0, sizeof(ss_k_x));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_enc_kdf,
		      struct lc_kyber_x25519_ct *ct, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_x25519_pk *pk)
{
	return lc_kyber_x25519_enc_kdf_internal(ct, ss, ss_len, pk,
						lc_seeded_rng);
}

int lc_kyber_x25519_dec_internal(struct lc_kyber_x25519_ss *ss,
				 const struct lc_kyber_x25519_ct *ct,
				 const struct lc_kyber_x25519_sk *sk)
{
	int ret;

	CKINT(lc_kyber_dec(&ss->ss, &ct->ct, &sk->sk));
	CKINT(lc_x25519_ss(&ss->ss_x25519, &ct->pk_x25519, &sk->sk_x25519));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_x25519_ct *ct,
		      const struct lc_kyber_x25519_sk *sk)
{
	struct lc_kyber_x25519_ss ss_k_x;
	int ret;

	CKINT(lc_kyber_x25519_dec_internal(&ss_k_x, ct, sk));

	kyber_x25519_ss_kdf(ss, ss_len, ct, &ss_k_x);

out:
	lc_memset_secure(&ss_k_x, 0, sizeof(ss_k_x));
	return ret;
}
