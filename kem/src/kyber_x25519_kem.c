/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
#include "ret_checkers.h"
#include "visibility.h"
#include "x25519/x25519.h"

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_keypair,
		      struct lc_kyber_x25519_pk *pk,
		      struct lc_kyber_x25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKINT(lc_kyber_keypair(&pk->pk, &sk->sk, rng_ctx));
	CKINT(lc_x25519_keypair(&pk->pk_x25519, &sk->sk_x25519, rng_ctx));

out:
	return ret;
}

/**
 * @brief kyber_double_ss_kdf - KDF to derive arbitrary sized SS from Kyber SS
 *
 *	SS <- KMAC256(K = Kyber-SS || X25519-SS, X = Kyber-CT,
 *		      L = requested SS length, S = "Kyber KEM Double SS")
 *
 * This KDF is is consistent with SP800-108 rev 1.
 */
static inline void kyber_x25519_ss_kdf(uint8_t *ss, size_t ss_len,
				       const struct lc_kyber_x25519_ct *ct,
				       const struct lc_kyber_x25519_ss *calc_ss)
{
	static const uint8_t kyber_ss_label[] = "Kyber KEM Double SS";

	lc_kmac(lc_cshake256, (uint8_t *)calc_ss, sizeof(struct lc_kyber_ss),
		kyber_ss_label, sizeof(kyber_ss_label) - 1, (uint8_t *)ct,
		sizeof(struct lc_kyber_x25519_ct), ss, ss_len);
}

int lc_kyber_x25519_enc_kdf_internal(struct lc_kyber_x25519_ct *ct, uint8_t *ss,
				     size_t ss_len,
				     const struct lc_kyber_x25519_pk *pk,
				     struct lc_rng_ctx *rng_ctx)
{
	struct lc_kyber_x25519_ss ss_k_x;
	struct lc_x25519_sk sk_x25519;
	int ret;

	CKINT(lc_kyber_enc_internal(&ct->ct, &ss_k_x.ss, &pk->pk, rng_ctx));

	CKINT(lc_x25519_keypair(&ct->pk_x25519, &sk_x25519, rng_ctx));
	CKINT(lc_x25519_ss(&ss_k_x.ss_x25519, &pk->pk_x25519, &sk_x25519));

	kyber_x25519_ss_kdf(ss, ss_len, ct, &ss_k_x);

out:
	lc_memset_secure(&ss_k_x, 0, sizeof(ss_k_x));
	lc_memset_secure(&sk_x25519, 0, sizeof(sk_x25519));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_enc_kdf, struct lc_kyber_x25519_ct *ct, uint8_t *ss,
			    size_t ss_len, const struct lc_kyber_x25519_pk *pk)
{
	return lc_kyber_x25519_enc_kdf_internal(ct, ss, ss_len, pk,
						lc_seeded_rng);
}

LC_INTERFACE_FUNCTION(
int, lc_kyber_x25519_dec_kdf, uint8_t *ss, size_t ss_len,
			    const struct lc_kyber_x25519_ct *ct,
			    const struct lc_kyber_x25519_sk *sk)
{
	struct lc_kyber_x25519_ss ss_k_x;
	int ret;

	CKINT(lc_kyber_dec(&ss_k_x.ss, &ct->ct, &sk->sk));
	CKINT(lc_x25519_ss(&ss_k_x.ss_x25519, &ct->pk_x25519, &sk->sk_x25519));

	kyber_x25519_ss_kdf(ss, ss_len, ct, &ss_k_x);

out:
	lc_memset_secure(&ss_k_x, 0, sizeof(ss_k_x));
	return ret;
}
