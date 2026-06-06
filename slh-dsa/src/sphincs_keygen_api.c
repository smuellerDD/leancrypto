/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include "lc_sphincs.h"
#include "sphincs_pct.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_sphincs_keypair, struct lc_sphincs_pk *pk,
		      struct lc_sphincs_sk *sk, struct lc_rng_ctx *rng_ctx,
		      enum lc_sphincs_type sphincs_type)
{
	if (!pk || !sk || !rng_ctx)
		return -EINVAL;

	switch (sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_256s_keypair(&pk->key.pk_shake_256s,
						     &sk->key.sk_shake_256s,
						     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_256f_keypair(&pk->key.pk_shake_256f,
						     &sk->key.sk_shake_256f,
						     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_192s_keypair(&pk->key.pk_shake_192s,
						     &sk->key.sk_shake_192s,
						     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_192f_keypair(&pk->key.pk_shake_192f,
						     &sk->key.sk_shake_192f,
						     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_128s_keypair(&pk->key.pk_shake_128s,
						     &sk->key.sk_shake_128s,
						     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_128f_keypair(&pk->key.pk_shake_128f,
						     &sk->key.sk_shake_128f,
						     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_keypair_from_seed,
		      struct lc_sphincs_pk *pk, struct lc_sphincs_sk *sk,
		      const uint8_t *seed, size_t seedlen,
		      enum lc_sphincs_type sphincs_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_256s_keypair_from_seed(
			&pk->key.pk_shake_256s, &sk->key.sk_shake_256s, seed,
			seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_256f_keypair_from_seed(
			&pk->key.pk_shake_256f, &sk->key.sk_shake_256f, seed,
			seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_192s_keypair_from_seed(
			&pk->key.pk_shake_192s, &sk->key.sk_shake_192s, seed,
			seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_192f_keypair_from_seed(
			&pk->key.pk_shake_192f, &sk->key.sk_shake_192f, seed,
			seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_128s_keypair_from_seed(
			&pk->key.pk_shake_128s, &sk->key.sk_shake_128s, seed,
			seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		pk->sphincs_type = sphincs_type;
		sk->sphincs_type = sphincs_type;
		return lc_sphincs_shake_128f_keypair_from_seed(
			&pk->key.pk_shake_128f, &sk->key.sk_shake_128f, seed,
			seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_pk_from_sk, struct lc_sphincs_pk *pk,
		      const struct lc_sphincs_sk *sk)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (sk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		pk->sphincs_type = sk->sphincs_type;
		return lc_sphincs_shake_256s_pk_from_sk(&pk->key.pk_shake_256s,
							&sk->key.sk_shake_256s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		pk->sphincs_type = sk->sphincs_type;
		return lc_sphincs_shake_256f_pk_from_sk(&pk->key.pk_shake_256f,
							&sk->key.sk_shake_256f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		pk->sphincs_type = sk->sphincs_type;
		return lc_sphincs_shake_192s_pk_from_sk(&pk->key.pk_shake_192s,
							&sk->key.sk_shake_192s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		pk->sphincs_type = sk->sphincs_type;
		return lc_sphincs_shake_192f_pk_from_sk(&pk->key.pk_shake_192f,
							&sk->key.sk_shake_192f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		pk->sphincs_type = sk->sphincs_type;
		return lc_sphincs_shake_128s_pk_from_sk(&pk->key.pk_shake_128s,
							&sk->key.sk_shake_128s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		pk->sphincs_type = sk->sphincs_type;
		return lc_sphincs_shake_128f_pk_from_sk(&pk->key.pk_shake_128f,
							&sk->key.sk_shake_128f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_pct, const struct lc_sphincs_pk *pk,
		      const struct lc_sphincs_sk *sk)
{
	return _lc_sphincs_pct_fips(pk, sk);
}
