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

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign, struct lc_sphincs_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_256s;
		return lc_sphincs_shake_256s_sign(&sig->sig.sig_shake_256s, m,
						  mlen, &sk->key.sk_shake_256s,
						  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_256f;
		return lc_sphincs_shake_256f_sign(&sig->sig.sig_shake_256f, m,
						  mlen, &sk->key.sk_shake_256f,
						  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_192s;
		return lc_sphincs_shake_192s_sign(&sig->sig.sig_shake_192s, m,
						  mlen, &sk->key.sk_shake_192s,
						  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_192f;
		return lc_sphincs_shake_192f_sign(&sig->sig.sig_shake_192f, m,
						  mlen, &sk->key.sk_shake_192f,
						  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_128s;
		return lc_sphincs_shake_128s_sign(&sig->sig.sig_shake_128s, m,
						  mlen, &sk->key.sk_shake_128s,
						  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_128f;
		return lc_sphincs_shake_128f_sign(&sig->sig.sig_shake_128f, m,
						  mlen, &sk->key.sk_shake_128f,
						  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_ctx, struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx, const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_256s;
		return lc_sphincs_shake_256s_sign_ctx(&sig->sig.sig_shake_256s,
						      ctx, m, mlen,
						      &sk->key.sk_shake_256s,
						      rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_256f;
		return lc_sphincs_shake_256f_sign_ctx(&sig->sig.sig_shake_256f,
						      ctx, m, mlen,
						      &sk->key.sk_shake_256f,
						      rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_192s;
		return lc_sphincs_shake_192s_sign_ctx(&sig->sig.sig_shake_192s,
						      ctx, m, mlen,
						      &sk->key.sk_shake_192s,
						      rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_192f;
		return lc_sphincs_shake_192f_sign_ctx(&sig->sig.sig_shake_192f,
						      ctx, m, mlen,
						      &sk->key.sk_shake_192f,
						      rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_128s;
		return lc_sphincs_shake_128s_sign_ctx(&sig->sig.sig_shake_128s,
						      ctx, m, mlen,
						      &sk->key.sk_shake_128s,
						      rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_128f;
		return lc_sphincs_shake_128f_sign_ctx(&sig->sig.sig_shake_128f,
						      ctx, m, mlen,
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

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_init, struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_sk *sk)
{
	if (!sk)
		return -EINVAL;

	switch (sk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		return lc_sphincs_shake_256s_sign_init(ctx,
						       &sk->key.sk_shake_256s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		return lc_sphincs_shake_256f_sign_init(ctx,
						       &sk->key.sk_shake_256f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		return lc_sphincs_shake_192s_sign_init(ctx,
						       &sk->key.sk_shake_192s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		return lc_sphincs_shake_192f_sign_init(ctx,
						       &sk->key.sk_shake_192f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		return lc_sphincs_shake_128s_sign_init(ctx,
						       &sk->key.sk_shake_128s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		return lc_sphincs_shake_128f_sign_init(ctx,
						       &sk->key.sk_shake_128f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_update, struct lc_sphincs_ctx *ctx,
		      const uint8_t *m, size_t mlen)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	return lc_sphincs_shake_256s_sign_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_256f_ENABLED)
	return lc_sphincs_shake_256f_sign_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_192s_ENABLED)
	return lc_sphincs_shake_192s_sign_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_192f_ENABLED)
	return lc_sphincs_shake_192f_sign_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_128s_ENABLED)
	return lc_sphincs_shake_128s_sign_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_128f_ENABLED)
	return lc_sphincs_shake_128f_sign_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sign_final, struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_256s;
		return lc_sphincs_shake_256s_sign_final(
			&sig->sig.sig_shake_256s, ctx, &sk->key.sk_shake_256s,
			rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_256f;
		return lc_sphincs_shake_256f_sign_final(
			&sig->sig.sig_shake_256f, ctx, &sk->key.sk_shake_256f,
			rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_192s;
		return lc_sphincs_shake_192s_sign_final(
			&sig->sig.sig_shake_192s, ctx, &sk->key.sk_shake_192s,
			rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_192f;
		return lc_sphincs_shake_192f_sign_final(
			&sig->sig.sig_shake_192f, ctx, &sk->key.sk_shake_192f,
			rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_128s;
		return lc_sphincs_shake_128s_sign_final(
			&sig->sig.sig_shake_128s, ctx, &sk->key.sk_shake_128s,
			rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		sig->sphincs_type = LC_SPHINCS_SHAKE_128f;
		return lc_sphincs_shake_128f_sign_final(
			&sig->sig.sig_shake_128f, ctx, &sk->key.sk_shake_128f,
			rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
