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

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify, const struct lc_sphincs_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_pk *pk)
{
	if (!pk || !sig || sig->sphincs_type != pk->sphincs_type)
		return -EINVAL;

	switch (pk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		return lc_sphincs_shake_256s_verify(&sig->sig.sig_shake_256s, m,
						    mlen,
						    &pk->key.pk_shake_256s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		return lc_sphincs_shake_256f_verify(&sig->sig.sig_shake_256f, m,
						    mlen,
						    &pk->key.pk_shake_256f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		return lc_sphincs_shake_192s_verify(&sig->sig.sig_shake_192s, m,
						    mlen,
						    &pk->key.pk_shake_192s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		return lc_sphincs_shake_192f_verify(&sig->sig.sig_shake_192f, m,
						    mlen,
						    &pk->key.pk_shake_192f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		return lc_sphincs_shake_128s_verify(&sig->sig.sig_shake_128s, m,
						    mlen,
						    &pk->key.pk_shake_128s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		return lc_sphincs_shake_128f_verify(&sig->sig.sig_shake_128f, m,
						    mlen,
						    &pk->key.pk_shake_128f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_ctx,
		      const struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx, const uint8_t *m, size_t mlen,
		      const struct lc_sphincs_pk *pk)
{
	if (!pk || !sig || sig->sphincs_type != pk->sphincs_type)
		return -EINVAL;

	switch (pk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		return lc_sphincs_shake_256s_verify_ctx(
			&sig->sig.sig_shake_256s, ctx, m, mlen,
			&pk->key.pk_shake_256s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		return lc_sphincs_shake_256f_verify_ctx(
			&sig->sig.sig_shake_256f, ctx, m, mlen,
			&pk->key.pk_shake_256f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		return lc_sphincs_shake_192s_verify_ctx(
			&sig->sig.sig_shake_192s, ctx, m, mlen,
			&pk->key.pk_shake_192s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		return lc_sphincs_shake_192f_verify_ctx(
			&sig->sig.sig_shake_192f, ctx, m, mlen,
			&pk->key.pk_shake_192f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		return lc_sphincs_shake_128s_verify_ctx(
			&sig->sig.sig_shake_128s, ctx, m, mlen,
			&pk->key.pk_shake_128s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		return lc_sphincs_shake_128f_verify_ctx(
			&sig->sig.sig_shake_128f, ctx, m, mlen,
			&pk->key.pk_shake_128f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_init, struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_pk *pk)
{
	if (!pk)
		return -EINVAL;

	switch (pk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		return lc_sphincs_shake_256s_verify_init(
			ctx, &pk->key.pk_shake_256s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		return lc_sphincs_shake_256f_verify_init(
			ctx, &pk->key.pk_shake_256f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		return lc_sphincs_shake_192s_verify_init(
			ctx, &pk->key.pk_shake_192s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		return lc_sphincs_shake_192f_verify_init(
			ctx, &pk->key.pk_shake_192f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		return lc_sphincs_shake_128s_verify_init(
			ctx, &pk->key.pk_shake_128s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		return lc_sphincs_shake_128f_verify_init(
			ctx, &pk->key.pk_shake_128f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_update, struct lc_sphincs_ctx *ctx,
		      const uint8_t *m, size_t mlen)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	return lc_sphincs_shake_256s_verify_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_256f_ENABLED)
	return lc_sphincs_shake_256f_verify_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_192s_ENABLED)
	return lc_sphincs_shake_192s_verify_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_192f_ENABLED)
	return lc_sphincs_shake_192f_verify_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_128s_ENABLED)
	return lc_sphincs_shake_128s_verify_update(ctx, m, mlen);
#elif defined(LC_SPHINCS_SHAKE_128f_ENABLED)
	return lc_sphincs_shake_128f_verify_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_verify_final,
		      const struct lc_sphincs_sig *sig,
		      struct lc_sphincs_ctx *ctx,
		      const struct lc_sphincs_pk *pk)
{
	if (!pk || !sig || sig->sphincs_type != pk->sphincs_type)
		return -EINVAL;

	switch (pk->sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		return lc_sphincs_shake_256s_verify_final(
			&sig->sig.sig_shake_256s, ctx, &pk->key.pk_shake_256s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		return lc_sphincs_shake_256f_verify_final(
			&sig->sig.sig_shake_256f, ctx, &pk->key.pk_shake_256f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		return lc_sphincs_shake_192s_verify_final(
			&sig->sig.sig_shake_192s, ctx, &pk->key.pk_shake_192s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		return lc_sphincs_shake_192f_verify_final(
			&sig->sig.sig_shake_192f, ctx, &pk->key.pk_shake_192f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		return lc_sphincs_shake_128s_verify_final(
			&sig->sig.sig_shake_128s, ctx, &pk->key.pk_shake_128s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		return lc_sphincs_shake_128f_verify_final(
			&sig->sig.sig_shake_128f, ctx, &pk->key.pk_shake_128f);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
