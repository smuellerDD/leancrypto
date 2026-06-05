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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include "ext_headers_internal.h"
#include "lc_dilithium.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign, struct lc_dilithium_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_sign(&sig->sig.sig_87, m, mlen,
					    &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_sign(&sig->sig.sig_65, m, mlen,
					    &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_sign(&sig->sig.sig_44, m, mlen,
					    &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_ctx, struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_sign_ctx(&sig->sig.sig_87, ctx, m, mlen,
						&sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_sign_ctx(&sig->sig.sig_65, ctx, m, mlen,
						&sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_sign_ctx(&sig->sig.sig_44, ctx, m, mlen,
						&sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_init, struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk)
{
	if (!sk)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_sign_init(ctx, &sk->key.sk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_sign_init(ctx, &sk->key.sk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_sign_init(ctx, &sk->key.sk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_update,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_sign_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_sign_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_sign_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_final,
		      struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_sign_final(&sig->sig.sig_87, ctx,
						  &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_sign_final(&sig->sig.sig_65, ctx,
						  &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_sign_final(&sig->sig.sig_44, ctx,
						  &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED25519_SIG

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign,
		      struct lc_dilithium_ed25519_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_ed25519_sign(&sig->sig.sig_87, m, mlen,
						    &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_ed25519_sign(&sig->sig.sig_65, m, mlen,
						    &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_ed25519_sign(&sig->sig.sig_44, m, mlen,
						    &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_ctx,
		      struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_ed25519_sign_ctx(&sig->sig.sig_87, ctx,
							m, mlen, &sk->key.sk_87,
							rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_ed25519_sign_ctx(&sig->sig.sig_65, ctx,
							m, mlen, &sk->key.sk_65,
							rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_ed25519_sign_ctx(&sig->sig.sig_44, ctx,
							m, mlen, &sk->key.sk_44,
							rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_init,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_sk *sk)
{
	if (!ctx || !sk)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed25519_sign_init(ctx, &sk->key.sk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed25519_sign_init(ctx, &sk->key.sk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed25519_sign_init(ctx, &sk->key.sk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_update,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_ed25519_sign_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_ed25519_sign_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_ed25519_sign_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_final,
		      struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig || !ctx)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_ed25519_sign_final(
			&sig->sig.sig_87, ctx, &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_ed25519_sign_final(
			&sig->sig.sig_65, ctx, &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_ed25519_sign_final(
			&sig->sig.sig_44, ctx, &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

#endif /* LC_DILITHIUM_ED25519_SIG */

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED448_SIG

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign,
		      struct lc_dilithium_ed448_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_ed448_sign(&sig->sig.sig_87, m, mlen,
						  &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_ed448_sign(&sig->sig.sig_65, m, mlen,
						  &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_ed448_sign(&sig->sig.sig_44, m, mlen,
						  &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_ctx,
		      struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_ed448_sign_ctx(&sig->sig.sig_87, ctx, m,
						      mlen, &sk->key.sk_87,
						      rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_ed448_sign_ctx(&sig->sig.sig_65, ctx, m,
						      mlen, &sk->key.sk_65,
						      rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_ed448_sign_ctx(&sig->sig.sig_44, ctx, m,
						      mlen, &sk->key.sk_44,
						      rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_init,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_sk *sk)
{
	if (!ctx || !sk)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed448_sign_init(ctx, &sk->key.sk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed448_sign_init(ctx, &sk->key.sk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed448_sign_init(ctx, &sk->key.sk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_update,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_ed448_sign_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_ed448_sign_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_ed448_sign_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_final,
		      struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	if (!sk || !sig || !ctx)
		return -EINVAL;

	switch (sk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		sig->dilithium_type = LC_DILITHIUM_87;
		return lc_dilithium_87_ed448_sign_final(
			&sig->sig.sig_87, ctx, &sk->key.sk_87, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		sig->dilithium_type = LC_DILITHIUM_65;
		return lc_dilithium_65_ed448_sign_final(
			&sig->sig.sig_65, ctx, &sk->key.sk_65, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		sig->dilithium_type = LC_DILITHIUM_44;
		return lc_dilithium_44_ed448_sign_final(
			&sig->sig.sig_44, ctx, &sk->key.sk_44, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

#endif /* LC_DILITHIUM_ED448_SIG */
