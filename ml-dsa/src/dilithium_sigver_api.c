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
#include "status_algorithms.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_verify(&sig->sig.sig_87, m, mlen,
					      &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_verify(&sig->sig.sig_65, m, mlen,
					      &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_verify(&sig->sig.sig_44, m, mlen,
					      &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_ctx,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_verify_ctx(&sig->sig.sig_87, ctx, m,
						  mlen, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_verify_ctx(&sig->sig.sig_65, ctx, m,
						  mlen, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_verify_ctx(&sig->sig.sig_44, ctx, m,
						  mlen, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	if (!pk)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_verify_init(ctx, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_verify_init(ctx, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_verify_init(ctx, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_verify_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_verify_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_verify_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_verify_final(&sig->sig.sig_87, ctx,
						    &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_verify_final(&sig->sig.sig_65, ctx,
						    &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_verify_final(&sig->sig.sig_44, ctx,
						    &pk->key.pk_44);
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

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify,
		      const struct lc_dilithium_ed25519_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed25519_verify(&sig->sig.sig_87, m, mlen,
						      &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed25519_verify(&sig->sig.sig_65, m, mlen,
						      &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed25519_verify(&sig->sig.sig_44, m, mlen,
						      &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_ctx,
		      const struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed25519_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed25519_verify_ctx(
			&sig->sig.sig_87, ctx, m, mlen, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed25519_verify_ctx(
			&sig->sig.sig_65, ctx, m, mlen, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed25519_verify_ctx(
			&sig->sig.sig_44, ctx, m, mlen, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_init,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	if (!pk || !ctx)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed25519_verify_init(ctx, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed25519_verify_init(ctx, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed25519_verify_init(ctx, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_update,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_ed25519_verify_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_ed25519_verify_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_ed25519_verify_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_final,
		      const struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	if (!ctx || !pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed25519_verify_final(
			&sig->sig.sig_87, ctx, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed25519_verify_final(
			&sig->sig.sig_65, ctx, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed25519_verify_final(
			&sig->sig.sig_44, ctx, &pk->key.pk_44);
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

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify,
		      const struct lc_dilithium_ed448_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_ed448_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed448_verify(&sig->sig.sig_87, m, mlen,
						    &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed448_verify(&sig->sig.sig_65, m, mlen,
						    &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed448_verify(&sig->sig.sig_44, m, mlen,
						    &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_ctx,
		      const struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed448_pk *pk)
{
	if (!pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed448_verify_ctx(
			&sig->sig.sig_87, ctx, m, mlen, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed448_verify_ctx(
			&sig->sig.sig_65, ctx, m, mlen, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed448_verify_ctx(
			&sig->sig.sig_44, ctx, m, mlen, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_init,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_pk *pk)
{
	if (!pk || !ctx)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed448_verify_init(ctx, &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed448_verify_init(ctx, &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed448_verify_init(ctx, &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_update,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_ed448_verify_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_ed448_verify_update(ctx, m, mlen);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_ed448_verify_update(ctx, m, mlen);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_final,
		      const struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_pk *pk)
{
	if (!ctx || !pk || !sig || sig->dilithium_type != pk->dilithium_type)
		return -EINVAL;

	switch (pk->dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_dilithium_87_ed448_verify_final(&sig->sig.sig_87, ctx,
							  &pk->key.pk_87);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_dilithium_65_ed448_verify_final(&sig->sig.sig_65, ctx,
							  &pk->key.pk_65);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_dilithium_44_ed448_verify_final(&sig->sig.sig_44, ctx,
							  &pk->key.pk_44);
#else
		return -EOPNOTSUPP;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

#endif /* LC_DILITHIUM_ED448_SIG */
