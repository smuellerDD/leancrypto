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
#include "ed25519_pct.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_ctx_alloc,
		      struct lc_dilithium_ctx **ctx)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_ctx_alloc(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_ctx_alloc(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_ctx_alloc(ctx);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ctx_alloc_ahat,
		      struct lc_dilithium_ctx **ctx)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_ctx_alloc_ahat(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_ctx_alloc_ahat(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_ctx_alloc_ahat(ctx);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ctx_zero_free,
		      struct lc_dilithium_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef LC_DILITHIUM_87_ENABLED
	lc_dilithium_87_ctx_zero_free(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	lc_dilithium_65_ctx_zero_free(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	lc_dilithium_44_ctx_zero_free(ctx);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ctx_zero, struct lc_dilithium_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef LC_DILITHIUM_87_ENABLED
	lc_dilithium_87_ctx_zero(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	lc_dilithium_65_ctx_zero(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	lc_dilithium_44_ctx_zero(ctx);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ctx_internal,
		      struct lc_dilithium_ctx *ctx)
{
	if (ctx)
		ctx->ml_dsa_internal = 1;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ctx_hash, struct lc_dilithium_ctx *ctx,
		      const struct lc_hash *hash)
{
	if (ctx)
		ctx->dilithium_prehash_type = hash;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ctx_userctx,
		      struct lc_dilithium_ctx *ctx, const uint8_t *userctx,
		      size_t userctxlen)
{
	if (ctx) {
		ctx->userctx = userctx;
		ctx->userctxlen = userctxlen;
	}
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ctx_external_mu,
		      struct lc_dilithium_ctx *ctx, const uint8_t *external_mu,
		      size_t external_mu_len)
{
	if (ctx) {
		ctx->external_mu = external_mu;
		ctx->external_mu_len = external_mu_len;
	}
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ctx_drop_ahat,
		      struct lc_dilithium_ctx *ctx)
{
	if (ctx)
		ctx->ahat_expanded = 0;
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_sk_type,
		      const struct lc_dilithium_sk *sk)
{
	if (!sk)
		return LC_DILITHIUM_UNKNOWN;
	return sk->dilithium_type;
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_pk_type,
		      const struct lc_dilithium_pk *pk)
{
	if (!pk)
		return LC_DILITHIUM_UNKNOWN;
	return pk->dilithium_type;
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_sig_type,
		      const struct lc_dilithium_sig *sig)
{
	if (!sig)
		return LC_DILITHIUM_UNKNOWN;
	return sig->dilithium_type;
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_sk_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_sk, key.sk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_sk, key.sk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_sk, key.sk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_pk_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_pk, key.pk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_pk, key.pk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_pk, key.pk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_sig_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_sig, sig.sig_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_sig, sig.sig_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_sig, sig.sig_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sk_load, struct lc_dilithium_sk *sk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (src_key_len == lc_dilithium_sk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_sk *_sk = &sk->key.sk_87;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (src_key_len == lc_dilithium_sk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_sk *_sk = &sk->key.sk_65;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (src_key_len == lc_dilithium_sk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_sk *_sk = &sk->key.sk_44;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_pk_load, struct lc_dilithium_pk *pk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (src_key_len == lc_dilithium_pk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_pk *_pk = &pk->key.pk_87;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (src_key_len == lc_dilithium_pk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_pk *_pk = &pk->key.pk_65;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (src_key_len == lc_dilithium_pk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_pk *_pk = &pk->key.pk_44;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sig_load, struct lc_dilithium_sig *sig,
		      const uint8_t *src_sig, size_t src_sig_len)
{
	if (!sig || !src_sig || src_sig_len == 0) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (src_sig_len == lc_dilithium_sig_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_sig *_sig = &sig->sig.sig_87;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (src_sig_len == lc_dilithium_sig_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_sig *_sig = &sig->sig.sig_65;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (src_sig_len == lc_dilithium_sig_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_sig *_sig = &sig->sig.sig_44;

		memcpy(_sig->sig, src_sig, src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sk_ptr, uint8_t **dilithium_key,
		      size_t *dilithium_key_len, struct lc_dilithium_sk *sk)
{
	if (!sk || !dilithium_key || !dilithium_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_sk *_sk = &sk->key.sk_87;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_sk *_sk = &sk->key.sk_65;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_sk *_sk = &sk->key.sk_44;

		*dilithium_key = _sk->sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_pk_ptr, uint8_t **dilithium_key,
		      size_t *dilithium_key_len, struct lc_dilithium_pk *pk)
{
	if (!pk || !dilithium_key || !dilithium_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_pk *_pk = &pk->key.pk_87;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_pk *_pk = &pk->key.pk_65;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_pk *_pk = &pk->key.pk_44;

		*dilithium_key = _pk->pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sig_ptr, uint8_t **dilithium_sig,
		      size_t *dilithium_sig_len, struct lc_dilithium_sig *sig)
{
	if (!sig || !dilithium_sig || !dilithium_sig_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_sig *_sig = &sig->sig.sig_87;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_sig *_sig = &sig->sig.sig_65;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_sig *_sig = &sig->sig.sig_44;

		*dilithium_sig = _sig->sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(enum lc_alg_status_val, lc_dilithium_alg_status,
		      const enum lc_dilithium_type dilithium_type,
		      const enum lc_dilithium_alg_operation operation)
{
	(void)dilithium_type;

	switch (operation) {
	case lc_alg_operation_dilithium_keygen:
		return lc_alg_status(LC_ALG_STATUS_FIPS |
				     LC_ALG_STATUS_MLDSA_KEYGEN);
	case lc_alg_operation_dilithium_siggen:
		return lc_alg_status(LC_ALG_STATUS_FIPS |
				     LC_ALG_STATUS_MLDSA_SIGGEN);
	case lc_alg_operation_dilithium_sigver:
		return lc_alg_status(LC_ALG_STATUS_FIPS |
				     LC_ALG_STATUS_MLDSA_SIGVER);
	case lc_alg_operation_dilithium_unknown:
	default:
		return lc_alg_status_unknown;
	}
	return lc_alg_status_unknown;
}

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED25519_SIG

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_ctx_alloc,
		      struct lc_dilithium_ed25519_ctx **ctx)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_ed25519_ctx_alloc(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_ed25519_ctx_alloc(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_ed25519_ctx_alloc(ctx);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed25519_ctx_zero_free,
		      struct lc_dilithium_ed25519_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef LC_DILITHIUM_87_ENABLED
	lc_dilithium_87_ed25519_ctx_zero_free(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	lc_dilithium_65_ed25519_ctx_zero_free(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	lc_dilithium_44_ed25519_ctx_zero_free(ctx);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed25519_ctx_zero,
		      struct lc_dilithium_ed25519_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef LC_DILITHIUM_87_ENABLED
	lc_dilithium_87_ed25519_ctx_zero(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	lc_dilithium_65_ed25519_ctx_zero(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	lc_dilithium_44_ed25519_ctx_zero(ctx);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed25519_ctx_hash,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_hash *hash)
{
	if (ctx)
		ctx->dilithium_ctx.dilithium_prehash_type = hash;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed25519_ctx_internal,
		      struct lc_dilithium_ed25519_ctx *ctx)
{
	if (ctx)
		ctx->dilithium_ctx.ml_dsa_internal = 1;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed25519_ctx_userctx,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const uint8_t *userctx, size_t userctxlen)
{
	if (ctx) {
		ctx->dilithium_ctx.userctx = userctx;
		ctx->dilithium_ctx.userctxlen = userctxlen;
	}
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_ed25519_sk_type,
		      const struct lc_dilithium_ed25519_sk *sk)
{
	if (!sk)
		return LC_DILITHIUM_UNKNOWN;
	return sk->dilithium_type;
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_ed25519_pk_type,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	if (!pk)
		return LC_DILITHIUM_UNKNOWN;
	return pk->dilithium_type;
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_ed25519_sig_type,
		      const struct lc_dilithium_ed25519_sig *sig)
{
	if (!sig)
		return LC_DILITHIUM_UNKNOWN;
	return sig->dilithium_type;
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_ed25519_sk_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sk,
				      key.sk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sk,
				      key.sk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sk,
				      key.sk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_ed25519_pk_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_pk,
				      key.pk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_pk,
				      key.pk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_pk,
				      key.pk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_ed25519_sig_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sig,
				      sig.sig_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sig,
				      sig.sig_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed25519_sig,
				      sig.sig_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sk_load,
		      struct lc_dilithium_ed25519_sk *sk,
		      const uint8_t *dilithium_src_key,
		      size_t dilithium_src_key_len,
		      const uint8_t *ed25519_src_key,
		      size_t ed25519_src_key_len)
{
	if (!sk || !dilithium_src_key || !ed25519_src_key ||
	    (ed25519_src_key_len != LC_ED25519_RAW_SECRETKEYBYTES &&
	     ed25519_src_key_len != LC_ED25519_SECRETKEYBYTES)) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_sk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed25519_sk *_sk = &sk->key.sk_87;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed25519.sk, ed25519_src_key,
		       ed25519_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_87;

		/*
		 * Allow only the secret part of the key to be set and
		 * then re-establish the public part.
		 */
		if (ed25519_src_key_len == LC_ED25519_RAW_SECRETKEYBYTES)
			return (lc_ed25519_derive_pk(NULL, &_sk->sk_ed25519));
		/* Check that the public/private key are a pair */
		return _lc_ed25519_pct_fips(
			(struct lc_ed25519_pk *)(_sk->sk_ed25519.sk + 32),
			&_sk->sk_ed25519);
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_sk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed25519_sk *_sk = &sk->key.sk_65;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed25519.sk, ed25519_src_key,
		       ed25519_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_65;

		/*
		 * Allow only the secret part of the key to be set and
		 * then re-establish the public part.
		 */
		if (ed25519_src_key_len == LC_ED25519_RAW_SECRETKEYBYTES)
			return (lc_ed25519_derive_pk(NULL, &_sk->sk_ed25519));
		/* Check that the public/private key are a pair */
		return _lc_ed25519_pct_fips(
			(struct lc_ed25519_pk *)(_sk->sk_ed25519.sk + 32),
			&_sk->sk_ed25519);
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_sk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed25519_sk *_sk = &sk->key.sk_44;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed25519.sk, ed25519_src_key,
		       ed25519_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_44;

		/*
		 * Allow only the secret part of the key to be set and
		 * then re-establish the public part.
		 */
		if (ed25519_src_key_len == LC_ED25519_RAW_SECRETKEYBYTES)
			return (lc_ed25519_derive_pk(NULL, &_sk->sk_ed25519));
		/* Check that the public/private key are a pair */
		return _lc_ed25519_pct_fips(
			(struct lc_ed25519_pk *)(_sk->sk_ed25519.sk + 32),
			&_sk->sk_ed25519);
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_pk_load,
		      struct lc_dilithium_ed25519_pk *pk,
		      const uint8_t *dilithium_src_key,
		      size_t dilithium_src_key_len,
		      const uint8_t *ed25519_src_key,
		      size_t ed25519_src_key_len)
{
	if (!pk || !dilithium_src_key || !ed25519_src_key ||
	    ed25519_src_key_len != LC_ED25519_PUBLICKEYBYTES) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed25519_pk *_pk = &pk->key.pk_87;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed25519.pk, ed25519_src_key,
		       ed25519_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed25519_pk *_pk = &pk->key.pk_65;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed25519.pk, ed25519_src_key,
		       ed25519_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed25519_pk *_pk = &pk->key.pk_44;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed25519.pk, ed25519_src_key,
		       ed25519_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sig_load,
		      struct lc_dilithium_ed25519_sig *sig,
		      const uint8_t *dilithium_src_sig,
		      size_t dilithium_src_sig_len,
		      const uint8_t *ed25519_src_sig,
		      size_t ed25519_src_sig_len)
{
	if (!sig || !dilithium_src_sig || !ed25519_src_sig ||
	    ed25519_src_sig_len != LC_ED25519_SIGBYTES) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed25519_sig *_sig = &sig->sig.sig_87;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed25519.sig, ed25519_src_sig,
		       ed25519_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed25519_sig *_sig = &sig->sig.sig_65;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed25519.sig, ed25519_src_sig,
		       ed25519_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed25519_sig *_sig = &sig->sig.sig_44;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed25519.sig, ed25519_src_sig,
		       ed25519_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sk_ptr, uint8_t **dilithium_key,
		      size_t *dilithium_key_len, uint8_t **ed25519_key,
		      size_t *ed25519_key_len,
		      struct lc_dilithium_ed25519_sk *sk)
{
	if (!sk || !dilithium_key || !dilithium_key_len || !ed25519_key ||
	    !ed25519_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed25519_sk *_sk = &sk->key.sk_87;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed25519_key = _sk->sk_ed25519.sk;
		*ed25519_key_len = LC_ED25519_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed25519_sk *_sk = &sk->key.sk_65;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed25519_key = _sk->sk_ed25519.sk;
		*ed25519_key_len = LC_ED25519_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed25519_sk *_sk = &sk->key.sk_44;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed25519_key = _sk->sk_ed25519.sk;
		*ed25519_key_len = LC_ED25519_SECRETKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_pk_ptr, uint8_t **dilithium_key,
		      size_t *dilithium_key_len, uint8_t **ed25519_key,
		      size_t *ed25519_key_len,
		      struct lc_dilithium_ed25519_pk *pk)
{
	if (!pk || !dilithium_key || !dilithium_key_len || !ed25519_key ||
	    !ed25519_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed25519_pk *_pk = &pk->key.pk_87;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed25519_key = _pk->pk_ed25519.pk;
		*ed25519_key_len = LC_ED25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed25519_pk *_pk = &pk->key.pk_65;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed25519_key = _pk->pk_ed25519.pk;
		*ed25519_key_len = LC_ED25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed25519_pk *_pk = &pk->key.pk_44;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed25519_key = _pk->pk_ed25519.pk;
		*ed25519_key_len = LC_ED25519_PUBLICKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sig_ptr,
		      uint8_t **dilithium_sig, size_t *dilithium_sig_len,
		      uint8_t **ed25519_sig, size_t *ed25519_sig_len,
		      struct lc_dilithium_ed25519_sig *sig)
{
	if (!sig || !dilithium_sig || !dilithium_sig_len || !ed25519_sig ||
	    !ed25519_sig_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed25519_sig *_sig = &sig->sig.sig_87;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed25519_sig = _sig->sig_ed25519.sig;
		*ed25519_sig_len = LC_ED25519_SIGBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed25519_sig *_sig = &sig->sig.sig_65;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed25519_sig = _sig->sig_ed25519.sig;
		*ed25519_sig_len = LC_ED25519_SIGBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed25519_sig *_sig = &sig->sig.sig_44;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed25519_sig = _sig->sig_ed25519.sig;
		*ed25519_sig_len = LC_ED25519_SIGBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

#endif /* LC_DILITHIUM_ED25519_SIG */

/****************************** Dilithium ED25510 *****************************/

#ifdef LC_DILITHIUM_ED448_SIG

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_ctx_alloc,
		      struct lc_dilithium_ed448_ctx **ctx)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_DILITHIUM_87_ENABLED
	return lc_dilithium_87_ed448_ctx_alloc(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	return lc_dilithium_65_ed448_ctx_alloc(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	return lc_dilithium_44_ed448_ctx_alloc(ctx);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed448_ctx_zero_free,
		      struct lc_dilithium_ed448_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef LC_DILITHIUM_87_ENABLED
	lc_dilithium_87_ed448_ctx_zero_free(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	lc_dilithium_65_ed448_ctx_zero_free(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	lc_dilithium_44_ed448_ctx_zero_free(ctx);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed448_ctx_zero,
		      struct lc_dilithium_ed448_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef LC_DILITHIUM_87_ENABLED
	lc_dilithium_87_ed448_ctx_zero(ctx);
#elif defined(LC_DILITHIUM_65_ENABLED)
	lc_dilithium_65_ed448_ctx_zero(ctx);
#elif defined(LC_DILITHIUM_44_ENABLED)
	lc_dilithium_44_ed448_ctx_zero(ctx);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed448_ctx_hash,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_hash *hash)
{
	if (ctx)
		ctx->dilithium_ctx.dilithium_prehash_type = hash;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed448_ctx_internal,
		      struct lc_dilithium_ed448_ctx *ctx)
{
	if (ctx)
		ctx->dilithium_ctx.ml_dsa_internal = 1;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed448_ctx_userctx,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const uint8_t *userctx, size_t userctxlen)
{
	if (ctx) {
		ctx->dilithium_ctx.userctx = userctx;
		ctx->dilithium_ctx.userctxlen = userctxlen;
	}
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_ed448_sk_type,
		      const struct lc_dilithium_ed448_sk *sk)
{
	if (!sk)
		return LC_DILITHIUM_UNKNOWN;
	return sk->dilithium_type;
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_ed448_pk_type,
		      const struct lc_dilithium_ed448_pk *pk)
{
	if (!pk)
		return LC_DILITHIUM_UNKNOWN;
	return pk->dilithium_type;
}

LC_INTERFACE_FUNCTION(enum lc_dilithium_type, lc_dilithium_ed448_sig_type,
		      const struct lc_dilithium_ed448_sig *sig)
{
	if (!sig)
		return LC_DILITHIUM_UNKNOWN;
	return sig->dilithium_type;
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_ed448_sk_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_sk, key.sk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_sk, key.sk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_sk, key.sk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_ed448_pk_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_pk, key.pk_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_pk, key.pk_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_pk, key.pk_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_dilithium_ed448_sig_size,
			      enum lc_dilithium_type dilithium_type)
{
	switch (dilithium_type) {
	case LC_DILITHIUM_87:
#ifdef LC_DILITHIUM_87_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_sig,
				      sig.sig_87);
#else
		return 0;
#endif
	case LC_DILITHIUM_65:
#ifdef LC_DILITHIUM_65_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_sig,
				      sig.sig_65);
#else
		return 0;
#endif
	case LC_DILITHIUM_44:
#ifdef LC_DILITHIUM_44_ENABLED
		return lc_member_size(struct lc_dilithium_ed448_sig,
				      sig.sig_44);
#else
		return 0;
#endif
	case LC_DILITHIUM_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sk_load,
		      struct lc_dilithium_ed448_sk *sk,
		      const uint8_t *dilithium_src_key,
		      size_t dilithium_src_key_len,
		      const uint8_t *ed448_src_key, size_t ed448_src_key_len)
{
	if (!sk || !dilithium_src_key || !ed448_src_key ||
	    ed448_src_key_len != LC_ED448_SECRETKEYBYTES) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_sk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed448_sk *_sk = &sk->key.sk_87;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed448.sk, ed448_src_key, ed448_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_sk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed448_sk *_sk = &sk->key.sk_65;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed448.sk, ed448_src_key, ed448_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_sk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed448_sk *_sk = &sk->key.sk_44;

		memcpy(_sk->sk.sk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_sk->sk_ed448.sk, ed448_src_key, ed448_src_key_len);
		sk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_pk_load,
		      struct lc_dilithium_ed448_pk *pk,
		      const uint8_t *dilithium_src_key,
		      size_t dilithium_src_key_len,
		      const uint8_t *ed448_src_key, size_t ed448_src_key_len)
{
	if (!pk || !dilithium_src_key || !ed448_src_key ||
	    ed448_src_key_len != LC_ED448_PUBLICKEYBYTES) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed448_pk *_pk = &pk->key.pk_87;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed448.pk, ed448_src_key, ed448_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed448_pk *_pk = &pk->key.pk_65;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed448.pk, ed448_src_key, ed448_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_key_len ==
		   lc_dilithium_pk_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed448_pk *_pk = &pk->key.pk_44;

		memcpy(_pk->pk.pk, dilithium_src_key, dilithium_src_key_len);
		memcpy(_pk->pk_ed448.pk, ed448_src_key, ed448_src_key_len);
		pk->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sig_load,
		      struct lc_dilithium_ed448_sig *sig,
		      const uint8_t *dilithium_src_sig,
		      size_t dilithium_src_sig_len,
		      const uint8_t *ed448_src_sig, size_t ed448_src_sig_len)
{
	if (!sig || !dilithium_src_sig || !ed448_src_sig ||
	    ed448_src_sig_len != LC_ED448_SIGBYTES) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_87)) {
		struct lc_dilithium_87_ed448_sig *_sig = &sig->sig.sig_87;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed448.sig, ed448_src_sig, ed448_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_87;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_65)) {
		struct lc_dilithium_65_ed448_sig *_sig = &sig->sig.sig_65;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed448.sig, ed448_src_sig, ed448_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_65;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (dilithium_src_sig_len ==
		   lc_dilithium_sig_size(LC_DILITHIUM_44)) {
		struct lc_dilithium_44_ed448_sig *_sig = &sig->sig.sig_44;

		memcpy(_sig->sig.sig, dilithium_src_sig, dilithium_src_sig_len);
		memcpy(_sig->sig_ed448.sig, ed448_src_sig, ed448_src_sig_len);
		sig->dilithium_type = LC_DILITHIUM_44;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sk_ptr, uint8_t **dilithium_key,
		      size_t *dilithium_key_len, uint8_t **ed448_key,
		      size_t *ed448_key_len, struct lc_dilithium_ed448_sk *sk)
{
	if (!sk || !dilithium_key || !dilithium_key_len || !ed448_key ||
	    !ed448_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed448_sk *_sk = &sk->key.sk_87;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed448_key = _sk->sk_ed448.sk;
		*ed448_key_len = LC_ED448_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed448_sk *_sk = &sk->key.sk_65;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed448_key = _sk->sk_ed448.sk;
		*ed448_key_len = LC_ED448_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed448_sk *_sk = &sk->key.sk_44;

		*dilithium_key = _sk->sk.sk;
		*dilithium_key_len = lc_dilithium_sk_size(sk->dilithium_type);
		*ed448_key = _sk->sk_ed448.sk;
		*ed448_key_len = LC_ED448_SECRETKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_pk_ptr, uint8_t **dilithium_key,
		      size_t *dilithium_key_len, uint8_t **ed448_key,
		      size_t *ed448_key_len, struct lc_dilithium_ed448_pk *pk)
{
	if (!pk || !dilithium_key || !dilithium_key_len || !ed448_key ||
	    !ed448_key_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed448_pk *_pk = &pk->key.pk_87;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed448_key = _pk->pk_ed448.pk;
		*ed448_key_len = LC_ED448_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed448_pk *_pk = &pk->key.pk_65;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed448_key = _pk->pk_ed448.pk;
		*ed448_key_len = LC_ED448_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (pk->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed448_pk *_pk = &pk->key.pk_44;

		*dilithium_key = _pk->pk.pk;
		*dilithium_key_len = lc_dilithium_pk_size(pk->dilithium_type);
		*ed448_key = _pk->pk_ed448.pk;
		*ed448_key_len = LC_ED448_PUBLICKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sig_ptr, uint8_t **dilithium_sig,
		      size_t *dilithium_sig_len, uint8_t **ed448_sig,
		      size_t *ed448_sig_len, struct lc_dilithium_ed448_sig *sig)
{
	if (!sig || !dilithium_sig || !dilithium_sig_len || !ed448_sig ||
	    !ed448_sig_len) {
		return -EINVAL;
#ifdef LC_DILITHIUM_87_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_87) {
		struct lc_dilithium_87_ed448_sig *_sig = &sig->sig.sig_87;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed448_sig = _sig->sig_ed448.sig;
		*ed448_sig_len = LC_ED448_SIGBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_65_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_65) {
		struct lc_dilithium_65_ed448_sig *_sig = &sig->sig.sig_65;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed448_sig = _sig->sig_ed448.sig;
		*ed448_sig_len = LC_ED448_SIGBYTES;
		return 0;
#endif
#ifdef LC_DILITHIUM_44_ENABLED
	} else if (sig->dilithium_type == LC_DILITHIUM_44) {
		struct lc_dilithium_44_ed448_sig *_sig = &sig->sig.sig_44;

		*dilithium_sig = _sig->sig.sig;
		*dilithium_sig_len = lc_dilithium_sig_size(sig->dilithium_type);
		*ed448_sig = _sig->sig_ed448.sig;
		*ed448_sig_len = LC_ED448_SIGBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

#endif /* LC_DILITHIUM_ED448_SIG */
