/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_sphincs_ctx_alloc, struct lc_sphincs_ctx **ctx)
{
	if (!ctx)
		return -EINVAL;

#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	return lc_sphincs_shake_256s_ctx_alloc(ctx);
#elif defined(LC_SPHINCS_SHAKE_256f_ENABLED)
	return lc_sphincs_shake_256f_ctx_alloc(ctx);
#elif defined(LC_SPHINCS_SHAKE_192s_ENABLED)
	return lc_sphincs_shake_192s_ctx_alloc(ctx);
#elif defined(LC_SPHINCS_SHAKE_192f_ENABLED)
	return lc_sphincs_shake_192f_ctx_alloc(ctx);
#elif defined(LC_SPHINCS_SHAKE_128s_ENABLED)
	return lc_sphincs_shake_128s_ctx_alloc(ctx);
#elif defined(LC_SPHINCS_SHAKE_128f_ENABLED)
	return lc_sphincs_shake_128f_ctx_alloc(ctx);
#else
	return -EOPNOTSUPP;
#endif
}

LC_INTERFACE_FUNCTION(void, lc_sphincs_ctx_zero_free,
		      struct lc_sphincs_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	lc_sphincs_shake_256s_ctx_zero_free(ctx);
#elif defined(LC_SPHINCS_SHAKE_256f_ENABLED)
	lc_sphincs_shake_256f_ctx_zero_free(ctx);
#elif defined(LC_SPHINCS_SHAKE_192s_ENABLED)
	lc_sphincs_shake_192s_ctx_zero_free(ctx);
#elif defined(LC_SPHINCS_SHAKE_192f_ENABLED)
	lc_sphincs_shake_192f_ctx_zero_free(ctx);
#elif defined(LC_SPHINCS_SHAKE_128s_ENABLED)
	lc_sphincs_shake_128s_ctx_zero_free(ctx);
#elif defined(LC_SPHINCS_SHAKE_128f_ENABLED)
	lc_sphincs_shake_128f_ctx_zero_free(ctx);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_sphincs_ctx_zero, struct lc_sphincs_ctx *ctx)
{
	if (!ctx)
		return;

#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	lc_sphincs_shake_256s_ctx_zero(ctx);
#elif defined(LC_SPHINCS_SHAKE_256f_ENABLED)
	lc_sphincs_shake_256f_ctx_zero(ctx);
#elif defined(LC_SPHINCS_SHAKE_192s_ENABLED)
	lc_sphincs_shake_192s_ctx_zero(ctx);
#elif defined(LC_SPHINCS_SHAKE_192f_ENABLED)
	lc_sphincs_shake_192f_ctx_zero(ctx);
#elif defined(LC_SPHINCS_SHAKE_128s_ENABLED)
	lc_sphincs_shake_128s_ctx_zero(ctx);
#elif defined(LC_SPHINCS_SHAKE_128f_ENABLED)
	lc_sphincs_shake_128f_ctx_zero(ctx);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_sphincs_ctx_internal, struct lc_sphincs_ctx *ctx)
{
	if (ctx)
		ctx->slh_dsa_internal = 1;
}

LC_INTERFACE_FUNCTION(void, lc_sphincs_ctx_hash, struct lc_sphincs_ctx *ctx,
		      const struct lc_hash *hash)
{
	if (ctx)
		ctx->sphincs_prehash_type = hash;
}

LC_INTERFACE_FUNCTION(void, lc_sphincs_ctx_userctx, struct lc_sphincs_ctx *ctx,
		      const uint8_t *userctx, size_t userctxlen)
{
	if (ctx) {
		ctx->userctx = userctx;
		ctx->userctxlen = userctxlen;
	}
}

LC_INTERFACE_FUNCTION(enum lc_sphincs_type, lc_sphincs_sk_type,
		      const struct lc_sphincs_sk *sk)
{
	if (!sk)
		return LC_SPHINCS_UNKNOWN;
	return sk->sphincs_type;
}

LC_INTERFACE_FUNCTION(enum lc_sphincs_type, lc_sphincs_pk_type,
		      const struct lc_sphincs_pk *pk)
{
	if (!pk)
		return LC_SPHINCS_UNKNOWN;
	return pk->sphincs_type;
}

LC_INTERFACE_FUNCTION(enum lc_sphincs_type, lc_sphincs_sig_type,
		      const struct lc_sphincs_sig *sig)
{
	if (!sig)
		return LC_SPHINCS_UNKNOWN;
	return sig->sphincs_type;
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_sphincs_sk_size,
			      enum lc_sphincs_type sphincs_type)
{
	switch (sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		return lc_member_size(struct lc_sphincs_sk, key.sk_shake_256s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		return lc_member_size(struct lc_sphincs_sk, key.sk_shake_256f);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		return lc_member_size(struct lc_sphincs_sk, key.sk_shake_192s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		return lc_member_size(struct lc_sphincs_sk, key.sk_shake_192f);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		return lc_member_size(struct lc_sphincs_sk, key.sk_shake_128s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		return lc_member_size(struct lc_sphincs_sk, key.sk_shake_128f);
#else
		return 0;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_sphincs_pk_size,
			      enum lc_sphincs_type sphincs_type)
{
	switch (sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		return lc_member_size(struct lc_sphincs_pk, key.pk_shake_256s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		return lc_member_size(struct lc_sphincs_pk, key.pk_shake_256f);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		return lc_member_size(struct lc_sphincs_pk, key.pk_shake_192s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		return lc_member_size(struct lc_sphincs_pk, key.pk_shake_192f);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		return lc_member_size(struct lc_sphincs_pk, key.pk_shake_128s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		return lc_member_size(struct lc_sphincs_pk, key.pk_shake_128f);
#else
		return 0;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE LC_INTERFACE_FUNCTION(unsigned int, lc_sphincs_sig_size,
			      enum lc_sphincs_type sphincs_type)
{
	switch (sphincs_type) {
	case LC_SPHINCS_SHAKE_256s:
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
		return lc_member_size(struct lc_sphincs_sig,
				      sig.sig_shake_256s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_256f:
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
		return lc_member_size(struct lc_sphincs_sig,
				      sig.sig_shake_256f);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_192s:
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
		return lc_member_size(struct lc_sphincs_sig,
				      sig.sig_shake_192s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_192f:
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
		return lc_member_size(struct lc_sphincs_sig,
				      sig.sig_shake_192f);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_128s:
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
		return lc_member_size(struct lc_sphincs_sig,
				      sig.sig_shake_128s);
#else
		return 0;
#endif
	case LC_SPHINCS_SHAKE_128f:
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
		return lc_member_size(struct lc_sphincs_sig,
				      sig.sig_shake_128f);
#else
		return 0;
#endif
	case LC_SPHINCS_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sk_load, struct lc_sphincs_sk *sk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	} else if (src_key_len == lc_sphincs_sk_size(LC_SPHINCS_SHAKE_256s)) {
		struct lc_sphincs_shake_256s_sk *_sk = &sk->key.sk_shake_256s;

		memcpy(_sk, src_key, src_key_len);
		sk->sphincs_type = LC_SPHINCS_SHAKE_256s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
	} else if (src_key_len == lc_sphincs_sk_size(LC_SPHINCS_SHAKE_256f)) {
		struct lc_sphincs_shake_256f_sk *_sk = &sk->key.sk_shake_256f;

		memcpy(_sk, src_key, src_key_len);
		sk->sphincs_type = LC_SPHINCS_SHAKE_256f;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
	} else if (src_key_len == lc_sphincs_sk_size(LC_SPHINCS_SHAKE_192s)) {
		struct lc_sphincs_shake_192s_sk *_sk = &sk->key.sk_shake_192s;

		memcpy(_sk, src_key, src_key_len);
		sk->sphincs_type = LC_SPHINCS_SHAKE_192s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
	} else if (src_key_len == lc_sphincs_sk_size(LC_SPHINCS_SHAKE_192f)) {
		struct lc_sphincs_shake_192f_sk *_sk = &sk->key.sk_shake_192f;

		memcpy(_sk, src_key, src_key_len);
		sk->sphincs_type = LC_SPHINCS_SHAKE_192f;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
	} else if (src_key_len == lc_sphincs_sk_size(LC_SPHINCS_SHAKE_128s)) {
		struct lc_sphincs_shake_128s_sk *_sk = &sk->key.sk_shake_128s;

		memcpy(_sk, src_key, src_key_len);
		sk->sphincs_type = LC_SPHINCS_SHAKE_128s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
	} else if (src_key_len == lc_sphincs_sk_size(LC_SPHINCS_SHAKE_128f)) {
		struct lc_sphincs_shake_128f_sk *_sk = &sk->key.sk_shake_128f;

		memcpy(_sk, src_key, src_key_len);
		sk->sphincs_type = LC_SPHINCS_SHAKE_128f;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sk_set_keytype_fast,
		      struct lc_sphincs_sk *sk)
{
	if (!sk) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_256s) {
		sk->sphincs_type = LC_SPHINCS_SHAKE_256f;
		return 0;
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_256f) {
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_192s) {
		sk->sphincs_type = LC_SPHINCS_SHAKE_192f;
		return 0;
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_192f) {
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_128s) {
		sk->sphincs_type = LC_SPHINCS_SHAKE_128f;
		return 0;
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_128f) {
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sk_set_keytype_small,
		      struct lc_sphincs_sk *sk)
{
	if (!sk) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_256s) {
		return 0;
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_256f) {
		sk->sphincs_type = LC_SPHINCS_SHAKE_256s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_192s) {
		return 0;
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_192f) {
		sk->sphincs_type = LC_SPHINCS_SHAKE_192s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_128s) {
		return 0;
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_128f) {
		sk->sphincs_type = LC_SPHINCS_SHAKE_128s;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_pk_load, struct lc_sphincs_pk *pk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	} else if (src_key_len == lc_sphincs_pk_size(LC_SPHINCS_SHAKE_256s)) {
		struct lc_sphincs_shake_256s_pk *_pk = &pk->key.pk_shake_256s;

		memcpy(_pk, src_key, src_key_len);
		pk->sphincs_type = LC_SPHINCS_SHAKE_256s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
	} else if (src_key_len == lc_sphincs_pk_size(LC_SPHINCS_SHAKE_256f)) {
		struct lc_sphincs_shake_256f_pk *_pk = &pk->key.pk_shake_256f;

		memcpy(_pk, src_key, src_key_len);
		pk->sphincs_type = LC_SPHINCS_SHAKE_256f;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
	} else if (src_key_len == lc_sphincs_pk_size(LC_SPHINCS_SHAKE_192s)) {
		struct lc_sphincs_shake_192s_pk *_pk = &pk->key.pk_shake_192s;

		memcpy(_pk, src_key, src_key_len);
		pk->sphincs_type = LC_SPHINCS_SHAKE_192s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
	} else if (src_key_len == lc_sphincs_pk_size(LC_SPHINCS_SHAKE_192f)) {
		struct lc_sphincs_shake_192f_pk *_pk = &pk->key.pk_shake_192f;

		memcpy(_pk, src_key, src_key_len);
		pk->sphincs_type = LC_SPHINCS_SHAKE_192f;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
	} else if (src_key_len == lc_sphincs_pk_size(LC_SPHINCS_SHAKE_128s)) {
		struct lc_sphincs_shake_128s_pk *_pk = &pk->key.pk_shake_128s;

		memcpy(_pk, src_key, src_key_len);
		pk->sphincs_type = LC_SPHINCS_SHAKE_128s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
	} else if (src_key_len == lc_sphincs_pk_size(LC_SPHINCS_SHAKE_128f)) {
		struct lc_sphincs_shake_128f_pk *_pk = &pk->key.pk_shake_128f;

		memcpy(_pk, src_key, src_key_len);
		pk->sphincs_type = LC_SPHINCS_SHAKE_128f;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_pk_set_keytype_fast,
		      struct lc_sphincs_pk *pk)
{
	if (!pk) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_256s) {
		pk->sphincs_type = LC_SPHINCS_SHAKE_256f;
		return 0;
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_256f) {
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_192s) {
		pk->sphincs_type = LC_SPHINCS_SHAKE_192f;
		return 0;
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_192f) {
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_128s) {
		pk->sphincs_type = LC_SPHINCS_SHAKE_128f;
		return 0;
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_128f) {
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_pk_set_keytype_small,
		      struct lc_sphincs_pk *pk)
{
	if (!pk) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_256s) {
		return 0;
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_256f) {
		pk->sphincs_type = LC_SPHINCS_SHAKE_256s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_192s) {
		return 0;
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_192f) {
		pk->sphincs_type = LC_SPHINCS_SHAKE_192s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_128s) {
		return 0;
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_128f) {
		pk->sphincs_type = LC_SPHINCS_SHAKE_128s;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sig_load, struct lc_sphincs_sig *sig,
		      const uint8_t *src_sig, size_t src_sig_len)
{
	if (!sig || !src_sig || src_sig_len == 0) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	} else if (src_sig_len == lc_sphincs_sig_size(LC_SPHINCS_SHAKE_256s)) {
		struct lc_sphincs_shake_256s_sig *_sig =
			&sig->sig.sig_shake_256s;

		memcpy(_sig, src_sig, src_sig_len);
		sig->sphincs_type = LC_SPHINCS_SHAKE_256s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
	} else if (src_sig_len == lc_sphincs_sig_size(LC_SPHINCS_SHAKE_256f)) {
		struct lc_sphincs_shake_256f_sig *_sig =
			&sig->sig.sig_shake_256f;

		memcpy(_sig, src_sig, src_sig_len);
		sig->sphincs_type = LC_SPHINCS_SHAKE_256f;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
	} else if (src_sig_len == lc_sphincs_sig_size(LC_SPHINCS_SHAKE_192s)) {
		struct lc_sphincs_shake_192s_sig *_sig =
			&sig->sig.sig_shake_192s;

		memcpy(_sig, src_sig, src_sig_len);
		sig->sphincs_type = LC_SPHINCS_SHAKE_192s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
	} else if (src_sig_len == lc_sphincs_sig_size(LC_SPHINCS_SHAKE_192f)) {
		struct lc_sphincs_shake_192f_sig *_sig =
			&sig->sig.sig_shake_192f;

		memcpy(_sig, src_sig, src_sig_len);
		sig->sphincs_type = LC_SPHINCS_SHAKE_192f;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
	} else if (src_sig_len == lc_sphincs_sig_size(LC_SPHINCS_SHAKE_128s)) {
		struct lc_sphincs_shake_128s_sig *_sig =
			&sig->sig.sig_shake_128s;

		memcpy(_sig, src_sig, src_sig_len);
		sig->sphincs_type = LC_SPHINCS_SHAKE_128s;
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
	} else if (src_sig_len == lc_sphincs_sig_size(LC_SPHINCS_SHAKE_128f)) {
		struct lc_sphincs_shake_128f_sig *_sig =
			&sig->sig.sig_shake_128f;

		memcpy(_sig, src_sig, src_sig_len);
		sig->sphincs_type = LC_SPHINCS_SHAKE_128f;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sk_ptr, uint8_t **sphincs_key,
		      size_t *sphincs_key_len, struct lc_sphincs_sk *sk)
{
	if (!sk || !sphincs_key || !sphincs_key_len) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_256s) {
		struct lc_sphincs_shake_256s_sk *_sk = &sk->key.sk_shake_256s;

		*sphincs_key = (uint8_t *)_sk;
		*sphincs_key_len = lc_sphincs_sk_size(sk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_256f) {
		struct lc_sphincs_shake_256f_sk *_sk = &sk->key.sk_shake_256f;

		*sphincs_key = (uint8_t *)_sk;
		*sphincs_key_len = lc_sphincs_sk_size(sk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_192s) {
		struct lc_sphincs_shake_192s_sk *_sk = &sk->key.sk_shake_192s;

		*sphincs_key = (uint8_t *)_sk;
		*sphincs_key_len = lc_sphincs_sk_size(sk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_192f) {
		struct lc_sphincs_shake_192f_sk *_sk = &sk->key.sk_shake_192f;

		*sphincs_key = (uint8_t *)_sk;
		*sphincs_key_len = lc_sphincs_sk_size(sk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_128s) {
		struct lc_sphincs_shake_128s_sk *_sk = &sk->key.sk_shake_128s;

		*sphincs_key = (uint8_t *)_sk;
		*sphincs_key_len = lc_sphincs_sk_size(sk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
	} else if (sk->sphincs_type == LC_SPHINCS_SHAKE_128f) {
		struct lc_sphincs_shake_128f_sk *_sk = &sk->key.sk_shake_128f;

		*sphincs_key = (uint8_t *)_sk;
		*sphincs_key_len = lc_sphincs_sk_size(sk->sphincs_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_pk_ptr, uint8_t **sphincs_key,
		      size_t *sphincs_key_len, struct lc_sphincs_pk *pk)
{
	if (!pk || !sphincs_key || !sphincs_key_len) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_256s) {
		struct lc_sphincs_shake_256s_pk *_pk = &pk->key.pk_shake_256s;

		*sphincs_key = (uint8_t *)_pk;
		*sphincs_key_len = lc_sphincs_pk_size(pk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_256f) {
		struct lc_sphincs_shake_256f_pk *_pk = &pk->key.pk_shake_256f;

		*sphincs_key = (uint8_t *)_pk;
		*sphincs_key_len = lc_sphincs_pk_size(pk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_192s) {
		struct lc_sphincs_shake_192s_pk *_pk = &pk->key.pk_shake_192s;

		*sphincs_key = (uint8_t *)_pk;
		*sphincs_key_len = lc_sphincs_pk_size(pk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_192f) {
		struct lc_sphincs_shake_192f_pk *_pk = &pk->key.pk_shake_192f;

		*sphincs_key = (uint8_t *)_pk;
		*sphincs_key_len = lc_sphincs_pk_size(pk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_128s) {
		struct lc_sphincs_shake_128s_pk *_pk = &pk->key.pk_shake_128s;

		*sphincs_key = (uint8_t *)_pk;
		*sphincs_key_len = lc_sphincs_pk_size(pk->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
	} else if (pk->sphincs_type == LC_SPHINCS_SHAKE_128f) {
		struct lc_sphincs_shake_128f_pk *_pk = &pk->key.pk_shake_128f;

		*sphincs_key = (uint8_t *)_pk;
		*sphincs_key_len = lc_sphincs_pk_size(pk->sphincs_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sphincs_sig_ptr, uint8_t **sphincs_sig,
		      size_t *sphincs_sig_len, struct lc_sphincs_sig *sig)
{
	if (!sig || !sphincs_sig || !sphincs_sig_len) {
		return -EINVAL;
#ifdef LC_SPHINCS_SHAKE_256s_ENABLED
	} else if (sig->sphincs_type == LC_SPHINCS_SHAKE_256s) {
		struct lc_sphincs_shake_256s_sig *_sig =
			&sig->sig.sig_shake_256s;

		*sphincs_sig = (uint8_t *)_sig;
		*sphincs_sig_len = lc_sphincs_sig_size(sig->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_256f_ENABLED
	} else if (sig->sphincs_type == LC_SPHINCS_SHAKE_256f) {
		struct lc_sphincs_shake_256f_sig *_sig =
			&sig->sig.sig_shake_256f;

		*sphincs_sig = (uint8_t *)_sig;
		*sphincs_sig_len = lc_sphincs_sig_size(sig->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192s_ENABLED
	} else if (sig->sphincs_type == LC_SPHINCS_SHAKE_192s) {
		struct lc_sphincs_shake_192s_sig *_sig =
			&sig->sig.sig_shake_192s;

		*sphincs_sig = (uint8_t *)_sig;
		*sphincs_sig_len = lc_sphincs_sig_size(sig->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_192f_ENABLED
	} else if (sig->sphincs_type == LC_SPHINCS_SHAKE_192f) {
		struct lc_sphincs_shake_192f_sig *_sig =
			&sig->sig.sig_shake_192f;

		*sphincs_sig = (uint8_t *)_sig;
		*sphincs_sig_len = lc_sphincs_sig_size(sig->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128s_ENABLED
	} else if (sig->sphincs_type == LC_SPHINCS_SHAKE_128s) {
		struct lc_sphincs_shake_128s_sig *_sig =
			&sig->sig.sig_shake_128s;

		*sphincs_sig = (uint8_t *)_sig;
		*sphincs_sig_len = lc_sphincs_sig_size(sig->sphincs_type);
		return 0;
#endif
#ifdef LC_SPHINCS_SHAKE_128f_ENABLED
	} else if (sig->sphincs_type == LC_SPHINCS_SHAKE_128f) {
		struct lc_sphincs_shake_128f_sig *_sig =
			&sig->sig.sig_shake_128f;

		*sphincs_sig = (uint8_t *)_sig;
		*sphincs_sig_len = lc_sphincs_sig_size(sig->sphincs_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

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
