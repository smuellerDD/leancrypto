/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_internal.h"
#include "lc_hqc.h"
#include "status_algorithms.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(enum lc_hqc_type, lc_hqc_sk_type,
		      const struct lc_hqc_sk *sk)
{
	if (!sk)
		return LC_HQC_UNKNOWN;
	return sk->hqc_type;
}

LC_INTERFACE_FUNCTION(enum lc_hqc_type, lc_hqc_pk_type,
		      const struct lc_hqc_pk *pk)
{
	if (!pk)
		return LC_HQC_UNKNOWN;
	return pk->hqc_type;
}

LC_INTERFACE_FUNCTION(enum lc_hqc_type, lc_hqc_ct_type,
		      const struct lc_hqc_ct *ct)
{
	if (!ct)
		return LC_HQC_UNKNOWN;
	return ct->hqc_type;
}

LC_INTERFACE_FUNCTION(enum lc_hqc_type, lc_hqc_ss_type,
		      const struct lc_hqc_ss *ss)
{
	if (!ss)
		return LC_HQC_UNKNOWN;
	return ss->hqc_type;
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_hqc_sk_size, enum lc_hqc_type hqc_type)
{
	switch (hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		return lc_member_size(struct lc_hqc_sk, key.sk_256);
#else
		return 0;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		return lc_member_size(struct lc_hqc_sk, key.sk_192);
#else
		return 0;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		return lc_member_size(struct lc_hqc_sk, key.sk_128);
#else
		return 0;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_hqc_pk_size, enum lc_hqc_type hqc_type)
{
	switch (hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		return lc_member_size(struct lc_hqc_pk, key.pk_256);
#else
		return 0;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		return lc_member_size(struct lc_hqc_pk, key.pk_192);
#else
		return 0;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		return lc_member_size(struct lc_hqc_pk, key.pk_128);
#else
		return 0;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_hqc_ct_size, enum lc_hqc_type hqc_type)
{
	switch (hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		return lc_member_size(struct lc_hqc_ct, key.ct_256);
#else
		return 0;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		return lc_member_size(struct lc_hqc_ct, key.ct_192);
#else
		return 0;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		return lc_member_size(struct lc_hqc_ct, key.ct_128);
#else
		return 0;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_hqc_ss_size, enum lc_hqc_type hqc_type)
{
	switch (hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		return lc_member_size(struct lc_hqc_ss, key.ss_256);
#else
		return 0;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		return lc_member_size(struct lc_hqc_ss, key.ss_192);
#else
		return 0;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		return lc_member_size(struct lc_hqc_ss, key.ss_128);
#else
		return 0;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_sk_load, struct lc_hqc_sk *sk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_HQC_256_ENABLED
	} else if (src_key_len == lc_hqc_sk_size(LC_HQC_256)) {
		struct lc_hqc_256_sk *_sk = &sk->key.sk_256;

		memcpy(_sk, src_key, src_key_len);
		sk->hqc_type = LC_HQC_256;
		return 0;
#endif
#ifdef LC_HQC_192_ENABLED
	} else if (src_key_len == lc_hqc_sk_size(LC_HQC_192)) {
		struct lc_hqc_192_sk *_sk = &sk->key.sk_192;

		memcpy(_sk, src_key, src_key_len);
		sk->hqc_type = LC_HQC_192;
		return 0;
#endif
#ifdef LC_HQC_128_ENABLED
	} else if (src_key_len == lc_hqc_sk_size(LC_HQC_128)) {
		struct lc_hqc_128_sk *_sk = &sk->key.sk_128;

		memcpy(_sk, src_key, src_key_len);
		sk->hqc_type = LC_HQC_128;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_pk_load, struct lc_hqc_pk *pk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_HQC_256_ENABLED
	} else if (src_key_len == lc_hqc_pk_size(LC_HQC_256)) {
		struct lc_hqc_256_pk *_pk = &pk->key.pk_256;

		memcpy(_pk, src_key, src_key_len);
		pk->hqc_type = LC_HQC_256;
		return 0;
#endif
#ifdef LC_HQC_192_ENABLED
	} else if (src_key_len == lc_hqc_pk_size(LC_HQC_192)) {
		struct lc_hqc_192_pk *_pk = &pk->key.pk_192;

		memcpy(_pk, src_key, src_key_len);
		pk->hqc_type = LC_HQC_192;
		return 0;
#endif
#ifdef LC_HQC_128_ENABLED
	} else if (src_key_len == lc_hqc_pk_size(LC_HQC_128)) {
		struct lc_hqc_128_pk *_pk = &pk->key.pk_128;

		memcpy(_pk, src_key, src_key_len);
		pk->hqc_type = LC_HQC_128;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_ct_load, struct lc_hqc_ct *ct,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!ct || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_HQC_256_ENABLED
	} else if (src_key_len == lc_hqc_ct_size(LC_HQC_256)) {
		struct lc_hqc_256_ct *_ct = &ct->key.ct_256;

		memcpy(_ct, src_key, src_key_len);
		ct->hqc_type = LC_HQC_256;
		return 0;
#endif
#ifdef LC_HQC_192_ENABLED
	} else if (src_key_len == lc_hqc_ct_size(LC_HQC_192)) {
		struct lc_hqc_192_ct *_ct = &ct->key.ct_192;

		memcpy(_ct, src_key, src_key_len);
		ct->hqc_type = LC_HQC_192;
		return 0;
#endif
#ifdef LC_HQC_128_ENABLED
	} else if (src_key_len == lc_hqc_ct_size(LC_HQC_128)) {
		struct lc_hqc_128_ct *_ct = &ct->key.ct_128;

		memcpy(_ct, src_key, src_key_len);
		ct->hqc_type = LC_HQC_128;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_ss_load, struct lc_hqc_ss *ss,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!ss || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_HQC_256_ENABLED
	} else if (src_key_len == lc_hqc_ss_size(LC_HQC_256)) {
		struct lc_hqc_256_ss *_ss = &ss->key.ss_256;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->hqc_type = LC_HQC_256;
		return 0;
#endif
#ifdef LC_HQC_192_ENABLED
	} else if (src_key_len == lc_hqc_ss_size(LC_HQC_192)) {
		struct lc_hqc_192_ss *_ss = &ss->key.ss_192;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->hqc_type = LC_HQC_192;
		return 0;
#endif
#ifdef LC_HQC_128_ENABLED
	} else if (src_key_len == lc_hqc_ss_size(LC_HQC_128)) {
		struct lc_hqc_128_ss *_ss = &ss->key.ss_128;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->hqc_type = LC_HQC_128;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_sk_ptr, uint8_t **hqc_key,
		      size_t *hqc_key_len, struct lc_hqc_sk *sk)
{
	if (!sk || !hqc_key || !hqc_key_len) {
		return -EINVAL;
#ifdef LC_HQC_256_ENABLED
	} else if (sk->hqc_type == LC_HQC_256) {
		struct lc_hqc_256_sk *_sk = &sk->key.sk_256;

		*hqc_key = (uint8_t *)_sk;
		*hqc_key_len = lc_hqc_sk_size(sk->hqc_type);
		return 0;
#endif
#ifdef LC_HQC_192_ENABLED
	} else if (sk->hqc_type == LC_HQC_192) {
		struct lc_hqc_192_sk *_sk = &sk->key.sk_192;

		*hqc_key = (uint8_t *)_sk;
		*hqc_key_len = lc_hqc_sk_size(sk->hqc_type);
		return 0;
#endif
#ifdef LC_HQC_128_ENABLED
	} else if (sk->hqc_type == LC_HQC_128) {
		struct lc_hqc_128_sk *_sk = &sk->key.sk_128;

		*hqc_key = (uint8_t *)_sk;
		*hqc_key_len = lc_hqc_sk_size(sk->hqc_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_pk_ptr, uint8_t **hqc_key,
		      size_t *hqc_key_len, struct lc_hqc_pk *pk)
{
	if (!pk || !hqc_key || !hqc_key_len) {
		return -EINVAL;
#ifdef LC_HQC_256_ENABLED
	} else if (pk->hqc_type == LC_HQC_256) {
		struct lc_hqc_256_pk *_pk = &pk->key.pk_256;

		*hqc_key = (uint8_t *)_pk;
		*hqc_key_len = lc_hqc_pk_size(pk->hqc_type);
		return 0;
#endif
#ifdef LC_HQC_192_ENABLED
	} else if (pk->hqc_type == LC_HQC_192) {
		struct lc_hqc_192_pk *_pk = &pk->key.pk_192;

		*hqc_key = (uint8_t *)_pk;
		*hqc_key_len = lc_hqc_pk_size(pk->hqc_type);
		return 0;
#endif
#ifdef LC_HQC_128_ENABLED
	} else if (pk->hqc_type == LC_HQC_128) {
		struct lc_hqc_128_pk *_pk = &pk->key.pk_128;

		*hqc_key = (uint8_t *)_pk;
		*hqc_key_len = lc_hqc_pk_size(pk->hqc_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_ct_ptr, uint8_t **hqc_ct, size_t *hqc_ct_len,
		      struct lc_hqc_ct *ct)
{
	if (!ct || !hqc_ct || !hqc_ct_len) {
		return -EINVAL;
#ifdef LC_HQC_256_ENABLED
	} else if (ct->hqc_type == LC_HQC_256) {
		struct lc_hqc_256_ct *_ct = &ct->key.ct_256;

		*hqc_ct = (uint8_t *)_ct;
		*hqc_ct_len = lc_hqc_ct_size(ct->hqc_type);
		return 0;
#endif
#ifdef LC_HQC_192_ENABLED
	} else if (ct->hqc_type == LC_HQC_192) {
		struct lc_hqc_192_ct *_ct = &ct->key.ct_192;

		*hqc_ct = (uint8_t *)_ct;
		*hqc_ct_len = lc_hqc_ct_size(ct->hqc_type);
		return 0;
#endif
#ifdef LC_HQC_128_ENABLED
	} else if (ct->hqc_type == LC_HQC_128) {
		struct lc_hqc_128_ct *_ct = &ct->key.ct_128;

		*hqc_ct = (uint8_t *)_ct;
		*hqc_ct_len = lc_hqc_ct_size(ct->hqc_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_ss_ptr, uint8_t **hqc_ss, size_t *hqc_ss_len,
		      struct lc_hqc_ss *ss)
{
	if (!ss || !hqc_ss || !hqc_ss_len) {
		return -EINVAL;
#ifdef LC_HQC_256_ENABLED
	} else if (ss->hqc_type == LC_HQC_256) {
		struct lc_hqc_256_ss *_ss = &ss->key.ss_256;

		*hqc_ss = _ss->ss;
		*hqc_ss_len = lc_hqc_ss_size(ss->hqc_type);
		return 0;
#endif
#ifdef LC_HQC_192_ENABLED
	} else if (ss->hqc_type == LC_HQC_192) {
		struct lc_hqc_192_ss *_ss = &ss->key.ss_192;

		*hqc_ss = _ss->ss;
		*hqc_ss_len = lc_hqc_ss_size(ss->hqc_type);
		return 0;
#endif
#ifdef LC_HQC_128_ENABLED
	} else if (ss->hqc_type == LC_HQC_128) {
		struct lc_hqc_128_ss *_ss = &ss->key.ss_128;

		*hqc_ss = _ss->ss;
		*hqc_ss_len = lc_hqc_ss_size(ss->hqc_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_keypair, struct lc_hqc_pk *pk,
		      struct lc_hqc_sk *sk, struct lc_rng_ctx *rng_ctx,
		      enum lc_hqc_type hqc_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		pk->hqc_type = hqc_type;
		sk->hqc_type = hqc_type;
		return lc_hqc_256_keypair(&pk->key.pk_256, &sk->key.sk_256,
					  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		pk->hqc_type = hqc_type;
		sk->hqc_type = hqc_type;
		return lc_hqc_192_keypair(&pk->key.pk_192, &sk->key.sk_192,
					  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		pk->hqc_type = hqc_type;
		sk->hqc_type = hqc_type;
		return lc_hqc_128_keypair(&pk->key.pk_128, &sk->key.sk_128,
					  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_keypair_from_seed, struct lc_hqc_pk *pk,
		      struct lc_hqc_sk *sk, const uint8_t *seed, size_t seedlen,
		      enum lc_hqc_type hqc_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		pk->hqc_type = hqc_type;
		sk->hqc_type = hqc_type;
		return lc_hqc_256_keypair_from_seed(
			&pk->key.pk_256, &sk->key.sk_256, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		pk->hqc_type = hqc_type;
		sk->hqc_type = hqc_type;
		return lc_hqc_192_keypair_from_seed(
			&pk->key.pk_192, &sk->key.sk_192, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		pk->hqc_type = hqc_type;
		sk->hqc_type = hqc_type;
		return lc_hqc_128_keypair_from_seed(
			&pk->key.pk_128, &sk->key.sk_128, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc, struct lc_hqc_ct *ct,
		      struct lc_hqc_ss *ss, const struct lc_hqc_pk *pk)
{
	if (!ct || !ss || !pk)
		return -EINVAL;

	switch (pk->hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		ct->hqc_type = LC_HQC_256;
		ss->hqc_type = LC_HQC_256;
		return lc_hqc_256_enc(&ct->key.ct_256, &ss->key.ss_256,
				      &pk->key.pk_256);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		ct->hqc_type = LC_HQC_192;
		ss->hqc_type = LC_HQC_192;
		return lc_hqc_192_enc(&ct->key.ct_192, &ss->key.ss_192,
				      &pk->key.pk_192);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		ct->hqc_type = LC_HQC_128;
		ss->hqc_type = LC_HQC_128;
		return lc_hqc_128_enc(&ct->key.ct_128, &ss->key.ss_128,
				      &pk->key.pk_128);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc_kdf, struct lc_hqc_ct *ct, uint8_t *ss,
		      size_t ss_len, const struct lc_hqc_pk *pk)
{
	if (!ct || !pk)
		return -EINVAL;

	switch (pk->hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		ct->hqc_type = LC_HQC_256;
		return lc_hqc_256_enc_kdf(&ct->key.ct_256, ss, ss_len,
					  &pk->key.pk_256);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		ct->hqc_type = LC_HQC_192;
		return lc_hqc_192_enc_kdf(&ct->key.ct_192, ss, ss_len,
					  &pk->key.pk_192);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		ct->hqc_type = LC_HQC_128;
		return lc_hqc_128_enc_kdf(&ct->key.ct_128, ss, ss_len,
					  &pk->key.pk_128);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_dec, struct lc_hqc_ss *ss,
		      const struct lc_hqc_ct *ct, const struct lc_hqc_sk *sk)
{
	if (!ss || !ct || !sk || ct->hqc_type != sk->hqc_type)
		return -EINVAL;

	switch (sk->hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		ss->hqc_type = LC_HQC_256;
		return lc_hqc_256_dec(&ss->key.ss_256, &ct->key.ct_256,
				      &sk->key.sk_256);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		ss->hqc_type = LC_HQC_192;
		return lc_hqc_192_dec(&ss->key.ss_192, &ct->key.ct_192,
				      &sk->key.sk_192);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		ss->hqc_type = LC_HQC_128;
		return lc_hqc_128_dec(&ss->key.ss_128, &ct->key.ct_128,
				      &sk->key.sk_128);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_hqc_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_hqc_ct *ct, const struct lc_hqc_sk *sk)
{
	if (!ct || !sk || ct->hqc_type != sk->hqc_type)
		return -EINVAL;

	switch (sk->hqc_type) {
	case LC_HQC_256:
#ifdef LC_HQC_256_ENABLED
		return lc_hqc_256_dec_kdf(ss, ss_len, &ct->key.ct_256,
					  &sk->key.sk_256);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_192:
#ifdef LC_HQC_192_ENABLED
		return lc_hqc_192_dec_kdf(ss, ss_len, &ct->key.ct_192,
					  &sk->key.sk_192);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_128:
#ifdef LC_HQC_128_ENABLED
		return lc_hqc_128_dec_kdf(ss, ss_len, &ct->key.ct_128,
					  &sk->key.sk_128);
#else
		return -EOPNOTSUPP;
#endif
	case LC_HQC_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(enum lc_alg_status_val, lc_hqc_alg_status,
		      const enum lc_hqc_type hqc_type,
		      const enum lc_hqc_alg_operation operation)
{
	(void)hqc_type;

	switch (operation) {
	case lc_alg_operation_hqc_keygen:
		return lc_alg_status(LC_ALG_STATUS_FIPS |
				     LC_ALG_STATUS_HQC_KEYGEN);
	case lc_alg_operation_hqc_enc:
		return lc_alg_status(LC_ALG_STATUS_FIPS |
				     LC_ALG_STATUS_HQC_ENC);
	case lc_alg_operation_hqc_dec:
		return lc_alg_status(LC_ALG_STATUS_FIPS |
				     LC_ALG_STATUS_HQC_DEC);
	case lc_alg_operation_hqc_enc_kdf:
		return lc_alg_status(LC_ALG_STATUS_FIPS |
				     LC_ALG_STATUS_HQC_ENC);
	case lc_alg_operation_hqc_dec_kdf:
		return lc_alg_status(LC_ALG_STATUS_FIPS |
				     LC_ALG_STATUS_HQC_DEC);
	case lc_alg_operation_hqc_unknown:
	default:
		return lc_alg_status_unknown;
	}
	return lc_alg_status_unknown;
}
