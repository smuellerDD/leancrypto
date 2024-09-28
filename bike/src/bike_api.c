/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers.h"
#include "lc_bike.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(enum lc_bike_type, lc_bike_sk_type,
		      const struct lc_bike_sk *sk)
{
	if (!sk)
		return LC_BIKE_UNKNOWN;
	return sk->bike_type;
}

LC_INTERFACE_FUNCTION(enum lc_bike_type, lc_bike_pk_type,
		      const struct lc_bike_pk *pk)
{
	if (!pk)
		return LC_BIKE_UNKNOWN;
	return pk->bike_type;
}

LC_INTERFACE_FUNCTION(enum lc_bike_type, lc_bike_ct_type,
		      const struct lc_bike_ct *ct)
{
	if (!ct)
		return LC_BIKE_UNKNOWN;
	return ct->bike_type;
}

LC_INTERFACE_FUNCTION(enum lc_bike_type, lc_bike_ss_type,
		      const struct lc_bike_ss *ss)
{
	if (!ss)
		return LC_BIKE_UNKNOWN;
	return ss->bike_type;
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_bike_sk_size,
		      enum lc_bike_type bike_type)
{
	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_member_size(struct lc_bike_sk, key.sk_5);
#else
		return 0;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_member_size(struct lc_bike_sk, key.sk_3);
#else
		return 0;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_member_size(struct lc_bike_sk, key.sk_1);
#else
		return 0;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_bike_pk_size,
		      enum lc_bike_type bike_type)
{
	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_member_size(struct lc_bike_pk, key.pk_5);
#else
		return 0;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_member_size(struct lc_bike_pk, key.pk_3);
#else
		return 0;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_member_size(struct lc_bike_pk, key.pk_1);
#else
		return 0;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_bike_ct_size,
		      enum lc_bike_type bike_type)
{
	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_member_size(struct lc_bike_ct, key.ct_5);
#else
		return 0;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_member_size(struct lc_bike_ct, key.ct_3);
#else
		return 0;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_member_size(struct lc_bike_ct, key.ct_1);
#else
		return 0;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_bike_ss_size,
		      enum lc_bike_type bike_type)
{
	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_member_size(struct lc_bike_ss, key.ss_5);
#else
		return 0;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_member_size(struct lc_bike_ss, key.ss_3);
#else
		return 0;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_member_size(struct lc_bike_ss, key.ss_1);
#else
		return 0;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_sk_load, struct lc_bike_sk *sk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (src_key_len == lc_bike_sk_size(LC_BIKE_5)) {
		struct lc_bike_5_sk *_sk = &sk->key.sk_5;

		memcpy(_sk, src_key, src_key_len);
		sk->bike_type = LC_BIKE_5;
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (src_key_len == lc_bike_sk_size(LC_BIKE_3)) {
		struct lc_bike_3_sk *_sk = &sk->key.sk_3;

		memcpy(_sk, src_key, src_key_len);
		sk->bike_type = LC_BIKE_3;
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (src_key_len == lc_bike_sk_size(LC_BIKE_1)) {
		struct lc_bike_1_sk *_sk = &sk->key.sk_1;

		memcpy(_sk, src_key, src_key_len);
		sk->bike_type = LC_BIKE_1;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_pk_load, struct lc_bike_pk *pk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (src_key_len == lc_bike_pk_size(LC_BIKE_5)) {
		struct lc_bike_5_pk *_pk = &pk->key.pk_5;

		memcpy(_pk, src_key, src_key_len);
		pk->bike_type = LC_BIKE_5;
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (src_key_len == lc_bike_pk_size(LC_BIKE_3)) {
		struct lc_bike_3_pk *_pk = &pk->key.pk_3;

		memcpy(_pk, src_key, src_key_len);
		pk->bike_type = LC_BIKE_3;
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (src_key_len == lc_bike_pk_size(LC_BIKE_1)) {
		struct lc_bike_1_pk *_pk = &pk->key.pk_1;

		memcpy(_pk, src_key, src_key_len);
		pk->bike_type = LC_BIKE_1;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_ct_load, struct lc_bike_ct *ct,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!ct || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (src_key_len == lc_bike_ct_size(LC_BIKE_5)) {
		struct lc_bike_5_ct *_ct = &ct->key.ct_5;

		memcpy(_ct, src_key, src_key_len);
		ct->bike_type = LC_BIKE_5;
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (src_key_len == lc_bike_ct_size(LC_BIKE_3)) {
		struct lc_bike_3_ct *_ct = &ct->key.ct_3;

		memcpy(_ct, src_key, src_key_len);
		ct->bike_type = LC_BIKE_3;
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (src_key_len == lc_bike_ct_size(LC_BIKE_1)) {
		struct lc_bike_1_ct *_ct = &ct->key.ct_1;

		memcpy(_ct, src_key, src_key_len);
		ct->bike_type = LC_BIKE_1;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_ss_load, struct lc_bike_ss *ss,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!ss || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (src_key_len == lc_bike_ss_size(LC_BIKE_5)) {
		struct lc_bike_5_ss *_ss = &ss->key.ss_5;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->bike_type = LC_BIKE_5;
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (src_key_len == lc_bike_ss_size(LC_BIKE_3)) {
		struct lc_bike_3_ss *_ss = &ss->key.ss_3;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->bike_type = LC_BIKE_3;
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (src_key_len == lc_bike_ss_size(LC_BIKE_1)) {
		struct lc_bike_1_ss *_ss = &ss->key.ss_1;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->bike_type = LC_BIKE_1;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_sk_ptr, uint8_t **bike_key,
		      size_t *bike_key_len, struct lc_bike_sk *sk)
{
	if (!sk || !bike_key || !bike_key_len) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (sk->bike_type == LC_BIKE_5) {
		struct lc_bike_5_sk *_sk = &sk->key.sk_5;

		*bike_key = (uint8_t *)_sk;
		*bike_key_len = lc_bike_sk_size(sk->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (sk->bike_type == LC_BIKE_3) {
		struct lc_bike_3_sk *_sk = &sk->key.sk_3;

		*bike_key = (uint8_t *)_sk;
		*bike_key_len = lc_bike_sk_size(sk->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (sk->bike_type == LC_BIKE_1) {
		struct lc_bike_1_sk *_sk = &sk->key.sk_1;

		*bike_key = (uint8_t *)_sk;
		*bike_key_len = lc_bike_sk_size(sk->bike_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_pk_ptr, uint8_t **bike_key,
		      size_t *bike_key_len, struct lc_bike_pk *pk)
{
	if (!pk || !bike_key || !bike_key_len) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (pk->bike_type == LC_BIKE_5) {
		struct lc_bike_5_pk *_pk = &pk->key.pk_5;

		*bike_key = (uint8_t *)_pk;
		*bike_key_len = lc_bike_pk_size(pk->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (pk->bike_type == LC_BIKE_3) {
		struct lc_bike_3_pk *_pk = &pk->key.pk_3;

		*bike_key = (uint8_t *)_pk;
		*bike_key_len = lc_bike_pk_size(pk->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (pk->bike_type == LC_BIKE_1) {
		struct lc_bike_1_pk *_pk = &pk->key.pk_1;

		*bike_key = (uint8_t *)_pk;
		*bike_key_len = lc_bike_pk_size(pk->bike_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_ct_ptr, uint8_t **bike_ct,
		      size_t *bike_ct_len, struct lc_bike_ct *ct)
{
	if (!ct || !bike_ct || !bike_ct_len) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (ct->bike_type == LC_BIKE_5) {
		struct lc_bike_5_ct *_ct = &ct->key.ct_5;

		*bike_ct = (uint8_t *)_ct;
		*bike_ct_len = lc_bike_ct_size(ct->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (ct->bike_type == LC_BIKE_3) {
		struct lc_bike_3_ct *_ct = &ct->key.ct_3;

		*bike_ct = (uint8_t *)_ct;
		*bike_ct_len = lc_bike_ct_size(ct->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (ct->bike_type == LC_BIKE_1) {
		struct lc_bike_1_ct *_ct = &ct->key.ct_1;

		*bike_ct = (uint8_t *)_ct;
		*bike_ct_len = lc_bike_ct_size(ct->bike_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_ss_ptr, uint8_t **bike_ss,
		      size_t *bike_ss_len, struct lc_bike_ss *ss)
{
	if (!ss || !bike_ss || !bike_ss_len) {
		return -EINVAL;
#ifdef LC_BIKE_5_ENABLED
	} else if (ss->bike_type == LC_BIKE_5) {
		struct lc_bike_5_ss *_ss = &ss->key.ss_5;

		*bike_ss = _ss->ss;
		*bike_ss_len = lc_bike_ss_size(ss->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_3_ENABLED
	} else if (ss->bike_type == LC_BIKE_3) {
		struct lc_bike_3_ss *_ss = &ss->key.ss_3;

		*bike_ss = _ss->ss;
		*bike_ss_len = lc_bike_ss_size(ss->bike_type);
		return 0;
#endif
#ifdef LC_BIKE_1_ENABLED
	} else if (ss->bike_type == LC_BIKE_1) {
		struct lc_bike_1_ss *_ss = &ss->key.ss_1;

		*bike_ss = _ss->ss;
		*bike_ss_len = lc_bike_ss_size(ss->bike_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_keypair, struct lc_bike_pk *pk,
		      struct lc_bike_sk *sk, struct lc_rng_ctx *rng_ctx,
		      enum lc_bike_type bike_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_5_keypair(&pk->key.pk_5, &sk->key.sk_5, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_3_keypair(&pk->key.pk_3, &sk->key.sk_3, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_1_keypair(&pk->key.pk_1, &sk->key.sk_1, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_keypair_from_seed, struct lc_bike_pk *pk,
		      struct lc_bike_sk *sk, const uint8_t *seed,
		      size_t seedlen, enum lc_bike_type bike_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_5_keypair_from_seed(&pk->key.pk_5, &sk->key.sk_5,
						   seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_3_keypair_from_seed(&pk->key.pk_3, &sk->key.sk_3,
						   seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		pk->bike_type = bike_type;
		sk->bike_type = bike_type;
		return lc_bike_1_keypair_from_seed(&pk->key.pk_1, &sk->key.sk_1,
						   seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_enc, struct lc_bike_ct *ct,
		      struct lc_bike_ss *ss, const struct lc_bike_pk *pk)
{
	if (!ct || !ss || !pk)
		return -EINVAL;

	switch (pk->bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		ct->bike_type = LC_BIKE_5;
		ss->bike_type = LC_BIKE_5;
		return lc_bike_5_enc(&ct->key.ct_5, &ss->key.ss_5,
				     &pk->key.pk_5);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		ct->bike_type = LC_BIKE_3;
		ss->bike_type = LC_BIKE_3;
		return lc_bike_3_enc(&ct->key.ct_3, &ss->key.ss_3,
				     &pk->key.pk_3);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		ct->bike_type = LC_BIKE_1;
		ss->bike_type = LC_BIKE_1;
		return lc_bike_1_enc(&ct->key.ct_1, &ss->key.ss_1,
				     &pk->key.pk_1);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_enc_kdf, struct lc_bike_ct *ct, uint8_t *ss,
		      size_t ss_len, const struct lc_bike_pk *pk)
{
	if (!ct || !pk)
		return -EINVAL;

	switch (pk->bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		ct->bike_type = LC_BIKE_5;
		return lc_bike_5_enc_kdf(&ct->key.ct_5, ss, ss_len,
					 &pk->key.pk_5);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		ct->bike_type = LC_BIKE_3;
		return lc_bike_3_enc_kdf(&ct->key.ct_3, ss, ss_len,
					 &pk->key.pk_3);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		ct->bike_type = LC_BIKE_1;
		return lc_bike_1_enc_kdf(&ct->key.ct_1, ss, ss_len,
					 &pk->key.pk_1);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_dec, struct lc_bike_ss *ss,
		      const struct lc_bike_ct *ct, const struct lc_bike_sk *sk)
{
	if (!ss || !ct || !sk || ct->bike_type != sk->bike_type)
		return -EINVAL;

	switch (sk->bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		ss->bike_type = LC_BIKE_5;
		return lc_bike_5_dec(&ss->key.ss_5, &ct->key.ct_5,
				     &sk->key.sk_5);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		ss->bike_type = LC_BIKE_3;
		return lc_bike_3_dec(&ss->key.ss_3, &ct->key.ct_3,
				     &sk->key.sk_3);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		ss->bike_type = LC_BIKE_1;
		return lc_bike_1_dec(&ss->key.ss_1, &ct->key.ct_1,
				     &sk->key.sk_1);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_bike_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_bike_ct *ct, const struct lc_bike_sk *sk)
{
	if (!ct || !sk || ct->bike_type != sk->bike_type)
		return -EINVAL;

	switch (sk->bike_type) {
	case LC_BIKE_5:
#ifdef LC_BIKE_5_ENABLED
		return lc_bike_5_dec_kdf(ss, ss_len, &ct->key.ct_5,
					 &sk->key.sk_5);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_3:
#ifdef LC_BIKE_3_ENABLED
		return lc_bike_3_dec_kdf(ss, ss_len, &ct->key.ct_3,
					 &sk->key.sk_3);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_1:
#ifdef LC_BIKE_1_ENABLED
		return lc_bike_1_dec_kdf(ss, ss_len, &ct->key.ct_1,
					 &sk->key.sk_1);
#else
		return -EOPNOTSUPP;
#endif
	case LC_BIKE_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
