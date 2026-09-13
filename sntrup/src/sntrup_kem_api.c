/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#include "lc_sntrup.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(enum lc_sntrup_type, lc_sntrup_sk_type,
		      const struct lc_sntrup_sk *sk)
{
	if (!sk)
		return LC_SNTRUP_UNKNOWN;
	return sk->sntrup_type;
}

LC_INTERFACE_FUNCTION(enum lc_sntrup_type, lc_sntrup_pk_type,
		      const struct lc_sntrup_pk *pk)
{
	if (!pk)
		return LC_SNTRUP_UNKNOWN;
	return pk->sntrup_type;
}

LC_INTERFACE_FUNCTION(enum lc_sntrup_type, lc_sntrup_ct_type,
		      const struct lc_sntrup_ct *ct)
{
	if (!ct)
		return LC_SNTRUP_UNKNOWN;
	return ct->sntrup_type;
}

LC_INTERFACE_FUNCTION(enum lc_sntrup_type, lc_sntrup_ss_type,
		      const struct lc_sntrup_ss *ss)
{
	if (!ss)
		return LC_SNTRUP_UNKNOWN;
	return ss->sntrup_type;
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_sntrup_sk_size,
		      enum lc_sntrup_type sntrup_type)
{
	switch (sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		return lc_member_size(struct lc_sntrup_sk, key.sk_sntrup_1277);
#else
		return 0;
#endif
	case LC_SNTRUP_1013:
#ifdef LC_SNTRUP_1013_ENABLED
		return lc_member_size(struct lc_sntrup_sk, key.sk_sntrup_1013);
#else
		return 0;
#endif
	case LC_SNTRUP_953:
#ifdef LC_SNTRUP_953_ENABLED
		return lc_member_size(struct lc_sntrup_sk, key.sk_sntrup_953);
#else
		return 0;
#endif
	case LC_SNTRUP_857:
#ifdef LC_SNTRUP_857_ENABLED
		return lc_member_size(struct lc_sntrup_sk, key.sk_sntrup_857);
#else
		return 0;
#endif
	case LC_SNTRUP_761:
#ifdef LC_SNTRUP_761_ENABLED
		return lc_member_size(struct lc_sntrup_sk, key.sk_sntrup_761);
#else
		return 0;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_sntrup_pk_size,
		      enum lc_sntrup_type sntrup_type)
{
	switch (sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		return lc_member_size(struct lc_sntrup_pk, key.pk_sntrup_1277);
#else
		return 0;
#endif
	case LC_SNTRUP_1013:
#ifdef LC_SNTRUP_1013_ENABLED
		return lc_member_size(struct lc_sntrup_pk, key.pk_sntrup_1013);
#else
		return 0;
#endif
	case LC_SNTRUP_953:
#ifdef LC_SNTRUP_953_ENABLED
		return lc_member_size(struct lc_sntrup_pk, key.pk_sntrup_953);
#else
		return 0;
#endif
	case LC_SNTRUP_857:
#ifdef LC_SNTRUP_857_ENABLED
		return lc_member_size(struct lc_sntrup_pk, key.pk_sntrup_857);
#else
		return 0;
#endif
	case LC_SNTRUP_761:
#ifdef LC_SNTRUP_761_ENABLED
		return lc_member_size(struct lc_sntrup_pk, key.pk_sntrup_761);
#else
		return 0;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_sntrup_ct_size,
		      enum lc_sntrup_type sntrup_type)
{
	switch (sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		return lc_member_size(struct lc_sntrup_ct, key.ct_sntrup_1277);
#else
		return 0;
#endif
	case LC_SNTRUP_1013:
#ifdef LC_SNTRUP_1013_ENABLED
		return lc_member_size(struct lc_sntrup_ct, key.ct_sntrup_1013);
#else
		return 0;
#endif
	case LC_SNTRUP_953:
#ifdef LC_SNTRUP_953_ENABLED
		return lc_member_size(struct lc_sntrup_ct, key.ct_sntrup_953);
#else
		return 0;
#endif
	case LC_SNTRUP_857:
#ifdef LC_SNTRUP_857_ENABLED
		return lc_member_size(struct lc_sntrup_ct, key.ct_sntrup_857);
#else
		return 0;
#endif
	case LC_SNTRUP_761:
#ifdef LC_SNTRUP_761_ENABLED
		return lc_member_size(struct lc_sntrup_ct, key.ct_sntrup_761);
#else
		return 0;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_sntrup_ss_size,
		      enum lc_sntrup_type sntrup_type)
{
	switch (sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		return lc_member_size(struct lc_sntrup_ss, key.ss_sntrup_1277);
#else
		return 0;
#endif
	case LC_SNTRUP_1013:
#ifdef LC_SNTRUP_1013_ENABLED
		return lc_member_size(struct lc_sntrup_ss, key.ss_sntrup_1013);
#else
		return 0;
#endif
	case LC_SNTRUP_953:
#ifdef LC_SNTRUP_953_ENABLED
		return lc_member_size(struct lc_sntrup_ss, key.ss_sntrup_953);
#else
		return 0;
#endif
	case LC_SNTRUP_857:
#ifdef LC_SNTRUP_857_ENABLED
		return lc_member_size(struct lc_sntrup_ss, key.ss_sntrup_857);
#else
		return 0;
#endif
	case LC_SNTRUP_761:
#ifdef LC_SNTRUP_761_ENABLED
		return lc_member_size(struct lc_sntrup_ss, key.ss_sntrup_761);
#else
		return 0;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_sk_load, struct lc_sntrup_sk *sk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_SNTRUP_1277_ENABLED
	} else if (src_key_len == lc_sntrup_sk_size(LC_SNTRUP_1277)) {
		struct lc_sntrup_1277_sk *_sk = &sk->key.sk_sntrup_1277;

		memcpy(_sk, src_key, src_key_len);
		sk->sntrup_type = LC_SNTRUP_1277;
		return 0;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
	} else if (src_key_len == lc_sntrup_sk_size(LC_SNTRUP_1013)) {
		struct lc_sntrup_1013_sk *_sk = &sk->key.sk_sntrup_1013;

		memcpy(_sk, src_key, src_key_len);
		sk->sntrup_type = LC_SNTRUP_1013;
		return 0;
#endif
#ifdef LC_SNTRUP_953_ENABLED
	} else if (src_key_len == lc_sntrup_sk_size(LC_SNTRUP_953)) {
		struct lc_sntrup_953_sk *_sk = &sk->key.sk_sntrup_953;

		memcpy(_sk, src_key, src_key_len);
		sk->sntrup_type = LC_SNTRUP_953;
		return 0;
#endif
#ifdef LC_SNTRUP_857_ENABLED
	} else if (src_key_len == lc_sntrup_sk_size(LC_SNTRUP_857)) {
		struct lc_sntrup_857_sk *_sk = &sk->key.sk_sntrup_857;

		memcpy(_sk, src_key, src_key_len);
		sk->sntrup_type = LC_SNTRUP_857;
		return 0;
#endif
#ifdef LC_SNTRUP_761_ENABLED
	} else if (src_key_len == lc_sntrup_sk_size(LC_SNTRUP_761)) {
		struct lc_sntrup_761_sk *_sk = &sk->key.sk_sntrup_761;

		memcpy(_sk, src_key, src_key_len);
		sk->sntrup_type = LC_SNTRUP_761;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_pk_load, struct lc_sntrup_pk *pk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_SNTRUP_1277_ENABLED
	} else if (src_key_len == lc_sntrup_pk_size(LC_SNTRUP_1277)) {
		struct lc_sntrup_1277_pk *_pk = &pk->key.pk_sntrup_1277;

		memcpy(_pk, src_key, src_key_len);
		pk->sntrup_type = LC_SNTRUP_1277;
		return 0;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
	} else if (src_key_len == lc_sntrup_pk_size(LC_SNTRUP_1013)) {
		struct lc_sntrup_1013_pk *_pk = &pk->key.pk_sntrup_1013;

		memcpy(_pk, src_key, src_key_len);
		pk->sntrup_type = LC_SNTRUP_1013;
		return 0;
#endif
#ifdef LC_SNTRUP_953_ENABLED
	} else if (src_key_len == lc_sntrup_pk_size(LC_SNTRUP_953)) {
		struct lc_sntrup_953_pk *_pk = &pk->key.pk_sntrup_953;

		memcpy(_pk, src_key, src_key_len);
		pk->sntrup_type = LC_SNTRUP_953;
		return 0;
#endif
#ifdef LC_SNTRUP_857_ENABLED
	} else if (src_key_len == lc_sntrup_pk_size(LC_SNTRUP_857)) {
		struct lc_sntrup_857_pk *_pk = &pk->key.pk_sntrup_857;

		memcpy(_pk, src_key, src_key_len);
		pk->sntrup_type = LC_SNTRUP_857;
		return 0;
#endif
#ifdef LC_SNTRUP_761_ENABLED
	} else if (src_key_len == lc_sntrup_pk_size(LC_SNTRUP_761)) {
		struct lc_sntrup_761_pk *_pk = &pk->key.pk_sntrup_761;

		memcpy(_pk, src_key, src_key_len);
		pk->sntrup_type = LC_SNTRUP_761;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_ct_load, struct lc_sntrup_ct *ct,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!ct || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_SNTRUP_1277_ENABLED
	} else if (src_key_len == lc_sntrup_ct_size(LC_SNTRUP_1277)) {
		struct lc_sntrup_1277_ct *_ct = &ct->key.ct_sntrup_1277;

		memcpy(_ct, src_key, src_key_len);
		ct->sntrup_type = LC_SNTRUP_1277;
		return 0;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
	} else if (src_key_len == lc_sntrup_ct_size(LC_SNTRUP_1013)) {
		struct lc_sntrup_1013_ct *_ct = &ct->key.ct_sntrup_1013;

		memcpy(_ct, src_key, src_key_len);
		ct->sntrup_type = LC_SNTRUP_1013;
		return 0;
#endif
#ifdef LC_SNTRUP_953_ENABLED
	} else if (src_key_len == lc_sntrup_ct_size(LC_SNTRUP_953)) {
		struct lc_sntrup_953_ct *_ct = &ct->key.ct_sntrup_953;

		memcpy(_ct, src_key, src_key_len);
		ct->sntrup_type = LC_SNTRUP_953;
		return 0;
#endif
#ifdef LC_SNTRUP_857_ENABLED
	} else if (src_key_len == lc_sntrup_ct_size(LC_SNTRUP_857)) {
		struct lc_sntrup_857_ct *_ct = &ct->key.ct_sntrup_857;

		memcpy(_ct, src_key, src_key_len);
		ct->sntrup_type = LC_SNTRUP_857;
		return 0;
#endif
#ifdef LC_SNTRUP_761_ENABLED
	} else if (src_key_len == lc_sntrup_ct_size(LC_SNTRUP_761)) {
		struct lc_sntrup_761_ct *_ct = &ct->key.ct_sntrup_761;

		memcpy(_ct, src_key, src_key_len);
		ct->sntrup_type = LC_SNTRUP_761;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_ss_load, struct lc_sntrup_ss *ss,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!ss || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_SNTRUP_1277_ENABLED
	} else if (src_key_len == lc_sntrup_ss_size(LC_SNTRUP_1277)) {
		struct lc_sntrup_1277_ss *_ss = &ss->key.ss_sntrup_1277;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->sntrup_type = LC_SNTRUP_1277;
		return 0;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
	} else if (src_key_len == lc_sntrup_ss_size(LC_SNTRUP_1013)) {
		struct lc_sntrup_1013_ss *_ss = &ss->key.ss_sntrup_1013;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->sntrup_type = LC_SNTRUP_1013;
		return 0;
#endif
#ifdef LC_SNTRUP_953_ENABLED
	} else if (src_key_len == lc_sntrup_ss_size(LC_SNTRUP_953)) {
		struct lc_sntrup_953_ss *_ss = &ss->key.ss_sntrup_953;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->sntrup_type = LC_SNTRUP_953;
		return 0;
#endif
#ifdef LC_SNTRUP_857_ENABLED
	} else if (src_key_len == lc_sntrup_ss_size(LC_SNTRUP_857)) {
		struct lc_sntrup_857_ss *_ss = &ss->key.ss_sntrup_857;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->sntrup_type = LC_SNTRUP_857;
		return 0;
#endif
#ifdef LC_SNTRUP_761_ENABLED
	} else if (src_key_len == lc_sntrup_ss_size(LC_SNTRUP_761)) {
		struct lc_sntrup_761_ss *_ss = &ss->key.ss_sntrup_761;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->sntrup_type = LC_SNTRUP_761;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_sk_ptr, uint8_t **sntrup_key,
		      size_t *sntrup_key_len, struct lc_sntrup_sk *sk)
{
	if (!sk || !sntrup_key || !sntrup_key_len) {
		return -EINVAL;
#ifdef LC_SNTRUP_1277_ENABLED
	} else if (sk->sntrup_type == LC_SNTRUP_1277) {
		struct lc_sntrup_1277_sk *_sk = &sk->key.sk_sntrup_1277;

		*sntrup_key = (uint8_t *)_sk;
		*sntrup_key_len = lc_sntrup_sk_size(sk->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
	} else if (sk->sntrup_type == LC_SNTRUP_1013) {
		struct lc_sntrup_1013_sk *_sk = &sk->key.sk_sntrup_1013;

		*sntrup_key = (uint8_t *)_sk;
		*sntrup_key_len = lc_sntrup_sk_size(sk->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_953_ENABLED
	} else if (sk->sntrup_type == LC_SNTRUP_953) {
		struct lc_sntrup_953_sk *_sk = &sk->key.sk_sntrup_953;

		*sntrup_key = (uint8_t *)_sk;
		*sntrup_key_len = lc_sntrup_sk_size(sk->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_857_ENABLED
	} else if (sk->sntrup_type == LC_SNTRUP_857) {
		struct lc_sntrup_857_sk *_sk = &sk->key.sk_sntrup_857;

		*sntrup_key = (uint8_t *)_sk;
		*sntrup_key_len = lc_sntrup_sk_size(sk->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_761_ENABLED
	} else if (sk->sntrup_type == LC_SNTRUP_761) {
		struct lc_sntrup_761_sk *_sk = &sk->key.sk_sntrup_761;

		*sntrup_key = (uint8_t *)_sk;
		*sntrup_key_len = lc_sntrup_sk_size(sk->sntrup_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_pk_ptr, uint8_t **sntrup_key,
		      size_t *sntrup_key_len, struct lc_sntrup_pk *pk)
{
	if (!pk || !sntrup_key || !sntrup_key_len) {
		return -EINVAL;
#ifdef LC_SNTRUP_1277_ENABLED
	} else if (pk->sntrup_type == LC_SNTRUP_1277) {
		struct lc_sntrup_1277_pk *_pk = &pk->key.pk_sntrup_1277;

		*sntrup_key = (uint8_t *)_pk;
		*sntrup_key_len = lc_sntrup_pk_size(pk->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
	} else if (pk->sntrup_type == LC_SNTRUP_1013) {
		struct lc_sntrup_1013_pk *_pk = &pk->key.pk_sntrup_1013;

		*sntrup_key = (uint8_t *)_pk;
		*sntrup_key_len = lc_sntrup_pk_size(pk->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_953_ENABLED
	} else if (pk->sntrup_type == LC_SNTRUP_953) {
		struct lc_sntrup_953_pk *_pk = &pk->key.pk_sntrup_953;

		*sntrup_key = (uint8_t *)_pk;
		*sntrup_key_len = lc_sntrup_pk_size(pk->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_857_ENABLED
	} else if (pk->sntrup_type == LC_SNTRUP_857) {
		struct lc_sntrup_857_pk *_pk = &pk->key.pk_sntrup_857;

		*sntrup_key = (uint8_t *)_pk;
		*sntrup_key_len = lc_sntrup_pk_size(pk->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_761_ENABLED
	} else if (pk->sntrup_type == LC_SNTRUP_761) {
		struct lc_sntrup_761_pk *_pk = &pk->key.pk_sntrup_761;

		*sntrup_key = (uint8_t *)_pk;
		*sntrup_key_len = lc_sntrup_pk_size(pk->sntrup_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_ct_ptr, uint8_t **sntrup_ct,
		      size_t *sntrup_ct_len, struct lc_sntrup_ct *ct)
{
	if (!ct || !sntrup_ct || !sntrup_ct_len) {
		return -EINVAL;
#ifdef LC_SNTRUP_1277_ENABLED
	} else if (ct->sntrup_type == LC_SNTRUP_1277) {
		struct lc_sntrup_1277_ct *_ct = &ct->key.ct_sntrup_1277;

		*sntrup_ct = (uint8_t *)_ct;
		*sntrup_ct_len = lc_sntrup_ct_size(ct->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
	} else if (ct->sntrup_type == LC_SNTRUP_1013) {
		struct lc_sntrup_1013_ct *_ct = &ct->key.ct_sntrup_1013;

		*sntrup_ct = (uint8_t *)_ct;
		*sntrup_ct_len = lc_sntrup_ct_size(ct->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_953_ENABLED
	} else if (ct->sntrup_type == LC_SNTRUP_953) {
		struct lc_sntrup_953_ct *_ct = &ct->key.ct_sntrup_953;

		*sntrup_ct = (uint8_t *)_ct;
		*sntrup_ct_len = lc_sntrup_ct_size(ct->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_857_ENABLED
	} else if (ct->sntrup_type == LC_SNTRUP_857) {
		struct lc_sntrup_857_ct *_ct = &ct->key.ct_sntrup_857;

		*sntrup_ct = (uint8_t *)_ct;
		*sntrup_ct_len = lc_sntrup_ct_size(ct->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_761_ENABLED
	} else if (ct->sntrup_type == LC_SNTRUP_761) {
		struct lc_sntrup_761_ct *_ct = &ct->key.ct_sntrup_761;

		*sntrup_ct = (uint8_t *)_ct;
		*sntrup_ct_len = lc_sntrup_ct_size(ct->sntrup_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_ss_ptr, uint8_t **sntrup_ss,
		      size_t *sntrup_ss_len, struct lc_sntrup_ss *ss)
{
	if (!ss || !sntrup_ss || !sntrup_ss_len) {
		return -EINVAL;
#ifdef LC_SNTRUP_1277_ENABLED
	} else if (ss->sntrup_type == LC_SNTRUP_1277) {
		struct lc_sntrup_1277_ss *_ss = &ss->key.ss_sntrup_1277;

		*sntrup_ss = _ss->ss;
		*sntrup_ss_len = lc_sntrup_ss_size(ss->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_1013_ENABLED
	} else if (ss->sntrup_type == LC_SNTRUP_1013) {
		struct lc_sntrup_1013_ss *_ss = &ss->key.ss_sntrup_1013;

		*sntrup_ss = _ss->ss;
		*sntrup_ss_len = lc_sntrup_ss_size(ss->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_953_ENABLED
	} else if (ss->sntrup_type == LC_SNTRUP_953) {
		struct lc_sntrup_953_ss *_ss = &ss->key.ss_sntrup_953;

		*sntrup_ss = _ss->ss;
		*sntrup_ss_len = lc_sntrup_ss_size(ss->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_857_ENABLED
	} else if (ss->sntrup_type == LC_SNTRUP_857) {
		struct lc_sntrup_857_ss *_ss = &ss->key.ss_sntrup_857;

		*sntrup_ss = _ss->ss;
		*sntrup_ss_len = lc_sntrup_ss_size(ss->sntrup_type);
		return 0;
#endif
#ifdef LC_SNTRUP_761_ENABLED
	} else if (ss->sntrup_type == LC_SNTRUP_761) {
		struct lc_sntrup_761_ss *_ss = &ss->key.ss_sntrup_761;

		*sntrup_ss = _ss->ss;
		*sntrup_ss_len = lc_sntrup_ss_size(ss->sntrup_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_keypair, struct lc_sntrup_pk *pk,
		      struct lc_sntrup_sk *sk, struct lc_rng_ctx *rng_ctx,
		      enum lc_sntrup_type sntrup_type)
{
	if (!pk || !sk || !rng_ctx)
		return -EINVAL;

	switch (sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		pk->sntrup_type = sntrup_type;
		sk->sntrup_type = sntrup_type;
		return lc_sntrup_1277_kem_keypair(&pk->key.pk_sntrup_1277,
						  &sk->key.sk_sntrup_1277,
						  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_1013:
#ifdef LC_SNTRUP_1013_ENABLED
		pk->sntrup_type = sntrup_type;
		sk->sntrup_type = sntrup_type;
		return lc_sntrup_1013_kem_keypair(&pk->key.pk_sntrup_1013,
						  &sk->key.sk_sntrup_1013,
						  rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_953:
#ifdef LC_SNTRUP_953_ENABLED
		pk->sntrup_type = sntrup_type;
		sk->sntrup_type = sntrup_type;
		return lc_sntrup_953_kem_keypair(&pk->key.pk_sntrup_953,
						 &sk->key.sk_sntrup_953,
						 rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_857:
#ifdef LC_SNTRUP_857_ENABLED
		pk->sntrup_type = sntrup_type;
		sk->sntrup_type = sntrup_type;
		return lc_sntrup_857_kem_keypair(&pk->key.pk_sntrup_857,
						 &sk->key.sk_sntrup_857,
						 rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_761:
#ifdef LC_SNTRUP_761_ENABLED
		pk->sntrup_type = sntrup_type;
		sk->sntrup_type = sntrup_type;
		return lc_sntrup_761_kem_keypair(&pk->key.pk_sntrup_761,
						 &sk->key.sk_sntrup_761,
						 rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

#if 0
LC_INTERFACE_FUNCTION(int, lc_sntrup_keypair_from_seed,
		      struct lc_sntrup_pk *pk, struct lc_sntrup_sk *sk,
		      const uint8_t *seed, size_t seedlen,
		      enum lc_sntrup_type sntrup_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		pk->sntrup_type = sntrup_type;
		sk->sntrup_type = sntrup_type;
		return lc_sntrup_shake_1277s_keypair_from_seed(
			&pk->key.pk_shake_1277s, &sk->key.sk_shake_1277s, seed,
			seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_pk_from_sk, struct lc_sntrup_pk *pk,
		      const struct lc_sntrup_sk *sk)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (sk->sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		pk->sntrup_type = sk->sntrup_type;
		return lc_sntrup_shake_1277s_pk_from_sk(&pk->key.pk_shake_1277s,
							&sk->key.sk_shake_1277s);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
#endif

LC_INTERFACE_FUNCTION(int, lc_sntrup_enc, struct lc_sntrup_ct *ct,
		      struct lc_sntrup_ss *ss, const struct lc_sntrup_pk *pk)
{
	if (!ct || !ss || !pk)
		return -EINVAL;

	switch (pk->sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		ct->sntrup_type = LC_SNTRUP_1277;
		ss->sntrup_type = LC_SNTRUP_1277;
		return lc_sntrup_1277_kem_enc(&ct->key.ct_sntrup_1277,
					      &ss->key.ss_sntrup_1277,
					      &pk->key.pk_sntrup_1277);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_1013:
#ifdef LC_SNTRUP_1013_ENABLED
		ct->sntrup_type = LC_SNTRUP_1013;
		ss->sntrup_type = LC_SNTRUP_1013;
		return lc_sntrup_1013_kem_enc(&ct->key.ct_sntrup_1013,
					      &ss->key.ss_sntrup_1013,
					      &pk->key.pk_sntrup_1013);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_953:
#ifdef LC_SNTRUP_953_ENABLED
		ct->sntrup_type = LC_SNTRUP_953;
		ss->sntrup_type = LC_SNTRUP_953;
		return lc_sntrup_953_kem_enc(&ct->key.ct_sntrup_953,
					     &ss->key.ss_sntrup_953,
					     &pk->key.pk_sntrup_953);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_857:
#ifdef LC_SNTRUP_857_ENABLED
		ct->sntrup_type = LC_SNTRUP_857;
		ss->sntrup_type = LC_SNTRUP_857;
		return lc_sntrup_857_kem_enc(&ct->key.ct_sntrup_857,
					     &ss->key.ss_sntrup_857,
					     &pk->key.pk_sntrup_857);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_761:
#ifdef LC_SNTRUP_761_ENABLED
		ct->sntrup_type = LC_SNTRUP_761;
		ss->sntrup_type = LC_SNTRUP_761;
		return lc_sntrup_761_kem_enc(&ct->key.ct_sntrup_761,
					     &ss->key.ss_sntrup_761,
					     &pk->key.pk_sntrup_761);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_sntrup_dec, struct lc_sntrup_ss *ss,
		      const struct lc_sntrup_ct *ct,
		      const struct lc_sntrup_sk *sk)
{
	if (!ct || !ss || !sk)
		return -EINVAL;

	switch (sk->sntrup_type) {
	case LC_SNTRUP_1277:
#ifdef LC_SNTRUP_1277_ENABLED
		ss->sntrup_type = LC_SNTRUP_1277;
		return lc_sntrup_1277_kem_dec(&ss->key.ss_sntrup_1277,
					      &ct->key.ct_sntrup_1277,
					      &sk->key.sk_sntrup_1277);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_1013:
#ifdef LC_SNTRUP_1013_ENABLED
		ss->sntrup_type = LC_SNTRUP_1013;
		return lc_sntrup_1013_kem_dec(&ss->key.ss_sntrup_1013,
					      &ct->key.ct_sntrup_1013,
					      &sk->key.sk_sntrup_1013);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_953:
#ifdef LC_SNTRUP_953_ENABLED
		ss->sntrup_type = LC_SNTRUP_953;
		return lc_sntrup_953_kem_dec(&ss->key.ss_sntrup_953,
					     &ct->key.ct_sntrup_953,
					     &sk->key.sk_sntrup_953);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_857:
#ifdef LC_SNTRUP_857_ENABLED
		ss->sntrup_type = LC_SNTRUP_857;
		return lc_sntrup_857_kem_dec(&ss->key.ss_sntrup_857,
					     &ct->key.ct_sntrup_857,
					     &sk->key.sk_sntrup_857);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_761:
#ifdef LC_SNTRUP_761_ENABLED
		ss->sntrup_type = LC_SNTRUP_761;
		return lc_sntrup_761_kem_dec(&ss->key.ss_sntrup_761,
					     &ct->key.ct_sntrup_761,
					     &sk->key.sk_sntrup_761);
#else
		return -EOPNOTSUPP;
#endif
	case LC_SNTRUP_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}
