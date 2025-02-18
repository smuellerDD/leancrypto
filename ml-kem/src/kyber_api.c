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

#include "ext_headers.h"
#include "lc_kyber.h"
#include "lc_memcmp_secure.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "timecop.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(enum lc_kyber_type, lc_kyber_sk_type,
		      const struct lc_kyber_sk *sk)
{
	if (!sk)
		return LC_KYBER_UNKNOWN;
	return sk->kyber_type;
}

LC_INTERFACE_FUNCTION(enum lc_kyber_type, lc_kyber_pk_type,
		      const struct lc_kyber_pk *pk)
{
	if (!pk)
		return LC_KYBER_UNKNOWN;
	return pk->kyber_type;
}

LC_INTERFACE_FUNCTION(enum lc_kyber_type, lc_kyber_ct_type,
		      const struct lc_kyber_ct *ct)
{
	if (!ct)
		return LC_KYBER_UNKNOWN;
	return ct->kyber_type;
}

LC_INTERFACE_FUNCTION(enum lc_kyber_type, lc_kyber_ss_type,
		      const struct lc_kyber_ss *ss)
{
	if (!ss)
		return LC_KYBER_UNKNOWN;
	return ss->kyber_type;
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_kyber_sk_size,
		      enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_sk, key.sk_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_sk, key.sk_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_sk, key.sk_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_kyber_pk_size,
		      enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_pk, key.pk_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_pk, key.pk_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_pk, key.pk_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_kyber_ct_size,
		      enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_ct, key.ct_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_ct, key.ct_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_ct, key.ct_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_kyber_ss_size,
		      enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_ss, key.ss_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_ss, key.ss_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_ss, key.ss_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_sk_load, struct lc_kyber_sk *sk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!sk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (src_key_len == lc_kyber_sk_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_sk *_sk = &sk->key.sk_1024;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (src_key_len == lc_kyber_sk_size(LC_KYBER_768)) {
		struct lc_kyber_768_sk *_sk = &sk->key.sk_768;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (src_key_len == lc_kyber_sk_size(LC_KYBER_512)) {
		struct lc_kyber_512_sk *_sk = &sk->key.sk_512;

		memcpy(_sk->sk, src_key, src_key_len);
		sk->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_pk_load, struct lc_kyber_pk *pk,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!pk || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (src_key_len == lc_kyber_pk_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_pk *_pk = &pk->key.pk_1024;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (src_key_len == lc_kyber_pk_size(LC_KYBER_768)) {
		struct lc_kyber_768_pk *_pk = &pk->key.pk_768;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (src_key_len == lc_kyber_pk_size(LC_KYBER_512)) {
		struct lc_kyber_512_pk *_pk = &pk->key.pk_512;

		memcpy(_pk->pk, src_key, src_key_len);
		pk->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ct_load, struct lc_kyber_ct *ct,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!ct || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (src_key_len == lc_kyber_ct_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_ct *_ct = &ct->key.ct_1024;

		memcpy(_ct->ct, src_key, src_key_len);
		ct->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (src_key_len == lc_kyber_ct_size(LC_KYBER_768)) {
		struct lc_kyber_768_ct *_ct = &ct->key.ct_768;

		memcpy(_ct->ct, src_key, src_key_len);
		ct->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (src_key_len == lc_kyber_ct_size(LC_KYBER_512)) {
		struct lc_kyber_512_ct *_ct = &ct->key.ct_512;

		memcpy(_ct->ct, src_key, src_key_len);
		ct->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ss_load, struct lc_kyber_ss *ss,
		      const uint8_t *src_key, size_t src_key_len)
{
	if (!ss || !src_key || src_key_len == 0) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (src_key_len == lc_kyber_ss_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_ss *_ss = &ss->key.ss_1024;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (src_key_len == lc_kyber_ss_size(LC_KYBER_768)) {
		struct lc_kyber_768_ss *_ss = &ss->key.ss_768;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (src_key_len == lc_kyber_ss_size(LC_KYBER_512)) {
		struct lc_kyber_512_ss *_ss = &ss->key.ss_512;

		memcpy(_ss->ss, src_key, src_key_len);
		ss->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_sk_ptr, uint8_t **kyber_key,
		      size_t *kyber_key_len, struct lc_kyber_sk *sk)
{
	if (!sk || !kyber_key || !kyber_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (sk->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_sk *_sk = &sk->key.sk_1024;

		*kyber_key = _sk->sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (sk->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_sk *_sk = &sk->key.sk_768;

		*kyber_key = _sk->sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (sk->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_sk *_sk = &sk->key.sk_512;

		*kyber_key = _sk->sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_pk_ptr, uint8_t **kyber_key,
		      size_t *kyber_key_len, struct lc_kyber_pk *pk)
{
	if (!pk || !kyber_key || !kyber_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (pk->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_pk *_pk = &pk->key.pk_1024;

		*kyber_key = _pk->pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (pk->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_pk *_pk = &pk->key.pk_768;

		*kyber_key = _pk->pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (pk->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_pk *_pk = &pk->key.pk_512;

		*kyber_key = _pk->pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ct_ptr, uint8_t **kyber_ct,
		      size_t *kyber_ct_len, struct lc_kyber_ct *ct)
{
	if (!ct || !kyber_ct || !kyber_ct_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (ct->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_ct *_ct = &ct->key.ct_1024;

		*kyber_ct = _ct->ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (ct->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_ct *_ct = &ct->key.ct_768;

		*kyber_ct = _ct->ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (ct->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_ct *_ct = &ct->key.ct_512;

		*kyber_ct = _ct->ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ss_ptr, uint8_t **kyber_ss,
		      size_t *kyber_ss_len, struct lc_kyber_ss *ss)
{
	if (!ss || !kyber_ss || !kyber_ss_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (ss->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_ss *_ss = &ss->key.ss_1024;

		*kyber_ss = _ss->ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (ss->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_ss *_ss = &ss->key.ss_768;

		*kyber_ss = _ss->ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (ss->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_ss *_ss = &ss->key.ss_512;

		*kyber_ss = _ss->ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_keypair, struct lc_kyber_pk *pk,
		      struct lc_kyber_sk *sk, struct lc_rng_ctx *rng_ctx,
		      enum lc_kyber_type kyber_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_1024_keypair(&pk->key.pk_1024, &sk->key.sk_1024,
					     rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_768_keypair(&pk->key.pk_768, &sk->key.sk_768,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_512_keypair(&pk->key.pk_512, &sk->key.sk_512,
					    rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_keypair_from_seed, struct lc_kyber_pk *pk,
		      struct lc_kyber_sk *sk, const uint8_t *seed,
		      size_t seedlen, enum lc_kyber_type kyber_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_1024_keypair_from_seed(
			&pk->key.pk_1024, &sk->key.sk_1024, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_768_keypair_from_seed(
			&pk->key.pk_768, &sk->key.sk_768, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_512_keypair_from_seed(
			&pk->key.pk_512, &sk->key.sk_512, seed, seedlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_pct, const struct lc_kyber_pk *pk,
		      const struct lc_kyber_sk *sk)
{
	struct workspace {
		uint8_t m[32];
		struct lc_kyber_ct ct;
		struct lc_kyber_ss ss1, ss2;
	};
	uint8_t *ss1_p, *ss2_p;
	size_t ss1_size, ss2_size;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, ws->m, sizeof(ws->m)));

	CKINT(lc_kyber_enc(&ws->ct, &ws->ss1, pk));
	CKINT(lc_kyber_dec(&ws->ss2, &ws->ct, sk));

	CKINT(lc_kyber_ss_ptr(&ss1_p, &ss1_size, &ws->ss1));
	CKINT(lc_kyber_ss_ptr(&ss2_p, &ss2_size, &ws->ss2));

	/*
	 * Timecop: the Kyber SS will not reveal anything about the SK or PK.
	 * Further, it is not a secret here, as it is generated for testing.
	 * Thus, we can ignore side channels here.
	 */
	unpoison(ss1_p, ss1_size);
	unpoison(ss2_p, ss2_size);

	CKINT(lc_memcmp_secure(ss1_p, ss1_size, ss2_p, ss2_size));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kyber_enc, struct lc_kyber_ct *ct,
		      struct lc_kyber_ss *ss, const struct lc_kyber_pk *pk)
{
	if (!ct || !ss || !pk)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		ss->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_enc(&ct->key.ct_1024, &ss->key.ss_1024,
					 &pk->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		ss->kyber_type = LC_KYBER_768;
		return lc_kyber_768_enc(&ct->key.ct_768, &ss->key.ss_768,
					&pk->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		ss->kyber_type = LC_KYBER_512;
		return lc_kyber_512_enc(&ct->key.ct_512, &ss->key.ss_512,
					&pk->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_enc_kdf, struct lc_kyber_ct *ct,
		      uint8_t *ss, size_t ss_len, const struct lc_kyber_pk *pk)
{
	if (!ct || !pk)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_enc_kdf(&ct->key.ct_1024, ss, ss_len,
					     &pk->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_enc_kdf(&ct->key.ct_768, ss, ss_len,
					    &pk->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_enc_kdf(&ct->key.ct_512, ss, ss_len,
					    &pk->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_dec, struct lc_kyber_ss *ss,
		      const struct lc_kyber_ct *ct,
		      const struct lc_kyber_sk *sk)
{
	if (!ss || !ct || !sk || ct->kyber_type != sk->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ss->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_dec(&ss->key.ss_1024, &ct->key.ct_1024,
					 &sk->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ss->kyber_type = LC_KYBER_768;
		return lc_kyber_768_dec(&ss->key.ss_768, &ct->key.ct_768,
					&sk->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ss->kyber_type = LC_KYBER_512;
		return lc_kyber_512_dec(&ss->key.ss_512, &ct->key.ct_512,
					&sk->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_ct *ct,
		      const struct lc_kyber_sk *sk)
{
	if (!ct || !sk || ct->kyber_type != sk->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_dec_kdf(ss, ss_len, &ct->key.ct_1024,
					     &sk->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_dec_kdf(ss, ss_len, &ct->key.ct_768,
					    &sk->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_dec_kdf(ss, ss_len, &ct->key.ct_512,
					    &sk->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/************************************* KEX ************************************/

LC_INTERFACE_FUNCTION(int, lc_kex_uake_initiator_init,
		      struct lc_kyber_pk *pk_e_i, struct lc_kyber_ct *ct_e_i,
		      struct lc_kyber_ss *tk, struct lc_kyber_sk *sk_e,
		      const struct lc_kyber_pk *pk_r)
{
	if (!pk_e_i || !ct_e_i || !tk || !sk_e || !pk_r)
		return -EINVAL;

	switch (pk_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk_e_i->kyber_type = LC_KYBER_1024;
		ct_e_i->kyber_type = LC_KYBER_1024;
		tk->kyber_type = LC_KYBER_1024;
		sk_e->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_uake_initiator_init(&pk_e_i->key.pk_1024,
						       &ct_e_i->key.ct_1024,
						       &tk->key.ss_1024,
						       &sk_e->key.sk_1024,
						       &pk_r->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk_e_i->kyber_type = LC_KYBER_768;
		ct_e_i->kyber_type = LC_KYBER_768;
		tk->kyber_type = LC_KYBER_768;
		sk_e->kyber_type = LC_KYBER_768;
		return lc_kex_768_uake_initiator_init(
			&pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&tk->key.ss_768, &sk_e->key.sk_768, &pk_r->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk_e_i->kyber_type = LC_KYBER_512;
		ct_e_i->kyber_type = LC_KYBER_512;
		tk->kyber_type = LC_KYBER_512;
		sk_e->kyber_type = LC_KYBER_512;
		return lc_kex_512_uake_initiator_init(
			&pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&tk->key.ss_512, &sk_e->key.sk_512, &pk_r->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_uake_responder_ss, struct lc_kyber_ct *ct_e_r,
		      uint8_t *shared_secret, size_t shared_secret_len,
		      const uint8_t *kdf_nonce, size_t kdf_nonce_len,
		      const struct lc_kyber_pk *pk_e_i,
		      const struct lc_kyber_ct *ct_e_i,
		      const struct lc_kyber_sk *sk_r)
{
	if (!ct_e_r || !pk_e_i || !ct_e_i || !sk_r ||
	    pk_e_i->kyber_type != ct_e_i->kyber_type ||
	    pk_e_i->kyber_type != sk_r->kyber_type)
		return -EINVAL;

	switch (pk_e_i->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct_e_r->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_uake_responder_ss(
			&ct_e_r->key.ct_1024, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_1024,
			&ct_e_i->key.ct_1024, &sk_r->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct_e_r->kyber_type = LC_KYBER_768;
		return lc_kex_768_uake_responder_ss(
			&ct_e_r->key.ct_768, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_768,
			&ct_e_i->key.ct_768, &sk_r->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct_e_r->kyber_type = LC_KYBER_512;
		return lc_kex_512_uake_responder_ss(
			&ct_e_r->key.ct_512, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_512,
			&ct_e_i->key.ct_512, &sk_r->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_uake_initiator_ss, uint8_t *shared_secret,
		      size_t shared_secret_len, const uint8_t *kdf_nonce,
		      size_t kdf_nonce_len, const struct lc_kyber_ct *ct_e_r,
		      const struct lc_kyber_ss *tk,
		      const struct lc_kyber_sk *sk_e)
{
	if (!ct_e_r || !tk || !sk_e || ct_e_r->kyber_type != tk->kyber_type ||
	    ct_e_r->kyber_type != sk_e->kyber_type)
		return -EINVAL;

	switch (ct_e_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kex_1024_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_1024, &tk->key.ss_1024,
			&sk_e->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kex_768_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_768, &tk->key.ss_768,
			&sk_e->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kex_512_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_512, &tk->key.ss_512,
			&sk_e->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_ake_initiator_init,
		      struct lc_kyber_pk *pk_e_i, struct lc_kyber_ct *ct_e_i,
		      struct lc_kyber_ss *tk, struct lc_kyber_sk *sk_e,
		      const struct lc_kyber_pk *pk_r)
{
	if (!pk_e_i || !ct_e_i || !tk || !sk_e || !pk_r)
		return -EINVAL;

	switch (pk_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk_e_i->kyber_type = LC_KYBER_1024;
		ct_e_i->kyber_type = LC_KYBER_1024;
		tk->kyber_type = LC_KYBER_1024;
		sk_e->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_ake_initiator_init(&pk_e_i->key.pk_1024,
						      &ct_e_i->key.ct_1024,
						      &tk->key.ss_1024,
						      &sk_e->key.sk_1024,
						      &pk_r->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk_e_i->kyber_type = LC_KYBER_768;
		ct_e_i->kyber_type = LC_KYBER_768;
		tk->kyber_type = LC_KYBER_768;
		sk_e->kyber_type = LC_KYBER_768;
		return lc_kex_768_ake_initiator_init(
			&pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&tk->key.ss_768, &sk_e->key.sk_768, &pk_r->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk_e_i->kyber_type = LC_KYBER_512;
		ct_e_i->kyber_type = LC_KYBER_512;
		tk->kyber_type = LC_KYBER_512;
		sk_e->kyber_type = LC_KYBER_512;
		return lc_kex_512_ake_initiator_init(
			&pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&tk->key.ss_512, &sk_e->key.sk_512, &pk_r->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_ake_responder_ss,
		      struct lc_kyber_ct *ct_e_r_1,
		      struct lc_kyber_ct *ct_e_r_2, uint8_t *shared_secret,
		      size_t shared_secret_len, const uint8_t *kdf_nonce,
		      size_t kdf_nonce_len, const struct lc_kyber_pk *pk_e_i,
		      const struct lc_kyber_ct *ct_e_i,
		      const struct lc_kyber_sk *sk_r,
		      const struct lc_kyber_pk *pk_i)
{
	if (!ct_e_r_1 || !ct_e_r_2 || !pk_e_i || !ct_e_i || !sk_r || !pk_i ||
	    pk_e_i->kyber_type != ct_e_i->kyber_type ||
	    pk_e_i->kyber_type != sk_r->kyber_type ||
	    pk_e_i->kyber_type != pk_i->kyber_type)
		return -EINVAL;

	switch (pk_e_i->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_1024;
		ct_e_r_2->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_ake_responder_ss(
			&ct_e_r_1->key.ct_1024, &ct_e_r_2->key.ct_1024,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_1024,
			&ct_e_i->key.ct_1024, &sk_r->key.sk_1024,
			&pk_i->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_768;
		ct_e_r_2->kyber_type = LC_KYBER_768;
		return lc_kex_768_ake_responder_ss(
			&ct_e_r_1->key.ct_768, &ct_e_r_2->key.ct_768,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&sk_r->key.sk_768, &pk_i->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_512;
		ct_e_r_2->kyber_type = LC_KYBER_512;
		return lc_kex_512_ake_responder_ss(
			&ct_e_r_1->key.ct_512, &ct_e_r_2->key.ct_512,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&sk_r->key.sk_512, &pk_i->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_ake_initiator_ss, uint8_t *shared_secret,
		      size_t shared_secret_len, const uint8_t *kdf_nonce,
		      size_t kdf_nonce_len, const struct lc_kyber_ct *ct_e_r_1,
		      const struct lc_kyber_ct *ct_e_r_2,
		      const struct lc_kyber_ss *tk,
		      const struct lc_kyber_sk *sk_e,
		      const struct lc_kyber_sk *sk_i)
{
	if (!ct_e_r_1 || !ct_e_r_2 || !tk || !sk_e || !sk_i ||
	    ct_e_r_1->kyber_type != ct_e_r_2->kyber_type ||
	    ct_e_r_1->kyber_type != tk->kyber_type ||
	    ct_e_r_1->kyber_type != sk_e->kyber_type ||
	    ct_e_r_1->kyber_type != sk_i->kyber_type)
		return -EINVAL;

	switch (ct_e_r_1->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kex_1024_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_1024,
			&ct_e_r_2->key.ct_1024, &tk->key.ss_1024,
			&sk_e->key.sk_1024, &sk_i->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kex_768_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_768,
			&ct_e_r_2->key.ct_768, &tk->key.ss_768,
			&sk_e->key.sk_768, &sk_i->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kex_512_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_512,
			&ct_e_r_2->key.ct_512, &tk->key.ss_512,
			&sk_e->key.sk_512, &sk_i->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/************************************* IES ************************************/

#ifdef LC_KYBER_IES

LC_INTERFACE_FUNCTION(int, lc_kyber_ies_enc, const struct lc_kyber_pk *pk,
		      struct lc_kyber_ct *ct, const uint8_t *plaintext,
		      uint8_t *ciphertext, size_t datalen, const uint8_t *aad,
		      size_t aadlen, uint8_t *tag, size_t taglen,
		      struct lc_aead_ctx *aead)
{
	if (!pk || !ct)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_ies_enc(&pk->key.pk_1024, &ct->key.ct_1024,
					     plaintext, ciphertext, datalen,
					     aad, aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_ies_enc(&pk->key.pk_768, &ct->key.ct_768,
					    plaintext, ciphertext, datalen, aad,
					    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_ies_enc(&pk->key.pk_512, &ct->key.ct_512,
					    plaintext, ciphertext, datalen, aad,
					    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ies_enc_init, struct lc_aead_ctx *aead,
		      const struct lc_kyber_pk *pk, struct lc_kyber_ct *ct,
		      const uint8_t *aad, size_t aadlen)
{
	if (!pk || !ct)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_ies_enc_init(
			aead, &pk->key.pk_1024, &ct->key.ct_1024, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_ies_enc_init(aead, &pk->key.pk_768,
						 &ct->key.ct_768, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_ies_enc_init(aead, &pk->key.pk_512,
						 &ct->key.ct_512, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ies_enc_update, struct lc_aead_ctx *aead,
		      const uint8_t *plaintext, uint8_t *ciphertext,
		      size_t datalen)
{
	return lc_aead_enc_update(aead, plaintext, ciphertext, datalen);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ies_enc_final, struct lc_aead_ctx *aead,
		      uint8_t *tag, size_t taglen)
{
	return lc_aead_enc_final(aead, tag, taglen);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ies_dec, const struct lc_kyber_sk *sk,
		      const struct lc_kyber_ct *ct, const uint8_t *ciphertext,
		      uint8_t *plaintext, size_t datalen, const uint8_t *aad,
		      size_t aadlen, const uint8_t *tag, size_t taglen,
		      struct lc_aead_ctx *aead)
{
	if (!sk || !ct || sk->kyber_type != ct->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_ies_dec(&sk->key.sk_1024, &ct->key.ct_1024,
					     ciphertext, plaintext, datalen,
					     aad, aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_ies_dec(&sk->key.sk_768, &ct->key.ct_768,
					    ciphertext, plaintext, datalen, aad,
					    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_ies_dec(&sk->key.sk_512, &ct->key.ct_512,
					    ciphertext, plaintext, datalen, aad,
					    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ies_dec_init, struct lc_aead_ctx *aead,
		      const struct lc_kyber_sk *sk,
		      const struct lc_kyber_ct *ct, const uint8_t *aad,
		      size_t aadlen)
{
	if (!sk || !ct || sk->kyber_type != ct->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_ies_dec_init(
			aead, &sk->key.sk_1024, &ct->key.ct_1024, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_ies_dec_init(aead, &sk->key.sk_768,
						 &ct->key.ct_768, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_ies_dec_init(aead, &sk->key.sk_512,
						 &ct->key.ct_512, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ies_dec_update, struct lc_aead_ctx *aead,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen)
{
	return lc_aead_dec_update(aead, ciphertext, plaintext, datalen);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_ies_dec_final, struct lc_aead_ctx *aead,
		      const uint8_t *tag, size_t taglen)
{
	return lc_aead_dec_final(aead, tag, taglen);
}

#endif /* LC_KYBER_IES */
/****************************** Kyber X25510 KEM ******************************/

#ifdef LC_KYBER_X25519_KEM

LC_INTERFACE_FUNCTION(enum lc_kyber_type, lc_kyber_x25519_sk_type,
		      const struct lc_kyber_x25519_sk *sk)
{
	if (!sk)
		return LC_KYBER_UNKNOWN;
	return sk->kyber_type;
}

LC_INTERFACE_FUNCTION(enum lc_kyber_type, lc_kyber_x25519_pk_type,
		      const struct lc_kyber_x25519_pk *pk)
{
	if (!pk)
		return LC_KYBER_UNKNOWN;
	return pk->kyber_type;
}

LC_INTERFACE_FUNCTION(enum lc_kyber_type, lc_kyber_x25519_ct_type,
		      const struct lc_kyber_x25519_ct *ct)
{
	if (!ct)
		return LC_KYBER_UNKNOWN;
	return ct->kyber_type;
}

LC_INTERFACE_FUNCTION(enum lc_kyber_type, lc_kyber_x25519_ss_type,
		      const struct lc_kyber_x25519_ss *ss)
{
	if (!ss)
		return LC_KYBER_UNKNOWN;
	return ss->kyber_type;
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_kyber_x25519_sk_size,
		      enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_x25519_sk, key.sk_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_x25519_sk, key.sk_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_x25519_sk, key.sk_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_kyber_x25519_pk_size,
		      enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_x25519_pk, key.pk_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_x25519_pk, key.pk_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_x25519_pk, key.pk_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_kyber_x25519_ct_size,
		      enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ct, key.ct_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ct, key.ct_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ct, key.ct_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

LC_PURE
LC_INTERFACE_FUNCTION(unsigned int, lc_kyber_x25519_ss_size,
		      enum lc_kyber_type kyber_type)
{
	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ss, key.ss_1024);
#else
		return 0;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ss, key.ss_768);
#else
		return 0;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_member_size(struct lc_kyber_x25519_ss, key.ss_512);
#else
		return 0;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return 0;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_sk_load,
		      struct lc_kyber_x25519_sk *sk,
		      const uint8_t *kyber_src_key, size_t kyber_src_key_len,
		      const uint8_t *x25519_src_key, size_t x25519_src_key_len)
{
	if (!sk || !kyber_src_key_len || !x25519_src_key_len ||
	    kyber_src_key_len == 0 ||
	    x25519_src_key_len != LC_X25519_SECRETKEYBYTES) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (kyber_src_key_len == lc_kyber_sk_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_x25519_sk *_sk = &sk->key.sk_1024;

		memcpy(_sk->sk.sk, kyber_src_key, kyber_src_key_len);
		memcpy(_sk->sk_x25519.sk, x25519_src_key, x25519_src_key_len);
		sk->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (kyber_src_key_len == lc_kyber_sk_size(LC_KYBER_768)) {
		struct lc_kyber_768_x25519_sk *_sk = &sk->key.sk_768;

		memcpy(_sk->sk.sk, kyber_src_key, kyber_src_key_len);
		memcpy(_sk->sk_x25519.sk, x25519_src_key, x25519_src_key_len);
		sk->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (kyber_src_key_len == lc_kyber_sk_size(LC_KYBER_512)) {
		struct lc_kyber_512_x25519_sk *_sk = &sk->key.sk_512;

		memcpy(_sk->sk.sk, kyber_src_key, kyber_src_key_len);
		memcpy(_sk->sk_x25519.sk, x25519_src_key, x25519_src_key_len);
		sk->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_pk_load,
		      struct lc_kyber_x25519_pk *pk,
		      const uint8_t *kyber_src_key, size_t kyber_src_key_len,
		      const uint8_t *x25519_src_key, size_t x25519_src_key_len)
{
	if (!pk || !kyber_src_key_len || !x25519_src_key_len ||
	    kyber_src_key_len == 0 ||
	    x25519_src_key_len != LC_X25519_PUBLICKEYBYTES) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (kyber_src_key_len == lc_kyber_pk_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_x25519_pk *_pk = &pk->key.pk_1024;

		memcpy(_pk->pk.pk, kyber_src_key, kyber_src_key_len);
		memcpy(_pk->pk_x25519.pk, x25519_src_key, x25519_src_key_len);
		pk->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (kyber_src_key_len == lc_kyber_pk_size(LC_KYBER_768)) {
		struct lc_kyber_768_x25519_pk *_pk = &pk->key.pk_768;

		memcpy(_pk->pk.pk, kyber_src_key, kyber_src_key_len);
		memcpy(_pk->pk_x25519.pk, x25519_src_key, x25519_src_key_len);
		pk->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (kyber_src_key_len == lc_kyber_pk_size(LC_KYBER_512)) {
		struct lc_kyber_512_x25519_pk *_pk = &pk->key.pk_512;

		memcpy(_pk->pk.pk, kyber_src_key, kyber_src_key_len);
		memcpy(_pk->pk_x25519.pk, x25519_src_key, x25519_src_key_len);
		pk->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ct_load,
		      struct lc_kyber_x25519_ct *ct,
		      const uint8_t *kyber_src_ct, size_t kyber_src_ct_len,
		      const uint8_t *x25519_rem_pub_key,
		      size_t x25519_rem_pub_len)
{
	if (!ct || !kyber_src_ct_len || !x25519_rem_pub_len ||
	    kyber_src_ct_len == 0 ||
	    x25519_rem_pub_len != LC_X25519_PUBLICKEYBYTES) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (kyber_src_ct_len == lc_kyber_ct_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_x25519_ct *_ct = &ct->key.ct_1024;

		memcpy(_ct->ct.ct, kyber_src_ct, kyber_src_ct_len);
		memcpy(_ct->pk_x25519.pk, x25519_rem_pub_key,
		       x25519_rem_pub_len);
		ct->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (kyber_src_ct_len == lc_kyber_ct_size(LC_KYBER_768)) {
		struct lc_kyber_768_x25519_ct *_ct = &ct->key.ct_768;

		memcpy(_ct->ct.ct, kyber_src_ct, kyber_src_ct_len);
		memcpy(_ct->pk_x25519.pk, x25519_rem_pub_key,
		       x25519_rem_pub_len);
		ct->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (kyber_src_ct_len == lc_kyber_ct_size(LC_KYBER_512)) {
		struct lc_kyber_512_x25519_ct *_ct = &ct->key.ct_512;

		memcpy(_ct->ct.ct, kyber_src_ct, kyber_src_ct_len);
		memcpy(_ct->pk_x25519.pk, x25519_rem_pub_key,
		       x25519_rem_pub_len);
		ct->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ss_load,
		      struct lc_kyber_x25519_ss *ss,
		      const uint8_t *kyber_src_ss, size_t kyber_src_ss_len,
		      const uint8_t *x25519_ss, size_t x25519_ss_len)
{
	if (!ss || !kyber_src_ss_len || !x25519_ss_len ||
	    kyber_src_ss_len == 0 || x25519_ss_len != LC_X25519_SSBYTES) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (kyber_src_ss_len == lc_kyber_ss_size(LC_KYBER_1024)) {
		struct lc_kyber_1024_x25519_ss *_ss = &ss->key.ss_1024;

		memcpy(_ss->ss.ss, kyber_src_ss, kyber_src_ss_len);
		memcpy(_ss->ss_x25519.ss, x25519_ss, x25519_ss_len);
		ss->kyber_type = LC_KYBER_1024;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (kyber_src_ss_len == lc_kyber_ss_size(LC_KYBER_768)) {
		struct lc_kyber_768_x25519_ss *_ss = &ss->key.ss_768;

		memcpy(_ss->ss.ss, kyber_src_ss, kyber_src_ss_len);
		memcpy(_ss->ss_x25519.ss, x25519_ss, x25519_ss_len);
		ss->kyber_type = LC_KYBER_768;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (kyber_src_ss_len == lc_kyber_ss_size(LC_KYBER_512)) {
		struct lc_kyber_512_x25519_ss *_ss = &ss->key.ss_512;

		memcpy(_ss->ss.ss, kyber_src_ss, kyber_src_ss_len);
		memcpy(_ss->ss_x25519.ss, x25519_ss, x25519_ss_len);
		ss->kyber_type = LC_KYBER_512;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_sk_ptr, uint8_t **kyber_key,
		      size_t *kyber_key_len, uint8_t **x25519_key,
		      size_t *x25519_key_len, struct lc_kyber_x25519_sk *sk)
{
	if (!sk || !kyber_key || !kyber_key_len || !x25519_key ||
	    !x25519_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (sk->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_x25519_sk *_sk = &sk->key.sk_1024;

		*kyber_key = _sk->sk.sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		*x25519_key = _sk->sk_x25519.sk;
		*x25519_key_len = LC_X25519_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (sk->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_x25519_sk *_sk = &sk->key.sk_768;

		*kyber_key = _sk->sk.sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		*x25519_key = _sk->sk_x25519.sk;
		*x25519_key_len = LC_X25519_SECRETKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (sk->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_x25519_sk *_sk = &sk->key.sk_512;

		*kyber_key = _sk->sk.sk;
		*kyber_key_len = lc_kyber_sk_size(sk->kyber_type);
		*x25519_key = _sk->sk_x25519.sk;
		*x25519_key_len = LC_X25519_SECRETKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_pk_ptr, uint8_t **kyber_key,
		      size_t *kyber_key_len, uint8_t **x25519_key,
		      size_t *x25519_key_len, struct lc_kyber_x25519_pk *pk)
{
	if (!pk || !kyber_key || !kyber_key_len || !x25519_key ||
	    !x25519_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (pk->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_x25519_pk *_pk = &pk->key.pk_1024;

		*kyber_key = _pk->pk.pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		*x25519_key = _pk->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (pk->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_x25519_pk *_pk = &pk->key.pk_768;

		*kyber_key = _pk->pk.pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		*x25519_key = _pk->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (pk->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_x25519_pk *_pk = &pk->key.pk_512;

		*kyber_key = _pk->pk.pk;
		*kyber_key_len = lc_kyber_pk_size(pk->kyber_type);
		*x25519_key = _pk->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ct_ptr, uint8_t **kyber_ct,
		      size_t *kyber_ct_len, uint8_t **x25519_key,
		      size_t *x25519_key_len, struct lc_kyber_x25519_ct *ct)
{
	if (!ct || !kyber_ct || !kyber_ct_len || !x25519_key ||
	    !x25519_key_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (ct->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_x25519_ct *_ct = &ct->key.ct_1024;

		*kyber_ct = _ct->ct.ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		*x25519_key = _ct->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (ct->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_x25519_ct *_ct = &ct->key.ct_768;

		*kyber_ct = _ct->ct.ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		*x25519_key = _ct->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (ct->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_x25519_ct *_ct = &ct->key.ct_512;

		*kyber_ct = _ct->ct.ct;
		*kyber_ct_len = lc_kyber_ct_size(ct->kyber_type);
		*x25519_key = _ct->pk_x25519.pk;
		*x25519_key_len = LC_X25519_PUBLICKEYBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ss_ptr, uint8_t **kyber_ss,
		      size_t *kyber_ss_len, uint8_t **x25519_ss,
		      size_t *x25519_ss_len, struct lc_kyber_x25519_ss *ss)
{
	if (!ss || !kyber_ss || !kyber_ss_len || !x25519_ss || !x25519_ss_len) {
		return -EINVAL;
#ifdef LC_KYBER_1024_ENABLED
	} else if (ss->kyber_type == LC_KYBER_1024) {
		struct lc_kyber_1024_x25519_ss *_ss = &ss->key.ss_1024;

		*kyber_ss = _ss->ss.ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		*x25519_ss = _ss->ss_x25519.ss;
		*x25519_ss_len = LC_X25519_SSBYTES;
		return 0;
#endif
#ifdef LC_KYBER_768_ENABLED
	} else if (ss->kyber_type == LC_KYBER_768) {
		struct lc_kyber_768_x25519_ss *_ss = &ss->key.ss_768;

		*kyber_ss = _ss->ss.ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		*x25519_ss = _ss->ss_x25519.ss;
		*x25519_ss_len = LC_X25519_SSBYTES;
		return 0;
#endif
#ifdef LC_KYBER_512_ENABLED
	} else if (ss->kyber_type == LC_KYBER_512) {
		struct lc_kyber_512_x25519_ss *_ss = &ss->key.ss_512;

		*kyber_ss = _ss->ss.ss;
		*kyber_ss_len = lc_kyber_ss_size(ss->kyber_type);
		*x25519_ss = _ss->ss_x25519.ss;
		*x25519_ss_len = LC_X25519_SSBYTES;
		return 0;
#endif
	} else {
		return -EINVAL;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_keypair,
		      struct lc_kyber_x25519_pk *pk,
		      struct lc_kyber_x25519_sk *sk, struct lc_rng_ctx *rng_ctx,
		      enum lc_kyber_type kyber_type)
{
	if (!pk || !sk)
		return -EINVAL;

	switch (kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_1024_x25519_keypair(&pk->key.pk_1024,
						    &sk->key.sk_1024, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_768_x25519_keypair(&pk->key.pk_768,
						   &sk->key.sk_768, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk->kyber_type = kyber_type;
		sk->kyber_type = kyber_type;
		return lc_kyber_512_x25519_keypair(&pk->key.pk_512,
						   &sk->key.sk_512, rng_ctx);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_enc_kdf,
		      struct lc_kyber_x25519_ct *ct, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_x25519_pk *pk)
{
	if (!ct || !pk)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_x25519_enc_kdf(&ct->key.ct_1024, ss,
						    ss_len, &pk->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_x25519_enc_kdf(&ct->key.ct_768, ss, ss_len,
						   &pk->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_x25519_enc_kdf(&ct->key.ct_512, ss, ss_len,
						   &pk->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_kyber_x25519_ct *ct,
		      const struct lc_kyber_x25519_sk *sk)
{
	if (!ct || !sk || ct->kyber_type != sk->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_x25519_dec_kdf(
			ss, ss_len, &ct->key.ct_1024, &sk->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_x25519_dec_kdf(ss, ss_len, &ct->key.ct_768,
						   &sk->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_x25519_dec_kdf(ss, ss_len, &ct->key.ct_512,
						   &sk->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/****************************** Kyber X25510 KEX ******************************/

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_uake_initiator_init,
		      struct lc_kyber_x25519_pk *pk_e_i,
		      struct lc_kyber_x25519_ct *ct_e_i,
		      struct lc_kyber_x25519_ss *tk,
		      struct lc_kyber_x25519_sk *sk_e,
		      const struct lc_kyber_x25519_pk *pk_r)
{
	if (!pk_e_i || !ct_e_i || !tk || !sk_e || !pk_r)
		return -EINVAL;

	switch (pk_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk_e_i->kyber_type = LC_KYBER_1024;
		ct_e_i->kyber_type = LC_KYBER_1024;
		tk->kyber_type = LC_KYBER_1024;
		sk_e->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_x25519_uake_initiator_init(
			&pk_e_i->key.pk_1024, &ct_e_i->key.ct_1024,
			&tk->key.ss_1024, &sk_e->key.sk_1024,
			&pk_r->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk_e_i->kyber_type = LC_KYBER_768;
		ct_e_i->kyber_type = LC_KYBER_768;
		tk->kyber_type = LC_KYBER_768;
		sk_e->kyber_type = LC_KYBER_768;
		return lc_kex_768_x25519_uake_initiator_init(
			&pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&tk->key.ss_768, &sk_e->key.sk_768, &pk_r->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk_e_i->kyber_type = LC_KYBER_512;
		ct_e_i->kyber_type = LC_KYBER_512;
		tk->kyber_type = LC_KYBER_512;
		sk_e->kyber_type = LC_KYBER_512;
		return lc_kex_512_x25519_uake_initiator_init(
			&pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&tk->key.ss_512, &sk_e->key.sk_512, &pk_r->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_uake_responder_ss,
		      struct lc_kyber_x25519_ct *ct_e_r, uint8_t *shared_secret,
		      size_t shared_secret_len, const uint8_t *kdf_nonce,
		      size_t kdf_nonce_len,
		      const struct lc_kyber_x25519_pk *pk_e_i,
		      const struct lc_kyber_x25519_ct *ct_e_i,
		      const struct lc_kyber_x25519_sk *sk_r)
{
	if (!ct_e_r || !pk_e_i || !ct_e_i || !sk_r ||
	    pk_e_i->kyber_type != ct_e_i->kyber_type ||
	    pk_e_i->kyber_type != sk_r->kyber_type)
		return -EINVAL;

	switch (pk_e_i->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct_e_r->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_x25519_uake_responder_ss(
			&ct_e_r->key.ct_1024, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_1024,
			&ct_e_i->key.ct_1024, &sk_r->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct_e_r->kyber_type = LC_KYBER_768;
		return lc_kex_768_x25519_uake_responder_ss(
			&ct_e_r->key.ct_768, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_768,
			&ct_e_i->key.ct_768, &sk_r->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct_e_r->kyber_type = LC_KYBER_512;
		return lc_kex_512_x25519_uake_responder_ss(
			&ct_e_r->key.ct_512, shared_secret, shared_secret_len,
			kdf_nonce, kdf_nonce_len, &pk_e_i->key.pk_512,
			&ct_e_i->key.ct_512, &sk_r->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_uake_initiator_ss,
		      uint8_t *shared_secret, size_t shared_secret_len,
		      const uint8_t *kdf_nonce, size_t kdf_nonce_len,
		      const struct lc_kyber_x25519_ct *ct_e_r,
		      const struct lc_kyber_x25519_ss *tk,
		      const struct lc_kyber_x25519_sk *sk_e)
{
	if (!ct_e_r || !tk || !sk_e || ct_e_r->kyber_type != tk->kyber_type ||
	    ct_e_r->kyber_type != sk_e->kyber_type)
		return -EINVAL;

	switch (ct_e_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kex_1024_x25519_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_1024, &tk->key.ss_1024,
			&sk_e->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kex_768_x25519_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_768, &tk->key.ss_768,
			&sk_e->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kex_512_x25519_uake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r->key.ct_512, &tk->key.ss_512,
			&sk_e->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_ake_initiator_init,
		      struct lc_kyber_x25519_pk *pk_e_i,
		      struct lc_kyber_x25519_ct *ct_e_i,
		      struct lc_kyber_x25519_ss *tk,
		      struct lc_kyber_x25519_sk *sk_e,
		      const struct lc_kyber_x25519_pk *pk_r)
{
	if (!pk_e_i || !ct_e_i || !tk || !sk_e || !pk_r)
		return -EINVAL;

	switch (pk_r->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		pk_e_i->kyber_type = LC_KYBER_1024;
		ct_e_i->kyber_type = LC_KYBER_1024;
		tk->kyber_type = LC_KYBER_1024;
		sk_e->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_x25519_ake_initiator_init(
			&pk_e_i->key.pk_1024, &ct_e_i->key.ct_1024,
			&tk->key.ss_1024, &sk_e->key.sk_1024,
			&pk_r->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		pk_e_i->kyber_type = LC_KYBER_768;
		ct_e_i->kyber_type = LC_KYBER_768;
		tk->kyber_type = LC_KYBER_768;
		sk_e->kyber_type = LC_KYBER_768;
		return lc_kex_768_x25519_ake_initiator_init(
			&pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&tk->key.ss_768, &sk_e->key.sk_768, &pk_r->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		pk_e_i->kyber_type = LC_KYBER_512;
		ct_e_i->kyber_type = LC_KYBER_512;
		tk->kyber_type = LC_KYBER_512;
		sk_e->kyber_type = LC_KYBER_512;
		return lc_kex_512_x25519_ake_initiator_init(
			&pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&tk->key.ss_512, &sk_e->key.sk_512, &pk_r->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_ake_responder_ss,
		      struct lc_kyber_x25519_ct *ct_e_r_1,
		      struct lc_kyber_x25519_ct *ct_e_r_2,
		      uint8_t *shared_secret, size_t shared_secret_len,
		      const uint8_t *kdf_nonce, size_t kdf_nonce_len,
		      const struct lc_kyber_x25519_pk *pk_e_i,
		      const struct lc_kyber_x25519_ct *ct_e_i,
		      const struct lc_kyber_x25519_sk *sk_r,
		      const struct lc_kyber_x25519_pk *pk_i)
{
	if (!ct_e_r_1 || !ct_e_r_2 || !pk_e_i || !ct_e_i || !sk_r || !pk_i ||
	    pk_e_i->kyber_type != ct_e_i->kyber_type ||
	    pk_e_i->kyber_type != sk_r->kyber_type ||
	    pk_e_i->kyber_type != pk_i->kyber_type)
		return -EINVAL;

	switch (pk_e_i->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_1024;
		ct_e_r_2->kyber_type = LC_KYBER_1024;
		return lc_kex_1024_x25519_ake_responder_ss(
			&ct_e_r_1->key.ct_1024, &ct_e_r_2->key.ct_1024,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_1024,
			&ct_e_i->key.ct_1024, &sk_r->key.sk_1024,
			&pk_i->key.pk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_768;
		ct_e_r_2->kyber_type = LC_KYBER_768;
		return lc_kex_768_x25519_ake_responder_ss(
			&ct_e_r_1->key.ct_768, &ct_e_r_2->key.ct_768,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_768, &ct_e_i->key.ct_768,
			&sk_r->key.sk_768, &pk_i->key.pk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct_e_r_1->kyber_type = LC_KYBER_512;
		ct_e_r_2->kyber_type = LC_KYBER_512;
		return lc_kex_512_x25519_ake_responder_ss(
			&ct_e_r_1->key.ct_512, &ct_e_r_2->key.ct_512,
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &pk_e_i->key.pk_512, &ct_e_i->key.ct_512,
			&sk_r->key.sk_512, &pk_i->key.pk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_ake_initiator_ss,
		      uint8_t *shared_secret, size_t shared_secret_len,
		      const uint8_t *kdf_nonce, size_t kdf_nonce_len,
		      const struct lc_kyber_x25519_ct *ct_e_r_1,
		      const struct lc_kyber_x25519_ct *ct_e_r_2,
		      const struct lc_kyber_x25519_ss *tk,
		      const struct lc_kyber_x25519_sk *sk_e,
		      const struct lc_kyber_x25519_sk *sk_i)
{
	if (!ct_e_r_1 || !ct_e_r_2 || !tk || !sk_e || !sk_i ||
	    ct_e_r_1->kyber_type != ct_e_r_2->kyber_type ||
	    ct_e_r_1->kyber_type != tk->kyber_type ||
	    ct_e_r_1->kyber_type != sk_e->kyber_type ||
	    ct_e_r_1->kyber_type != sk_i->kyber_type)
		return -EINVAL;

	switch (ct_e_r_1->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kex_1024_x25519_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_1024,
			&ct_e_r_2->key.ct_1024, &tk->key.ss_1024,
			&sk_e->key.sk_1024, &sk_i->key.sk_1024);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kex_768_x25519_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_768,
			&ct_e_r_2->key.ct_768, &tk->key.ss_768,
			&sk_e->key.sk_768, &sk_i->key.sk_768);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kex_512_x25519_ake_initiator_ss(
			shared_secret, shared_secret_len, kdf_nonce,
			kdf_nonce_len, &ct_e_r_1->key.ct_512,
			&ct_e_r_2->key.ct_512, &tk->key.ss_512,
			&sk_e->key.sk_512, &sk_i->key.sk_512);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

/****************************** Kyber X25519 IES ******************************/

#ifdef LC_KYBER_IES

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_enc,
		      const struct lc_kyber_x25519_pk *pk,
		      struct lc_kyber_x25519_ct *ct, const uint8_t *plaintext,
		      uint8_t *ciphertext, size_t datalen, const uint8_t *aad,
		      size_t aadlen, uint8_t *tag, size_t taglen,
		      struct lc_aead_ctx *aead)
{
	if (!pk || !ct)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_x25519_ies_enc(&pk->key.pk_1024,
						    &ct->key.ct_1024, plaintext,
						    ciphertext, datalen, aad,
						    aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_x25519_ies_enc(&pk->key.pk_768,
						   &ct->key.ct_768, plaintext,
						   ciphertext, datalen, aad,
						   aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_x25519_ies_enc(&pk->key.pk_512,
						   &ct->key.ct_512, plaintext,
						   ciphertext, datalen, aad,
						   aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_enc_init,
		      struct lc_aead_ctx *aead,
		      const struct lc_kyber_x25519_pk *pk,
		      struct lc_kyber_x25519_ct *ct, const uint8_t *aad,
		      size_t aadlen)
{
	if (!pk || !ct)
		return -EINVAL;

	switch (pk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		ct->kyber_type = LC_KYBER_1024;
		return lc_kyber_1024_x25519_ies_enc_init(
			aead, &pk->key.pk_1024, &ct->key.ct_1024, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		ct->kyber_type = LC_KYBER_768;
		return lc_kyber_768_x25519_ies_enc_init(
			aead, &pk->key.pk_768, &ct->key.ct_768, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		ct->kyber_type = LC_KYBER_512;
		return lc_kyber_512_x25519_ies_enc_init(
			aead, &pk->key.pk_512, &ct->key.ct_512, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_enc_update,
		      struct lc_aead_ctx *aead, const uint8_t *plaintext,
		      uint8_t *ciphertext, size_t datalen)
{
	return lc_aead_enc_update(aead, plaintext, ciphertext, datalen);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_enc_final,
		      struct lc_aead_ctx *aead, uint8_t *tag, size_t taglen)
{
	return lc_aead_enc_final(aead, tag, taglen);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_dec,
		      const struct lc_kyber_x25519_sk *sk,
		      const struct lc_kyber_x25519_ct *ct,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen, const uint8_t *aad, size_t aadlen,
		      const uint8_t *tag, size_t taglen,
		      struct lc_aead_ctx *aead)
{
	if (!sk || !ct || sk->kyber_type != ct->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_x25519_ies_dec(
			&sk->key.sk_1024, &ct->key.ct_1024, ciphertext,
			plaintext, datalen, aad, aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_x25519_ies_dec(&sk->key.sk_768,
						   &ct->key.ct_768, ciphertext,
						   plaintext, datalen, aad,
						   aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_x25519_ies_dec(&sk->key.sk_512,
						   &ct->key.ct_512, ciphertext,
						   plaintext, datalen, aad,
						   aadlen, tag, taglen, aead);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_dec_init,
		      struct lc_aead_ctx *aead,
		      const struct lc_kyber_x25519_sk *sk,
		      const struct lc_kyber_x25519_ct *ct, const uint8_t *aad,
		      size_t aadlen)
{
	if (!sk || !ct || sk->kyber_type != ct->kyber_type)
		return -EINVAL;

	switch (sk->kyber_type) {
	case LC_KYBER_1024:
#ifdef LC_KYBER_1024_ENABLED
		return lc_kyber_1024_x25519_ies_dec_init(
			aead, &sk->key.sk_1024, &ct->key.ct_1024, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_768:
#ifdef LC_KYBER_768_ENABLED
		return lc_kyber_768_x25519_ies_dec_init(
			aead, &sk->key.sk_768, &ct->key.ct_768, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_512:
#ifdef LC_KYBER_512_ENABLED
		return lc_kyber_512_x25519_ies_dec_init(
			aead, &sk->key.sk_512, &ct->key.ct_512, aad, aadlen);
#else
		return -EOPNOTSUPP;
#endif
	case LC_KYBER_UNKNOWN:
	default:
		return -EOPNOTSUPP;
	}
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_dec_update,
		      struct lc_aead_ctx *aead, const uint8_t *ciphertext,
		      uint8_t *plaintext, size_t datalen)
{
	return lc_aead_dec_update(aead, ciphertext, plaintext, datalen);
}

LC_INTERFACE_FUNCTION(int, lc_kyber_x25519_ies_dec_final,
		      struct lc_aead_ctx *aead, const uint8_t *tag,
		      size_t taglen)
{
	return lc_aead_dec_final(aead, tag, taglen);
}

#endif /* LC_KYBER_IES */

#endif /* LC_KYBER_X25519_KEM */
