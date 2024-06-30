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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef DILITHIUM_SIGNATURE_IMPL_H
#define DILITHIUM_SIGNATURE_IMPL_H

#include "alignment.h"
#include "build_bug_on.h"
#include "dilithium_type.h"
#include "dilithium_debug.h"
#include "dilithium_pack.h"
#include "dilithium_selftest.h"
#include "dilithium_signature_impl.h"
#include "lc_hash.h"
#include "lc_memcmp_secure.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "timecop.h"
#include "visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _WS_POLY_UNIFORM_BUF_SIZE                                              \
	(POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2)

#ifndef LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER
#error "LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER is not defined"
#endif

#define WS_POLY_UNIFORM_BUF_SIZE                                               \
	(_WS_POLY_UNIFORM_BUF_SIZE * LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER)

static int lc_dilithium_keypair_impl(struct lc_dilithium_pk *pk,
				     struct lc_dilithium_sk *sk,
				     struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		polyvecl mat[LC_DILITHIUM_K];
		union {
			polyvecl s1, s1hat;
		} s1;
		polyveck s2, t1, t0;
		uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES +
				LC_DILITHIUM_CRHBYTES];
		union {
			poly polyvecl_pointwise_acc_montgomery_buf;
			uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
			uint8_t poly_uniform_eta_buf[POLY_UNIFORM_ETA_BYTES];
			uint8_t tr[LC_DILITHIUM_TRBYTES];
		} tmp;
	};
	const uint8_t *rho, *rhoprime, *key;
	int ret;
	static int tested = LC_DILITHIUM_TEST_INIT;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKNULL(pk, -EINVAL);
	CKNULL(sk, -EINVAL);

	lc_rng_check(&rng_ctx);

	dilithium_keypair_tester(&tested, "Dilithium Keygen C",
				 lc_dilithium_keypair_impl);

	/* Get randomness for rho, rhoprime and key */
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->seedbuf,
			      LC_DILITHIUM_SEEDBYTES));
	dilithium_print_buffer(ws->seedbuf, LC_DILITHIUM_SEEDBYTES,
			       "Keygen - Seed");

	lc_xof(lc_shake256, ws->seedbuf, LC_DILITHIUM_SEEDBYTES, ws->seedbuf,
	       sizeof(ws->seedbuf));

	rho = ws->seedbuf;
	dilithium_print_buffer(ws->seedbuf, LC_DILITHIUM_SEEDBYTES,
			       "Keygen - RHO");
	pack_pk_rho(pk, rho);
	pack_sk_rho(sk, rho);

	rhoprime = rho + LC_DILITHIUM_SEEDBYTES;
	dilithium_print_buffer(rhoprime, LC_DILITHIUM_CRHBYTES,
			       "Keygen - RHOPrime");

	/* Timecop: RHO' goes into the secret key */
	poison(rhoprime, LC_DILITHIUM_CRHBYTES);

	key = rhoprime + LC_DILITHIUM_CRHBYTES;
	dilithium_print_buffer(key, LC_DILITHIUM_SEEDBYTES, "Keygen - Key");

	/* Timecop: key goes into the secret key */
	poison(key, LC_DILITHIUM_SEEDBYTES);

	pack_sk_key(sk, key);

	/* Expand matrix */
	polyvec_matrix_expand(ws->mat, rho, ws->tmp.poly_uniform_buf);
	dilithium_print_polyvecl_k(
		ws->mat, "Keygen - MAT K x L x N matrix after ExpandA:");

	/* Sample short vectors s1 and s2 */

	polyvecl_uniform_eta(&ws->s1.s1, rhoprime, 0,
			     ws->tmp.poly_uniform_eta_buf);
	polyveck_uniform_eta(&ws->s2, rhoprime, LC_DILITHIUM_L,
			     ws->tmp.poly_uniform_eta_buf);

	/* Timecop: s1 and s2 are secret */
	poison(&ws->s1.s1, sizeof(polyvecl));
	poison(&ws->s2, sizeof(polyveck));

	dilithium_print_polyvecl(&ws->s1.s1,
				 "Keygen - S1 L x N matrix after ExpandS:");
	dilithium_print_polyveck(&ws->s2,
				 "Keygen - S2 K x N matrix after ExpandS:");

	pack_sk_s1(sk, &ws->s1.s1);
	pack_sk_s2(sk, &ws->s2);

	polyvecl_ntt(&ws->s1.s1hat);
	dilithium_print_polyvecl(&ws->s1.s1hat,
				 "Keygen - S1 L x N matrix after NTT:");

	polyvec_matrix_pointwise_montgomery(
		&ws->t1, ws->mat, &ws->s1.s1hat,
		&ws->tmp.polyvecl_pointwise_acc_montgomery_buf);
	dilithium_print_polyveck(&ws->t1,
				 "Keygen - T K x N matrix after A*NTT(s1):");

	polyveck_reduce(&ws->t1);
	dilithium_print_polyveck(
		&ws->t1, "Keygen - T K x N matrix reduce after A*NTT(s1):");

	polyveck_invntt_tomont(&ws->t1);
	dilithium_print_polyveck(&ws->t1,
				 "Keygen - T K x N matrix after NTT-1:");

	/* Add error vector s2 */
	polyveck_add(&ws->t1, &ws->t1, &ws->s2);
	dilithium_print_polyveck(&ws->t1,
				 "Keygen - T K x N matrix after add S2:");

	/* Extract t1 and write public key */
	polyveck_caddq(&ws->t1);
	dilithium_print_polyveck(&ws->t1, "Keygen - T K x N matrix caddq:");

	polyveck_power2round(&ws->t1, &ws->t0, &ws->t1);
	dilithium_print_polyveck(&ws->t0,
				 "Keygen - T0 K x N matrix after power2round:");
	dilithium_print_polyveck(&ws->t1,
				 "Keygen - T1 K x N matrix after power2round:");

	pack_sk_t0(sk, &ws->t0);
	pack_pk_t1(pk, &ws->t1);
	dilithium_print_buffer(pk->pk, LC_DILITHIUM_PUBLICKEYBYTES,
			       "Keygen - PK after pkEncode:");

	/* Compute H(rho, t1) and write secret key */
	lc_xof(lc_shake256, pk->pk, sizeof(pk->pk), ws->tmp.tr,
	       sizeof(ws->tmp.tr));
	dilithium_print_buffer(ws->tmp.tr, sizeof(ws->tmp.tr), "Keygen - TR:");
	pack_sk_tr(sk, ws->tmp.tr);

	dilithium_print_buffer(sk->sk, LC_DILITHIUM_SECRETKEYBYTES,
			       "Keygen - SK:");

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(pk->pk, sizeof(pk->pk));
	unpoison(sk->sk, sizeof(sk->sk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_keypair_from_seed_impl(struct lc_dilithium_pk *pk,
					       struct lc_dilithium_sk *sk,
					       const uint8_t *seed,
					       size_t seedlen)
{
	struct lc_static_rng_data s_rng_state;
	LC_STATIC_DRNG_ON_STACK(s_drng, &s_rng_state);
	int ret;

	if (seedlen != LC_DILITHIUM_SEEDBYTES)
		return -EINVAL;

	/* Set the seed that the key generation can pull via the RNG. */
	s_rng_state.seed = seed;
	s_rng_state.seedlen = seedlen;

	/* Generate the key pair from the seed. */
	CKINT(lc_dilithium_keypair_impl(pk, sk, &s_drng));

out:
	return ret;
}

static int lc_dilithium_sign_internal(struct lc_dilithium_sig *sig,
				      const struct lc_dilithium_sk *sk,
				      struct lc_hash_ctx *hash_ctx,
				      struct lc_rng_ctx *rng_ctx)
{
	struct workspace_sign {
		polyvecl mat[LC_DILITHIUM_K], s1, y, z;
		polyveck t0, s2, w1, w0, h;
		poly cp;
		uint8_t seedbuf[LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_RNDBYTES +
				LC_DILITHIUM_CRHBYTES];
		union {
			poly polyvecl_pointwise_acc_montgomery_buf;
			uint8_t poly_uniform_gamma1_buf
				[POLY_UNIFORM_GAMMA1_BYTES];
			uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
			uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
		} tmp;
	};
	unsigned int n;
	uint8_t *key, *mu, *rhoprime, *rnd;
	uint16_t nonce = 0;
	/* The first bytes of the key is rho. */
	const uint8_t *rho;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_sign, sizeof(uint64_t));

	key = ws->seedbuf;
	rnd = key + LC_DILITHIUM_SEEDBYTES;
	mu = rnd + LC_DILITHIUM_RNDBYTES;

	/* Re-use the ws->seedbuf, but making sure that mu is unchanged */
	BUILD_BUG_ON(LC_DILITHIUM_CRHBYTES >
		     LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_RNDBYTES);
	rhoprime = key;

	/* Timecop: key is secret */
	poison(rhoprime, LC_DILITHIUM_CRHBYTES);

	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
	lc_hash_final(hash_ctx, mu);
	dilithium_print_buffer(mu, LC_DILITHIUM_CRHBYTES, "Siggen - MU:");

	if (rng_ctx) {
		CKINT(lc_rng_generate(rng_ctx, NULL, 0, rnd,
				      LC_DILITHIUM_RNDBYTES));
	} else {
		memset(rnd, 0, LC_DILITHIUM_RNDBYTES);
	}
	dilithium_print_buffer(rnd, LC_DILITHIUM_RNDBYTES, "Siggen - RND:");

	/* Expand matrix and transform vectors */
	rho = sk->sk;
	polyvec_matrix_expand(ws->mat, rho, ws->tmp.poly_uniform_buf);
	dilithium_print_polyvecl_k(
		ws->mat, "Siggen - A K x L x N matrix after ExpandA:");

	unpack_sk_key(key, sk);

	/* Timecop: key is secret */
	poison(key, LC_DILITHIUM_SEEDBYTES);

	lc_xof(lc_shake256, key,
	       LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_RNDBYTES +
		       LC_DILITHIUM_CRHBYTES,
	       rhoprime, LC_DILITHIUM_CRHBYTES);
	dilithium_print_buffer(rhoprime, LC_DILITHIUM_CRHBYTES,
			       "Siggen - RHOPrime:");

	unpack_sk_s1(&ws->s1, sk);

	/* Timecop: s1 is secret */
	poison(&ws->s1, sizeof(polyvecl));

	polyvecl_ntt(&ws->s1);
	dilithium_print_polyvecl(&ws->s1,
				 "Siggen - S1 L x N matrix after NTT:");

	unpack_sk_s2(&ws->s2, sk);

	/* Timecop: s2 is secret */
	poison(&ws->s2, sizeof(polyveck));

	polyveck_ntt(&ws->s2);
	dilithium_print_polyveck(&ws->s2,
				 "Siggen - S2 K x N matrix after NTT:");

	unpack_sk_t0(&ws->t0, sk);
	polyveck_ntt(&ws->t0);
	dilithium_print_polyveck(&ws->t0,
				 "Siggen - T0 K x N matrix after NTT:");

rej:
	/* Sample intermediate vector y */
	polyvecl_uniform_gamma1(&ws->y, rhoprime, nonce++,
				ws->tmp.poly_uniform_gamma1_buf);
	dilithium_print_polyvecl(
		&ws->y,
		"Siggen - Y L x N matrix after ExpandMask - start of loop");

	/* Matrix-vector multiplication */
	ws->z = ws->y;
	polyvecl_ntt(&ws->z);

	/* Use the cp for this operation as it is not used here so far. */
	polyvec_matrix_pointwise_montgomery(&ws->w1, ws->mat, &ws->z, &ws->cp);
	polyveck_reduce(&ws->w1);
	polyveck_invntt_tomont(&ws->w1);
	dilithium_print_polyveck(&ws->w1,
				 "Siggen - W K x N matrix after NTT-1");

	/* Decompose w and call the random oracle */
	polyveck_caddq(&ws->w1);
	polyveck_decompose(&ws->w1, &ws->w0, &ws->w1);
	polyveck_pack_w1(sig->sig, &ws->w1);
	dilithium_print_buffer(sig->sig,
			       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES,
			       "Siggen - w1Encode of W1");

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, sig->sig,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CTILDE_BYTES);
	lc_hash_final(hash_ctx, sig->sig);
	dilithium_print_buffer(sig->sig, LC_DILITHIUM_CTILDE_BYTES,
			       "Siggen - ctilde");

	poly_challenge(&ws->cp, sig->sig, ws->tmp.poly_challenge_buf);
	dilithium_print_poly(&ws->cp, "Siggen - c after SampleInBall");
	poly_ntt(&ws->cp);
	dilithium_print_poly(&ws->cp, "Siggen - c after NTT");

	/* Compute z, reject if it reveals secret */
	polyvecl_pointwise_poly_montgomery(&ws->z, &ws->cp, &ws->s1);
	polyvecl_invntt_tomont(&ws->z);
	polyvecl_add(&ws->z, &ws->z, &ws->y);
	dilithium_print_polyvecl(&ws->z, "Siggen - z <- y + cs1");

	polyvecl_reduce(&ws->z);
	dilithium_print_polyvecl(&ws->z, "Siggen - z reduction");

	/* Timecop: the signature component z is not sensitive any more. */
	unpoison(&ws->z, sizeof(polyvecl));

	if (polyvecl_chknorm(&ws->z, LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA))
		goto rej;

	/*
	 * Check that subtracting cs2 does not change high bits of w and low
	 * bits do not reveal secret information.
	 */
	polyveck_pointwise_poly_montgomery(&ws->h, &ws->cp, &ws->s2);
	polyveck_invntt_tomont(&ws->h);
	polyveck_sub(&ws->w0, &ws->w0, &ws->h);
	polyveck_reduce(&ws->w0);

	/* Timecop: verification data w0 is not sensitive any more. */
	unpoison(&ws->w0, sizeof(polyveck));

	if (polyveck_chknorm(&ws->w0, LC_DILITHIUM_GAMMA2 - LC_DILITHIUM_BETA))
		goto rej;

	/* Compute hints for w1 */
	polyveck_pointwise_poly_montgomery(&ws->h, &ws->cp, &ws->t0);
	polyveck_invntt_tomont(&ws->h);
	polyveck_reduce(&ws->h);

	/* Timecop: the signature component h is not sensitive any more. */
	unpoison(&ws->h, sizeof(polyveck));

	if (polyveck_chknorm(&ws->h, LC_DILITHIUM_GAMMA2))
		goto rej;

	polyveck_add(&ws->w0, &ws->w0, &ws->h);

	n = polyveck_make_hint(&ws->h, &ws->w0, &ws->w1);
	if (n > LC_DILITHIUM_OMEGA)
		goto rej;

	/* Write signature */
	dilithium_print_buffer(sig->sig, LC_DILITHIUM_CTILDE_BYTES,
			       "Siggen - Ctilde:");
	dilithium_print_polyvecl(&ws->z, "Siggen - Z L x N matrix:");
	dilithium_print_polyveck(&ws->h, "Siggen - H K x N matrix:");

	pack_sig(sig, &ws->z, &ws->h);

	dilithium_print_buffer(sig->sig, LC_DILITHIUM_CRYPTO_BYTES,
			       "Siggen - Signature:");

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_sign_impl(struct lc_dilithium_sig *sig,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx)
{
	uint8_t tr[LC_DILITHIUM_TRBYTES];
	int ret = 0;
	static int tested = LC_DILITHIUM_TEST_INIT;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !m || !sk) {
		ret = -EINVAL;
		goto out;
	}

	dilithium_siggen_tester(&tested, "Dilithium Siggen C",
				lc_dilithium_sign_impl);

	dilithium_print_buffer(m, mlen, "Siggen - Message");

	unpack_sk_tr(tr, sk);

	/* Compute mu = CRH(tr, msg) */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
	lc_hash_update(hash_ctx, m, mlen);

	ret = lc_dilithium_sign_internal(sig, sk, hash_ctx, rng_ctx);

out:
	lc_hash_zero(hash_ctx);
	lc_memset_secure(tr, 0, sizeof(tr));
	return ret;
}

static int lc_dilithium_sign_init_impl(struct lc_hash_ctx *hash_ctx,
				       const struct lc_dilithium_sk *sk)
{
	uint8_t tr[LC_DILITHIUM_TRBYTES];
	static int tested = LC_DILITHIUM_TEST_INIT;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!hash_ctx || !sk)
		return -EINVAL;

	/* Require the use of SHAKE256 */
	if (hash_ctx->hash != lc_shake256)
		return -EOPNOTSUPP;

	dilithium_siggen_tester(&tested, "Dilithium Siggen C",
				lc_dilithium_sign_impl);

	unpack_sk_tr(tr, sk);

	/* Compute mu = CRH(tr, msg) */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
	lc_memset_secure(tr, 0, sizeof(tr));

	return 0;
}

static int lc_dilithium_sign_update_impl(struct lc_hash_ctx *hash_ctx,
					 const uint8_t *m, size_t mlen)
{
	if (!hash_ctx || !m)
		return -EINVAL;

	/* Compute CRH(tr, msg) */
	lc_hash_update(hash_ctx, m, mlen);

	return 0;
}

static int lc_dilithium_sign_final_impl(struct lc_dilithium_sig *sig,
					struct lc_hash_ctx *hash_ctx,
					const struct lc_dilithium_sk *sk,
					struct lc_rng_ctx *rng_ctx)
{
	int ret = 0;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !hash_ctx || !sk) {
		ret = -EINVAL;
		goto out;
	}

	ret = lc_dilithium_sign_internal(sig, sk, hash_ctx, rng_ctx);

out:
	lc_hash_zero(hash_ctx);
	return ret;
}

static int lc_dilithium_verify_internal(const struct lc_dilithium_sig *sig,
					const struct lc_dilithium_pk *pk,
					struct lc_hash_ctx *hash_ctx)
{
	struct workspace_verify {
		poly cp;
		polyvecl mat[LC_DILITHIUM_K];
		polyveck w1;
		union {
			polyveck t1, h;
			polyvecl z;
			uint8_t mu[LC_DILITHIUM_CRHBYTES];
			BUF_ALIGNED_UINT8_UINT64(LC_DILITHIUM_CTILDE_BYTES) c2;
		} buf;

		union {
			poly polyvecl_pointwise_acc_montgomery_buf;
			uint8_t buf[LC_DILITHIUM_K *
				    LC_DILITHIUM_POLYW1_PACKEDBYTES];
			uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
			uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
		} tmp;
	};
	/* The first bytes of the signature is c~ and thus contains c1. */
	const uint8_t *c1 = sig->sig;
	/* The first bytes of the key is rho. */
	const uint8_t *rho = pk->pk;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));

	polyvec_matrix_expand(ws->mat, rho, ws->tmp.poly_uniform_buf);

	unpack_sig_z(&ws->buf.z, sig);
	if (polyvecl_chknorm(&ws->buf.z,
			     LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA)) {
		ret = -EINVAL;
		goto out;
	}

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	poly_challenge(&ws->cp, c1, ws->tmp.poly_challenge_buf);

	polyvecl_ntt(&ws->buf.z);
	polyvec_matrix_pointwise_montgomery(
		&ws->w1, ws->mat, &ws->buf.z,
		&ws->tmp.polyvecl_pointwise_acc_montgomery_buf);

	poly_ntt(&ws->cp);

	unpack_pk_t1(&ws->buf.t1, pk);
	polyveck_shiftl(&ws->buf.t1);
	polyveck_ntt(&ws->buf.t1);
	polyveck_pointwise_poly_montgomery(&ws->buf.t1, &ws->cp, &ws->buf.t1);

	polyveck_sub(&ws->w1, &ws->w1, &ws->buf.t1);
	polyveck_reduce(&ws->w1);
	polyveck_invntt_tomont(&ws->w1);

	/* Reconstruct w1 */
	polyveck_caddq(&ws->w1);
	dilithium_print_polyveck(&ws->w1,
				 "Sigver - W K x N matrix before hint:");

	if (unpack_sig_h(&ws->buf.h, sig))
		return -EINVAL;
	dilithium_print_polyveck(&ws->buf.h, "Siggen - H K x N matrix:");

	polyveck_use_hint(&ws->w1, &ws->w1, &ws->buf.h);
	dilithium_print_polyveck(&ws->w1,
				 "Sigver - W K x N matrix after hint:");
	polyveck_pack_w1(ws->tmp.buf, &ws->w1);
	dilithium_print_buffer(ws->tmp.buf,
			       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES,
			       "Sigver - W after w1Encode");

	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
	lc_hash_final(hash_ctx, ws->buf.mu);

	/* Call random oracle and verify challenge */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, ws->buf.mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, ws->tmp.buf,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CTILDE_BYTES);
	lc_hash_final(hash_ctx, ws->buf.c2.coeffs);

	/* Signature verification operation */
	if (lc_memcmp_secure(c1, LC_DILITHIUM_CTILDE_BYTES, ws->buf.c2.coeffs,
			     LC_DILITHIUM_CTILDE_BYTES))
		ret = -EBADMSG;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_verify_impl(const struct lc_dilithium_sig *sig,
				    const uint8_t *m, size_t mlen,
				    const struct lc_dilithium_pk *pk)
{
	uint8_t tr[LC_DILITHIUM_TRBYTES];
	int ret = 0;
	static int tested = LC_DILITHIUM_TEST_INIT;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	if (!sig || !m || !pk) {
		ret = -EINVAL;
		goto out;
	}

	dilithium_sigver_tester(&tested, "Dilithium Sigver C",
				lc_dilithium_verify_impl);

	/* Make sure that ->mu is large enough for ->tr */
	BUILD_BUG_ON(LC_DILITHIUM_TRBYTES > LC_DILITHIUM_CRHBYTES);

	/* Compute CRH(H(rho, t1), msg) */
	lc_xof(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES, tr,
	       LC_DILITHIUM_TRBYTES);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
	lc_hash_update(hash_ctx, m, mlen);

	ret = lc_dilithium_verify_internal(sig, pk, hash_ctx);

out:
	lc_hash_zero(hash_ctx);
	lc_memset_secure(tr, 0, sizeof(tr));
	return ret;
}

static int lc_dilithium_verify_init_impl(struct lc_hash_ctx *hash_ctx,
					 const struct lc_dilithium_pk *pk)
{
	uint8_t mu[LC_DILITHIUM_TRBYTES];
	static int tested = LC_DILITHIUM_TEST_INIT;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!hash_ctx || !pk)
		return -EINVAL;

	/* Require the use of SHAKE256 */
	if (hash_ctx->hash != lc_shake256)
		return -EOPNOTSUPP;

	dilithium_sigver_tester(&tested, "Dilithium Sigver C",
				lc_dilithium_verify_impl);

	/* Compute CRH(H(rho, t1), msg) */
	lc_xof(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES, mu,
	       LC_DILITHIUM_TRBYTES);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_TRBYTES);
	lc_memset_secure(mu, 0, sizeof(mu));

	return 0;
}

static int lc_dilithium_verify_update_impl(struct lc_hash_ctx *hash_ctx,
					   const uint8_t *m, size_t mlen)
{
	if (!hash_ctx || !m)
		return -EINVAL;

	/* Compute CRH(H(rho, t1), msg) */
	lc_hash_update(hash_ctx, m, mlen);

	return 0;
}

static int lc_dilithium_verify_final_impl(const struct lc_dilithium_sig *sig,
					  struct lc_hash_ctx *hash_ctx,
					  const struct lc_dilithium_pk *pk)
{
	int ret = 0;

	if (!sig || !hash_ctx || !pk) {
		ret = -EINVAL;
		goto out;
	}

	ret = lc_dilithium_verify_internal(sig, pk, hash_ctx);

out:
	lc_hash_zero(hash_ctx);
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_SIGNATURE_IMPL_H */
