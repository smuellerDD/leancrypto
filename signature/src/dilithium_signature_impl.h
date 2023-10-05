/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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
#include "dilithium_debug.h"
#include "dilithium_pack.h"
#include "dilithium_selftest.h"
#include "dilithium_signature_impl.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_memcmp_secure.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
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

struct workspace_sign {
	polyvecl mat[LC_DILITHIUM_K], s1, y, z;
	polyveck t0, s2, w1, w0, h;
	poly cp;
	/* See comment below - currently not needed */
	//poly polyvecl_pointwise_acc_montgomery_buf;
	/* See comment below - currently not needed */
	//uint8_t poly_uniform_gamma1_buf[POLY_UNIFORM_GAMMA1_BYTES];
	/* See comment below - currently not needed */
	//uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
	uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES +
			LC_DILITHIUM_RNDBYTES + 2 * LC_DILITHIUM_CRHBYTES];
	uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
};

struct workspace_verify {
	poly cp;
	poly polyvecl_pointwise_acc_montgomery_buf;
	polyvecl mat[LC_DILITHIUM_K], z;
	polyveck t1, w1, h;

#define WS_VERIFY_BUF_SIZE (LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES)
	uint8_t buf[WS_VERIFY_BUF_SIZE];

	/* See comment below - currently not needed */
	//uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
	uint8_t rho[LC_DILITHIUM_SEEDBYTES];
	uint8_t mu[LC_DILITHIUM_CRHBYTES];

#if (WS_VERIFY_BUF_SIZE < WS_POLY_UNIFORM_BUF_SIZE)
	/* See comment below - only needed if buf is too small */
	uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
#endif

	BUF_ALIGNED_UINT8_UINT64(LC_DILITHIUM_CTILDE_BYTES) c2;
};

static int lc_dilithium_keypair_impl(struct lc_dilithium_pk *pk,
				     struct lc_dilithium_sk *sk,
				     struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		polyvecl mat[LC_DILITHIUM_K];
		polyvecl s1, s1hat;
		polyveck s2, t1, t0;
		poly polyvecl_pointwise_acc_montgomery_buf;
		uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES +
				LC_DILITHIUM_CRHBYTES];
		uint8_t tr[LC_DILITHIUM_TRBYTES];
		/* See comment below - currently not needed */
		//uint8_t poly_uniform_eta_buf[POLY_UNIFORM_ETA_BYTES];
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	const uint8_t *rho, *rhoprime, *key;
	int ret;
	static int tested = LC_DILITHIUM_TEST_INIT;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (!pk || !sk || !rng_ctx) {
		ret = -EINVAL;
		goto out;
	}

	dilithium_keypair_tester(&tested, "Dilithium Keygen C",
				 lc_dilithium_keypair_impl);

	/* Get randomness for rho, rhoprime and key */
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->seedbuf,
			      LC_DILITHIUM_SEEDBYTES));
	dilithium_print_buffer(ws->seedbuf, LC_DILITHIUM_SEEDBYTES,
			       "Keygen - Seed");

	lc_shake(lc_shake256, ws->seedbuf, LC_DILITHIUM_SEEDBYTES, ws->seedbuf,
		 sizeof(ws->seedbuf));

	rho = ws->seedbuf;
	dilithium_print_buffer(ws->seedbuf, LC_DILITHIUM_SEEDBYTES,
			       "Keygen - RHO");

	rhoprime = rho + LC_DILITHIUM_SEEDBYTES;
	dilithium_print_buffer(rhoprime, LC_DILITHIUM_CRHBYTES,
			       "Keygen - RHOPrime");

	key = rhoprime + LC_DILITHIUM_CRHBYTES;
	dilithium_print_buffer(key, LC_DILITHIUM_SEEDBYTES, "Keygen - Key");

	/* Expand matrix */
	polyvec_matrix_expand(ws->mat, rho, ws->poly_uniform_buf);
	dilithium_print_polyvecl_k(
		ws->mat, "Keygen - MAT K x L x N matrix after ExpandA:");

	/* Sample short vectors s1 and s2 */

	/*
	 * Use the poly_uniform_buf for this operation as
	 * poly_uniform_eta_buf is smaller than poly_uniform_buf and has the
	 * same alignment
	 */
	BUILD_BUG_ON((POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2) <
		     POLY_UNIFORM_ETA_BYTES);
	polyvecl_uniform_eta(&ws->s1, rhoprime, 0, ws->poly_uniform_buf);
	polyveck_uniform_eta(&ws->s2, rhoprime, LC_DILITHIUM_L,
			     ws->poly_uniform_buf);
	dilithium_print_polyvecl(&ws->s1,
				 "Keygen - S1 L x N matrix after ExpandS:");
	dilithium_print_polyveck(&ws->s2,
				 "Keygen - S2 K x N matrix after ExpandS:");

	/* Matrix-vector multiplication */
	ws->s1hat = ws->s1;

	polyvecl_ntt(&ws->s1hat);
	dilithium_print_polyvecl(&ws->s1hat,
				 "Keygen - S1 L x N matrix after NTT:");

	polyvec_matrix_pointwise_montgomery(
		&ws->t1, ws->mat, &ws->s1hat,
		&ws->polyvecl_pointwise_acc_montgomery_buf);
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

	pack_pk(pk, rho, &ws->t1);
	dilithium_print_buffer(pk->pk, LC_DILITHIUM_PUBLICKEYBYTES,
			       "Keygen - PK after pkEncode:");

	/* Compute H(rho, t1) and write secret key */
	lc_shake(lc_shake256, pk->pk, sizeof(pk->pk), ws->tr, sizeof(ws->tr));
	dilithium_print_buffer(ws->tr, sizeof(ws->tr), "Keygen - TR:");

	pack_sk(sk, rho, ws->tr, key, &ws->t0, &ws->s1, &ws->s2);
	dilithium_print_buffer(sk->sk, LC_DILITHIUM_SECRETKEYBYTES,
			       "Keygen - SK:");

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_sign_internal(struct lc_dilithium_sig *sig,
				      struct workspace_sign *ws,
				      struct lc_hash_ctx *hash_ctx,
				      struct lc_rng_ctx *rng_ctx)
{
	unsigned int n;
	uint8_t *rho, *key, *mu, *rhoprime, *rnd;
	uint16_t nonce = 0;
	int ret = 0;

	rho = ws->seedbuf;
	/* Skip tr which is in rho + LC_DILITHIUM_SEEDBYTES; */
	key = rho + LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES;
	rnd = key + LC_DILITHIUM_SEEDBYTES;
	mu = rnd + LC_DILITHIUM_RNDBYTES;
	rhoprime = mu + LC_DILITHIUM_CRHBYTES;

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
	lc_shake(lc_shake256, key,
		 LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_RNDBYTES +
			 LC_DILITHIUM_CRHBYTES,
		 rhoprime, LC_DILITHIUM_CRHBYTES);
	dilithium_print_buffer(rhoprime, LC_DILITHIUM_CRHBYTES,
			       "Siggen - RHOPrime:");

	/* Expand matrix and transform vectors */
	polyvec_matrix_expand(ws->mat, rho, ws->poly_uniform_buf);
	dilithium_print_polyvecl_k(
		ws->mat, "Siggen - A K x L x N matrix after ExpandA:");

	polyvecl_ntt(&ws->s1);
	dilithium_print_polyvecl(&ws->s1,
				 "Siggen - S1 L x N matrix after NTT:");

	polyveck_ntt(&ws->s2);
	dilithium_print_polyveck(&ws->s2,
				 "Siggen - S2 K x N matrix after NTT:");

	polyveck_ntt(&ws->t0);
	dilithium_print_polyveck(&ws->t0,
				 "Siggen - T0 K x N matrix after NTT:");

rej:
	/* Sample intermediate vector y */
	/*
	 * Use the poly_uniform_buf for this operation as
	 * poly_uniform_gamma1_buf is smaller than poly_uniform_buf and has
	 * the same alignment.
	 */
	BUILD_BUG_ON((POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2) <
		     POLY_UNIFORM_GAMMA1_BYTES);
	polyvecl_uniform_gamma1(&ws->y, rhoprime, nonce++,
				ws->poly_uniform_buf);
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

	/*
	 * Use the poly_uniform_buf for this operation as
	 * poly_uniform_gamma1_buf is smaller than poly_uniform_buf and has
	 * the same alignment.
	 */
	BUILD_BUG_ON((POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2) <
		     POLY_UNIFORM_GAMMA1_BYTES);
	poly_challenge(&ws->cp, sig->sig, ws->poly_uniform_buf);
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
	if (polyveck_chknorm(&ws->w0, LC_DILITHIUM_GAMMA2 - LC_DILITHIUM_BETA))
		goto rej;

	/* Compute hints for w1 */
	polyveck_pointwise_poly_montgomery(&ws->h, &ws->cp, &ws->t0);
	polyveck_invntt_tomont(&ws->h);
	polyveck_reduce(&ws->h);
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
	return ret;
}

static int lc_dilithium_sign_impl(struct lc_dilithium_sig *sig,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx)
{
	uint8_t *rho, *tr, *key;
	int ret = 0;
	static int tested = LC_DILITHIUM_TEST_INIT;
	LC_DECLARE_MEM(ws, struct workspace_sign, sizeof(uint64_t));
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !m || !sk) {
		ret = -EINVAL;
		goto out;
	}

	dilithium_siggen_tester(&tested, "Dilithium Siggen C",
				lc_dilithium_sign_impl);

	dilithium_print_buffer(m, mlen, "Siggen - Message");

	rho = ws->seedbuf;
	tr = rho + LC_DILITHIUM_SEEDBYTES;
	key = tr + LC_DILITHIUM_TRBYTES;
	unpack_sk(rho, tr, key, &ws->t0, &ws->s1, &ws->s2, sk);

	/* Compute mu = CRH(tr, msg) */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
	lc_hash_update(hash_ctx, m, mlen);

	ret = lc_dilithium_sign_internal(sig, ws, hash_ctx, rng_ctx);

out:
	lc_hash_zero(hash_ctx);
	LC_RELEASE_MEM(ws);
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
	uint8_t *rho, *key;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_sign, sizeof(uint64_t));

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !hash_ctx || !sk) {
		ret = -EINVAL;
		goto out;
	}

	rho = ws->seedbuf;
	/* Skip tr which is in rho + LC_DILITHIUM_SEEDBYTES; */
	key = rho + LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES;
	unpack_sk_ex_tr(rho, key, &ws->t0, &ws->s1, &ws->s2, sk);

	ret = lc_dilithium_sign_internal(sig, ws, hash_ctx, rng_ctx);

out:
	lc_hash_zero(hash_ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_verify_internal(const struct lc_dilithium_sig *sig,
					const struct lc_dilithium_pk *pk,
					struct workspace_verify *ws,
					struct lc_hash_ctx *hash_ctx)
{
	/* The first bytes of the signature is c~ and thus contains c1. */
	const uint8_t *c1 = sig->sig;
	int ret = 0;

	unpack_pk(ws->rho, &ws->t1, pk);
	if (unpack_sig(&ws->z, &ws->h, sig))
		return -EINVAL;
	if (polyvecl_chknorm(&ws->z, LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA))
		return -EINVAL;

	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
	lc_hash_final(hash_ctx, ws->mu);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */

	/*
	 * Use the buf for this operation as poly_challenge_buf is smaller than
	 * buf and has the same alignment
	 */
	BUILD_BUG_ON(sizeof(ws->buf) < POLY_CHALLENGE_BYTES);
	poly_challenge(&ws->cp, c1, ws->buf);

	/*
	 * Use the buf for this operation as poly_uniform_buf is smaller than
	 * buf and has the same alignment
	 */
#if (WS_VERIFY_BUF_SIZE < WS_POLY_UNIFORM_BUF_SIZE)
	polyvec_matrix_expand(ws->mat, ws->rho, ws->poly_uniform_buf);
#else
	polyvec_matrix_expand(ws->mat, ws->rho, ws->buf);
#endif

	polyvecl_ntt(&ws->z);
	polyvec_matrix_pointwise_montgomery(
		&ws->w1, ws->mat, &ws->z,
		&ws->polyvecl_pointwise_acc_montgomery_buf);

	poly_ntt(&ws->cp);
	polyveck_shiftl(&ws->t1);
	polyveck_ntt(&ws->t1);
	polyveck_pointwise_poly_montgomery(&ws->t1, &ws->cp, &ws->t1);

	polyveck_sub(&ws->w1, &ws->w1, &ws->t1);
	polyveck_reduce(&ws->w1);
	polyveck_invntt_tomont(&ws->w1);

	/* Reconstruct w1 */
	polyveck_caddq(&ws->w1);
	dilithium_print_polyveck(&ws->h, "Siggen - H K x N matrix:");
	dilithium_print_polyveck(&ws->w1,
				 "Sigver - W K x N matrix before hint:");
	polyveck_use_hint(&ws->w1, &ws->w1, &ws->h);
	dilithium_print_polyveck(&ws->w1,
				 "Sigver - W K x N matrix after hint:");
	polyveck_pack_w1(ws->buf, &ws->w1);
	dilithium_print_buffer(ws->buf,
			       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES,
			       "Sigver - W after w1Encode");

	/* Call random oracle and verify challenge */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, ws->mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, ws->buf,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CTILDE_BYTES);
	lc_hash_final(hash_ctx, ws->c2.coeffs);

	/* Signature verification operation */
	if (lc_memcmp_secure(c1, LC_DILITHIUM_CTILDE_BYTES, ws->c2.coeffs,
			     LC_DILITHIUM_CTILDE_BYTES))
		ret = -EBADMSG;

	return ret;
}

static int lc_dilithium_verify_impl(const struct lc_dilithium_sig *sig,
				    const uint8_t *m, size_t mlen,
				    const struct lc_dilithium_pk *pk)
{
	int ret = 0;
	static int tested = LC_DILITHIUM_TEST_INIT;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));
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
	lc_shake(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES, ws->mu,
		 LC_DILITHIUM_TRBYTES);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, ws->mu, LC_DILITHIUM_TRBYTES);
	lc_hash_update(hash_ctx, m, mlen);

	ret = lc_dilithium_verify_internal(sig, pk, ws, hash_ctx);

out:
	lc_hash_zero(hash_ctx);
	LC_RELEASE_MEM(ws);
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
	lc_shake(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES, mu,
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

static int lc_dilithium_verify_final_impl(struct lc_dilithium_sig *sig,
					  struct lc_hash_ctx *hash_ctx,
					  const struct lc_dilithium_pk *pk)
{
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));

	if (!sig || !hash_ctx || !pk) {
		ret = -EINVAL;
		goto out;
	}

	ret = lc_dilithium_verify_internal(sig, pk, ws, hash_ctx);

out:
	lc_hash_zero(hash_ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_SIGNATURE_IMPL_H */
