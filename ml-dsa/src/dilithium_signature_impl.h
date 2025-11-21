/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "dilithium_pack.h"
#include "dilithium_pct.h"
#include "dilithium_signature_impl.h"
#include "lc_hash.h"
#include "lc_memcmp_secure.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "signature_domain_separation.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "timecop.h"
#include "visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Enable this macro to report the rejection code paths taken with the
 * signature generation operation. When disabled, the compiler should
 * eliminate this code which means that the counting code is folded away.
 */
#undef REJECTION_TEST_SAMPLING

#define _WS_POLY_UNIFORM_BUF_SIZE                                              \
	(POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2)

#ifndef LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER
#error "LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER is not defined"
#endif

#define WS_POLY_UNIFORM_BUF_SIZE                                               \
	(_WS_POLY_UNIFORM_BUF_SIZE * LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER)

static int lc_dilithium_keypair_from_seed_impl(struct lc_dilithium_pk *pk,
					       struct lc_dilithium_sk *sk,
					       const uint8_t *seed,
					       size_t seedlen);

static int lc_dilithium_keypair_impl(struct lc_dilithium_pk *pk,
				     struct lc_dilithium_sk *sk,
				     struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		union {
			polyvecl s1, s1hat;
		} s1;
		union {
			polyvecl mat[LC_DILITHIUM_K];
			polyveck t0;
		} matrix;
		polyveck s2, t1;
		uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES +
				LC_DILITHIUM_CRHBYTES];
		union {
			poly polyvecl_pointwise_acc_montgomery_buf;
			uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
			uint8_t poly_uniform_eta_buf[POLY_UNIFORM_ETA_BYTES];
		} tmp;
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t dimension[2] = { LC_DILITHIUM_K, LC_DILITHIUM_L };
	const uint8_t *rho, *rhoprime, *key;
	polyveck *t1, *s2, *t0;
	polyvecl *s1;
	uint8_t *seckey, *pubkey, *tr;
	unsigned int i;
	int ret;
	LC_HASH_CTX_ON_STACK(shake256_ctx, lc_shake256);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKNULL(pk, -EINVAL);
	CKNULL(sk, -EINVAL);

	lc_rng_check(&rng_ctx);

	/* Get randomness for rho, rhoprime and key */
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->seedbuf,
			      LC_DILITHIUM_SEEDBYTES));

	CKINT(lc_hash_init(shake256_ctx));
	lc_hash_update(shake256_ctx, ws->seedbuf, LC_DILITHIUM_SEEDBYTES);
	lc_hash_update(shake256_ctx, dimension, sizeof(dimension));
	lc_hash_set_digestsize(shake256_ctx, sizeof(ws->seedbuf));
	lc_hash_final(shake256_ctx, ws->seedbuf);
	lc_hash_zero(shake256_ctx);

	rho = ws->seedbuf;
	pack_pk_rho(pk, rho);
	pack_sk_rho(sk, rho);

	/*
	 * Timecop: RHO' is a random number which is enlarged to sample the
	 * vectors S1 and S2 from. The sampling operation is not considered
	 * relevant for the side channel operation as (a) an attacker does not
	 * have access to the random number and (b) only the result after the
	 * sampling operation of S1 and S2 is released.
	 */
	rhoprime = rho + LC_DILITHIUM_SEEDBYTES;

	key = rhoprime + LC_DILITHIUM_CRHBYTES;

	/* Timecop: key goes into the secret key */
	poison(key, LC_DILITHIUM_SEEDBYTES);

	pack_sk_key(sk, key);

	/*
	 * Sample short vectors s1 and s2
	 *
	 * Do not implement the loop around L and K here, because ARMv8 has an
	 * accelerated implementation of this.
	 */
	polyvecl_uniform_eta(&ws->s1.s1, rhoprime, 0,
			     ws->tmp.poly_uniform_eta_buf);
	polyveck_uniform_eta(&ws->s2, rhoprime, LC_DILITHIUM_L,
			     ws->tmp.poly_uniform_eta_buf);

	/* Timecop: s1 and s2 are secret */
	poison(&ws->s1.s1, sizeof(polyvecl));
	poison(&ws->s2, sizeof(polyveck));

	pack_sk_s1(sk, &ws->s1.s1);
	pack_sk_s2(sk, &ws->s2);

	polyvecl_ntt(&ws->s1.s1hat);

	/* Expand matrix */
	polyvec_matrix_expand(ws->matrix.mat, rho, ws->tmp.poly_uniform_buf);

	s1 = &ws->s1.s1hat;
	s2 = &ws->s2;
	t1 = &ws->t1;
	t0 = &ws->matrix.t0;
	pubkey = pk->pk + LC_DILITHIUM_SEEDBYTES;
	seckey = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES +
		 LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES +
		 LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		polyvecl_pointwise_acc_montgomery(
			&t1->vec[i], &ws->matrix.mat[i], s1,
			&ws->tmp.polyvecl_pointwise_acc_montgomery_buf);

		poly_reduce(&t1->vec[i]);
		poly_invntt_tomont(&t1->vec[i]);

		/* Add error vector s2 */
		poly_add(&t1->vec[i], &t1->vec[i], &s2->vec[i]);

		/*
		* Reference: The following reduction is not present in the
		* reference implementation. Omitting this reduction requires the
		* output of the invntt to be small enough such that the addition
		* of s2 does not result in absolute values >= LC_DILITHIUM_Q.
		* While the C, x86_64, and AArch64 invntt implementations
		* produce small enough values for this to work out, it
		* complicates the bounds reasoning. Therefore, add an additional
		* reduction, allowing to relax the bounds requirements for the
		* invntt, especially when adding new invntt assembler
		* implementations.
		*/
#ifndef LC_DILITHIUM_INVNTT_SMALL
		poly_reduce(&t1->vec[i]);
#endif

		/* Extract t1 and write public key */
		poly_caddq(&t1->vec[i]);
		poly_power2round(&t1->vec[i], &t0->vec[i], &t1->vec[i]);

		polyt1_pack(pubkey + i * LC_DILITHIUM_POLYT1_PACKEDBYTES,
			    &t1->vec[i]);
		polyt0_pack(seckey + i * LC_DILITHIUM_POLYT0_PACKEDBYTES,
			    &t0->vec[i]);
	}

	/* Compute H(rho, t1) and write secret key */
	tr = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES;
	CKINT(lc_xof(lc_shake256, pk->pk, sizeof(pk->pk), tr,
		     LC_DILITHIUM_TRBYTES));

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(pk->pk, sizeof(pk->pk));
	unpoison(sk->sk, sizeof(sk->sk));

	CKINT(lc_dilithium_pct_fips(pk, sk));

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

static int lc_dilithium_sign_internal_ahat(struct lc_dilithium_sig *sig,
					   const struct lc_dilithium_sk *sk,
					   struct lc_dilithium_ctx *ctx,
					   struct lc_rng_ctx *rng_ctx)
{
	struct workspace_sign {
		polyvecl s1, y, z;
		polyveck t0, s2, w1, w0, h;
		poly cp;
		uint8_t seedbuf[LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_RNDBYTES +
				LC_DILITHIUM_CRHBYTES];
		union {
			uint8_t poly_uniform_gamma1_buf[WS_POLY_UNIFORM_BUF_SIZE];
			uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
		} tmp;
	};
	unsigned int n, i;
	uint8_t *key, *mu, *rhoprime, *rnd;
	const polyvecl *mat = ctx->ahat;
	const uint8_t *seckey;
	polyvecl *z, *s1, *y;
	polyveck *w0, *w1, *h, *s2, *t0;
	uint16_t nonce = 0;
	int ret = 0;
	struct lc_hash_ctx *hash_ctx = &ctx->dilithium_hash_ctx;
	uint8_t __maybe_unused rej_total = 0;
	LC_DECLARE_MEM(ws, struct workspace_sign, sizeof(uint64_t));

	/* AHat must be present at this time */
	CKNULL(mat, -EINVAL);

	w0 = &ws->w0;
	w1 = &ws->w1;

	key = ws->seedbuf;
	rnd = key + LC_DILITHIUM_SEEDBYTES;
	mu = rnd + LC_DILITHIUM_RNDBYTES;

	/*
	 * If the external mu is provided, use this verbatim, otherwise
	 * calculate the mu value.
	 */
	if (ctx->external_mu) {
		if (ctx->external_mu_len != LC_DILITHIUM_CRHBYTES)
			return -EINVAL;
		memcpy(mu, ctx->external_mu, LC_DILITHIUM_CRHBYTES);
	} else {
		/*
		 * Set the digestsize - for SHA512 this is a noop, for SHAKE256,
		 * it sets the value. The BUILD_BUG_ON is to check that the
		 * SHA-512 output size is identical to the expected length.
		 */
		BUILD_BUG_ON(LC_DILITHIUM_CRHBYTES != LC_SHA3_512_SIZE_DIGEST);
		lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
		lc_hash_final(hash_ctx, mu);
	}

	if (rng_ctx) {
		CKINT(lc_rng_generate(rng_ctx, NULL, 0, rnd,
				      LC_DILITHIUM_RNDBYTES));
	} else {
		memset(rnd, 0, LC_DILITHIUM_RNDBYTES);
	}

	unpack_sk_key(key, sk);

	/* Timecop: key is secret */
	poison(key, LC_DILITHIUM_SEEDBYTES);

	/* Re-use the ws->seedbuf, but making sure that mu is unchanged */
	BUILD_BUG_ON(LC_DILITHIUM_CRHBYTES >
		     LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_RNDBYTES);
	rhoprime = key;

	CKINT(lc_xof(lc_shake256, key,
		     LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_RNDBYTES +
			     LC_DILITHIUM_CRHBYTES,
		     rhoprime, LC_DILITHIUM_CRHBYTES));

	/*
	 * Timecop: RHO' is the hash of the secret value of key which is
	 * enlarged to sample the intermediate vector y from. Due to the hashing
	 * any side channel on RHO' cannot allow the deduction of the original
	 * key.
	 */
	unpoison(rhoprime, LC_DILITHIUM_CRHBYTES);

	s1 = &ws->s1;
	seckey = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES;
	for (i = 0; i < LC_DILITHIUM_L; ++i) {
		polyeta_unpack(&s1->vec[i],
			       seckey + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);

		/* Timecop: s1 is secret */
		poison(&s1->vec[i], sizeof(poly));
		poly_ntt(&s1->vec[i]);
	}

	s2 = &ws->s2;
	seckey = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES +
		 LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		polyeta_unpack(&s2->vec[i],
			       seckey + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);

		/* Timecop: s2 is secret */
		poison(&s2->vec[i], sizeof(poly));
		poly_ntt(&s2->vec[i]);
	}

	t0 = &ws->t0;
	seckey = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES +
		 LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES +
		 LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		polyt0_unpack(&t0->vec[i],
			      seckey + i * LC_DILITHIUM_POLYT0_PACKEDBYTES);
		poly_ntt(&t0->vec[i]);
	}

	z = &ws->z;
	y = &ws->y;
	h = &ws->h;

rej:
	/* Sample intermediate vector y */
	polyvecl_uniform_gamma1(&ws->y, rhoprime, nonce++,
				ws->tmp.poly_uniform_gamma1_buf);

	/* Timecop: s2 is secret */
	poison(&ws->y, sizeof(polyvecl));

	/* Matrix-vector multiplication */
	ws->z = ws->y;
	polyvecl_ntt(&ws->z);

	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		/*
		 * Use the cp for this operation as it is not used here so far.
		 */
		polyvecl_pointwise_acc_montgomery(&w1->vec[i], &mat[i], &ws->z,
						  &ws->cp);
		poly_reduce(&w1->vec[i]);
		poly_invntt_tomont(&w1->vec[i]);

		/* Decompose w and call the random oracle */
		poly_caddq(&w1->vec[i]);
		poly_decompose(&w1->vec[i], &w0->vec[i], &w1->vec[i]);

		/*
		 * Timecop: the signature component w1 is not sensitive any
		 * more.
		 */
		unpoison(&w1->vec[i], sizeof(poly));
		polyw1_pack(&sig->sig[i * LC_DILITHIUM_POLYW1_PACKEDBYTES],
			    &w1->vec[i]);
	}

	CKINT(lc_hash_init(hash_ctx));
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, sig->sig,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CTILDE_BYTES);
	lc_hash_final(hash_ctx, sig->sig);
	lc_hash_zero(hash_ctx);

	poly_challenge(&ws->cp, sig->sig, ws->tmp.poly_challenge_buf);
	poly_ntt(&ws->cp);

	/* Compute z, reject if it reveals secret */
	for (i = 0; i < LC_DILITHIUM_L; ++i) {
		poly_pointwise_montgomery(&z->vec[i], &ws->cp, &s1->vec[i]);
		poly_invntt_tomont(&z->vec[i]);
		poly_add(&z->vec[i], &z->vec[i], &y->vec[i]);
		poly_reduce(&z->vec[i]);

		/* Timecop: the signature component z is not sensitive any more. */
		unpoison(&z->vec[i], sizeof(poly));

		/* Siggen - z rejection */
		if (poly_chknorm(&z->vec[i],
				 LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA)) {
			rej_total |= 1 << 0;
			goto rej;
		}
	}

	/*
	 * Check that subtracting cs2 does not change high bits of w and low
	 * bits do not reveal secret information.
	 */
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		poly_pointwise_montgomery(&h->vec[i], &ws->cp, &s2->vec[i]);
		poly_invntt_tomont(&h->vec[i]);
		poly_sub(&w0->vec[i], &w0->vec[i], &h->vec[i]);
		poly_reduce(&w0->vec[i]);

		/* Timecop: verification data w0 is not sensitive any more. */
		unpoison(&w0->vec[i], sizeof(poly));

		/* Siggen - r0 rejection */
		if (poly_chknorm(&w0->vec[i],
				 LC_DILITHIUM_GAMMA2 - LC_DILITHIUM_BETA)) {
			rej_total |= 1 << 1;
			goto rej;
		}

		/* Compute hints for w1 */
		poly_pointwise_montgomery(&h->vec[i], &ws->cp, &t0->vec[i]);
		poly_invntt_tomont(&h->vec[i]);
		poly_reduce(&h->vec[i]);

		/*
		 * Timecop: the signature component h is not sensitive any more.
		 */
		unpoison(&h->vec[i], sizeof(poly));

		/* Siggen - ct0 rejection */
		if (poly_chknorm(&h->vec[i], LC_DILITHIUM_GAMMA2)) {
			rej_total |= 1 << 2;
			goto rej;
		}

		poly_add(&w0->vec[i], &w0->vec[i], &h->vec[i]);
	}

	n = polyveck_make_hint(&ws->h, &ws->w0, &ws->w1);
	if (n > LC_DILITHIUM_OMEGA) {
		rej_total |= 1 << 3;
		goto rej;
	}

	/* Write signature */
	pack_sig(sig, &ws->z, &ws->h);

out:
	LC_RELEASE_MEM(ws);
#ifdef REJECTION_TEST_SAMPLING
	return ret ? ret : rej_total;
#else
	return ret;
#endif
}

static int lc_dilithium_sign_internal_noahat(struct lc_dilithium_sig *sig,
					     const struct lc_dilithium_sk *sk,
					     struct lc_dilithium_ctx *ctx,
					     struct lc_rng_ctx *rng_ctx)
{
	struct workspace_sign {
		polyvecl mat[LC_DILITHIUM_K];
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	/* The first bytes of the key is rho. */
	const uint8_t *rho = sk->sk;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_sign, LC_DILITHIUM_AHAT_ALIGNMENT);

	polyvec_matrix_expand(ws->mat, rho, ws->poly_uniform_buf);

	/* Temporarily set the pointer */
	ctx->ahat = ws->mat;

	CKINT(lc_dilithium_sign_internal_ahat(sig, sk, ctx, rng_ctx));

out:
	ctx->ahat = NULL;
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_sk_expand_impl(const struct lc_dilithium_sk *sk,
				       struct lc_dilithium_ctx *ctx)
{
	struct workspace_sign {
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	/* The first bytes of the key is rho. */
	const uint8_t *rho = sk->sk;
	polyvecl *mat = ctx->ahat;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_sign, sizeof(uint64_t));

	/*
	 * The compile time sanity check links API header file with
	 * Dilithium-internal definitions.
	 *
	 * Runtime sanity check ensures that the allocated context has
	 * sufficient size (e.g. not that caller used, say,
	 * LC_DILITHIUM_44_CTX_ON_STACK_AHAT with a ML-DSA 65 or 87 key)
	 */
#if LC_DILITHIUM_MODE == 2
	BUILD_BUG_ON(LC_DILITHIUM_44_AHAT_SIZE !=
		     sizeof(polyvecl) * LC_DILITHIUM_K);
	if (ctx->ahat_size < LC_DILITHIUM_44_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#elif LC_DILITHIUM_MODE == 3
	BUILD_BUG_ON(LC_DILITHIUM_65_AHAT_SIZE !=
		     sizeof(polyvecl) * LC_DILITHIUM_K);
	if (ctx->ahat_size < LC_DILITHIUM_65_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#elif LC_DILITHIUM_MODE == 5
	BUILD_BUG_ON(LC_DILITHIUM_87_AHAT_SIZE !=
		     sizeof(polyvecl) * LC_DILITHIUM_K);
	if (ctx->ahat_size < LC_DILITHIUM_87_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#else
#error "Undefined LC_DILITHIUM_MODE"
#endif

	polyvec_matrix_expand(mat, rho, ws->poly_uniform_buf);

	ctx->ahat_expanded = 1;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_sign_internal(struct lc_dilithium_sig *sig,
				      const struct lc_dilithium_sk *sk,
				      struct lc_dilithium_ctx *ctx,
				      struct lc_rng_ctx *rng_ctx)
{
	int ret;

	if (!ctx->ahat)
		return lc_dilithium_sign_internal_noahat(sig, sk, ctx, rng_ctx);

	if (!ctx->ahat_expanded)
		CKINT(lc_dilithium_sk_expand_impl(sk, ctx));

	CKINT(lc_dilithium_sign_internal_ahat(sig, sk, ctx, rng_ctx));

out:
	return ret;
}

static int lc_dilithium_sign_ctx_impl(struct lc_dilithium_sig *sig,
				      struct lc_dilithium_ctx *ctx,
				      const uint8_t *m, size_t mlen,
				      const struct lc_dilithium_sk *sk,
				      struct lc_rng_ctx *rng_ctx)
{
	uint8_t tr[LC_DILITHIUM_TRBYTES];
	int ret = 0;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !sk || !ctx)
		return -EINVAL;
	/* Either the message or the external mu must be provided */
	if (!m && !ctx->external_mu)
		return -EINVAL;

	unpack_sk_tr(tr, sk);

	if (m) {
		/* Compute mu = CRH(tr, msg) */
		struct lc_hash_ctx *hash_ctx = &ctx->dilithium_hash_ctx;

		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);

		CKINT(signature_domain_separation(
			&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
			ctx->dilithium_prehash_type, ctx->userctx,
			ctx->userctxlen, m, mlen, ctx->randomizer,
			ctx->randomizerlen, LC_DILITHIUM_NIST_CATEGORY));
	}

	ret = lc_dilithium_sign_internal(sig, sk, ctx, rng_ctx);

out:
	lc_memset_secure(tr, 0, sizeof(tr));
	return ret;
}

static int lc_dilithium_sign_impl(struct lc_dilithium_sig *sig,
				  const uint8_t *m, size_t mlen,
				  const struct lc_dilithium_sk *sk,
				  struct lc_rng_ctx *rng_ctx)
{
	LC_DILITHIUM_CTX_ON_STACK(dilithium_ctx);
	int ret = lc_dilithium_sign_ctx_impl(sig, dilithium_ctx, m, mlen, sk,
					     rng_ctx);

	lc_dilithium_ctx_zero(dilithium_ctx);
	return ret;
}

static int lc_dilithium_sign_init_impl(struct lc_dilithium_ctx *ctx,
				       const struct lc_dilithium_sk *sk)
{
	uint8_t tr[LC_DILITHIUM_TRBYTES];
	struct lc_hash_ctx *hash_ctx;
	int ret;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!ctx || !sk)
		return -EINVAL;

	hash_ctx = &ctx->dilithium_hash_ctx;

	/* Require the use of SHAKE256 */
	if (hash_ctx->hash != lc_shake256)
		return -EOPNOTSUPP;

	unpack_sk_tr(tr, sk);

	/* Compute mu = CRH(tr, msg) */
	ret = lc_hash_init(hash_ctx);
	if (ret)
		return ret;
	lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
	lc_memset_secure(tr, 0, sizeof(tr));

	return signature_domain_separation(
		&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
		ctx->dilithium_prehash_type, ctx->userctx, ctx->userctxlen,
		NULL, 0, ctx->randomizer, ctx->randomizerlen,
		LC_DILITHIUM_NIST_CATEGORY);
}

static int lc_dilithium_sign_update_impl(struct lc_dilithium_ctx *ctx,
					 const uint8_t *m, size_t mlen)
{
	if (!ctx || !m)
		return -EINVAL;

	/* Compute CRH(tr, msg) */
	lc_hash_update(&ctx->dilithium_hash_ctx, m, mlen);

	return 0;
}

static int lc_dilithium_sign_final_impl(struct lc_dilithium_sig *sig,
					struct lc_dilithium_ctx *ctx,
					const struct lc_dilithium_sk *sk,
					struct lc_rng_ctx *rng_ctx)
{
	int ret = 0;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !ctx || !sk) {
		ret = -EINVAL;
		goto out;
	}

	ret = lc_dilithium_sign_internal(sig, sk, ctx, rng_ctx);

out:
	lc_dilithium_ctx_zero(ctx);
	return ret;
}

static int lc_dilithium_verify_internal_ahat(const struct lc_dilithium_sig *sig,
					     const struct lc_dilithium_pk *pk,
					     struct lc_dilithium_ctx *ctx)
{
	struct workspace_verify {
		union {
			poly cp;
		} matrix;
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
			uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
		} tmp;
	};
	/* The first bytes of the signature is c~ and thus contains c1. */
	const uint8_t *c1 = sig->sig;
	/* Skip c */
	const uint8_t *signature = sig->sig + LC_DILITHIUM_CTILDE_BYTES;
	const polyvecl *mat = ctx->ahat;
	polyvecl *z;
	polyveck *h, *t1, *w1;
	struct lc_hash_ctx *hash_ctx = &ctx->dilithium_hash_ctx;
	unsigned int i;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));

	/* AHat must be present at this time */
	CKNULL(mat, -EINVAL);

	z = &ws->buf.z;
	for (i = 0; i < LC_DILITHIUM_L; ++i) {
		polyz_unpack(&z->vec[i],
			     signature + i * LC_DILITHIUM_POLYZ_PACKEDBYTES);

		if (poly_chknorm(&z->vec[i],
				 LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA)) {
			ret = -EINVAL;
			goto out;
		}

		poly_ntt(&z->vec[i]);
	}

	polyvec_matrix_pointwise_montgomery(
		&ws->w1, mat, &ws->buf.z,
		&ws->tmp.polyvecl_pointwise_acc_montgomery_buf);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	poly_challenge(&ws->matrix.cp, c1, ws->tmp.poly_challenge_buf);
	poly_ntt(&ws->matrix.cp);

	unpack_pk_t1(&ws->buf.t1, pk);

	t1 = &ws->buf.t1;
	w1 = &ws->w1;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		poly_shiftl(&t1->vec[i]);
		poly_ntt(&t1->vec[i]);

		poly_pointwise_montgomery(&t1->vec[i], &ws->matrix.cp,
					  &t1->vec[i]);

		poly_sub(&w1->vec[i], &w1->vec[i], &t1->vec[i]);
		poly_reduce(&w1->vec[i]);
		poly_invntt_tomont(&w1->vec[i]);

		/* Reconstruct w1 */
		poly_caddq(&w1->vec[i]);
	}

	if (unpack_sig_h(&ws->buf.h, sig))
		return -EINVAL;

	h = &ws->buf.h;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		poly_use_hint(&w1->vec[i], &w1->vec[i], &h->vec[i]);
		polyw1_pack(&ws->tmp.buf[i * LC_DILITHIUM_POLYW1_PACKEDBYTES],
			    &w1->vec[i]);
	}

	if (ctx->external_mu) {
		if (ctx->external_mu_len != LC_DILITHIUM_CRHBYTES)
			return -EINVAL;

		/* Call random oracle and verify challenge */
		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, ctx->external_mu,
			       LC_DILITHIUM_CRHBYTES);
	} else {
		lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
		lc_hash_final(hash_ctx, ws->buf.mu);

		/* Call random oracle and verify challenge */
		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, ws->buf.mu, LC_DILITHIUM_CRHBYTES);
	}

	lc_hash_update(hash_ctx, ws->tmp.buf,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CTILDE_BYTES);
	lc_hash_final(hash_ctx, ws->buf.c2.coeffs);
	lc_hash_zero(hash_ctx);

	/* Signature verification operation */
	if (lc_memcmp_secure(c1, LC_DILITHIUM_CTILDE_BYTES, ws->buf.c2.coeffs,
			     LC_DILITHIUM_CTILDE_BYTES))
		ret = -EBADMSG;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int
lc_dilithium_verify_internal_noahat(const struct lc_dilithium_sig *sig,
				    const struct lc_dilithium_pk *pk,
				    struct lc_dilithium_ctx *ctx)
{
	struct workspace_verify {
		polyvecl mat[LC_DILITHIUM_K];
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	/* The first bytes of the key is rho. */
	const uint8_t *rho = pk->pk;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));

	polyvec_matrix_expand(ws->mat, rho, ws->poly_uniform_buf);

	/* Temporarily set the pointer */
	ctx->ahat = ws->mat;

	CKINT(lc_dilithium_verify_internal_ahat(sig, pk, ctx));

out:
	ctx->ahat = NULL;
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_pk_expand_impl(const struct lc_dilithium_pk *pk,
				       struct lc_dilithium_ctx *ctx)
{
	struct workspace_verify {
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
	};
	/* The first bytes of the key is rho. */
	const uint8_t *rho = pk->pk;
	polyvecl *mat = ctx->ahat;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, sizeof(uint64_t));

	/*
	 * Runtime sanity check ensures that the allocated context has
	 * sufficient size (e.g. not that caller used, say,
	 * LC_DILITHIUM_44_CTX_ON_STACK_AHAT with a ML-DSA 65 or 87 key)
	 */
#if LC_DILITHIUM_MODE == 2
	if (ctx->ahat_size < LC_DILITHIUM_44_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#elif LC_DILITHIUM_MODE == 3
	if (ctx->ahat_size < LC_DILITHIUM_65_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#elif LC_DILITHIUM_MODE == 5
	if (ctx->ahat_size < LC_DILITHIUM_87_AHAT_SIZE) {
		ret = -EOVERFLOW;
		goto out;
	}
#else
#error "Undefined LC_DILITHIUM_MODE"
#endif

	polyvec_matrix_expand(mat, rho, ws->poly_uniform_buf);
	ctx->ahat_expanded = 1;

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_verify_internal(const struct lc_dilithium_sig *sig,
					const struct lc_dilithium_pk *pk,
					struct lc_dilithium_ctx *ctx)
{
	int ret;

	if (!ctx->ahat)
		return lc_dilithium_verify_internal_noahat(sig, pk, ctx);

	if (!ctx->ahat_expanded)
		CKINT(lc_dilithium_pk_expand_impl(pk, ctx));

	CKINT(lc_dilithium_verify_internal_ahat(sig, pk, ctx));

out:
	return ret;
}

static int lc_dilithium_verify_ctx_impl(const struct lc_dilithium_sig *sig,
					struct lc_dilithium_ctx *ctx,
					const uint8_t *m, size_t mlen,
					const struct lc_dilithium_pk *pk)
{
	uint8_t tr[LC_DILITHIUM_TRBYTES];
	int ret = 0;

	if (!sig || !pk || !ctx)
		return -EINVAL;

	/* Either the message or the external mu must be provided */
	if (!m && !ctx->external_mu)
		return -EINVAL;

	/* Make sure that ->mu is large enough for ->tr */
	BUILD_BUG_ON(LC_DILITHIUM_TRBYTES > LC_DILITHIUM_CRHBYTES);

	/* Compute CRH(H(rho, t1), msg) */
	CKINT(lc_xof(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES, tr,
		     LC_DILITHIUM_TRBYTES));

	if (m) {
		struct lc_hash_ctx *hash_ctx = &ctx->dilithium_hash_ctx;

		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
		CKINT(signature_domain_separation(
			&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
			ctx->dilithium_prehash_type, ctx->userctx,
			ctx->userctxlen, m, mlen, ctx->randomizer,
			ctx->randomizerlen, LC_DILITHIUM_NIST_CATEGORY));
	}

	ret = lc_dilithium_verify_internal(sig, pk, ctx);

out:
	lc_memset_secure(tr, 0, sizeof(tr));
	return ret;
}

static int lc_dilithium_verify_impl(const struct lc_dilithium_sig *sig,
				    const uint8_t *m, size_t mlen,
				    const struct lc_dilithium_pk *pk)
{
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	int ret = lc_dilithium_verify_ctx_impl(sig, ctx, m, mlen, pk);

	lc_dilithium_ctx_zero(ctx);
	return ret;
}

static int lc_dilithium_verify_init_impl(struct lc_dilithium_ctx *ctx,
					 const struct lc_dilithium_pk *pk)
{
	uint8_t mu[LC_DILITHIUM_TRBYTES];
	struct lc_hash_ctx *hash_ctx;
	int ret;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!ctx || !pk)
		return -EINVAL;

	hash_ctx = &ctx->dilithium_hash_ctx;

	/* Require the use of SHAKE256 */
	if (hash_ctx->hash != lc_shake256)
		return -EOPNOTSUPP;

	/* Compute CRH(H(rho, t1), msg) */
	CKINT(lc_xof(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES, mu,
		     LC_DILITHIUM_TRBYTES));

	CKINT(lc_hash_init(hash_ctx));
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_TRBYTES);
	lc_memset_secure(mu, 0, sizeof(mu));

	CKINT(signature_domain_separation(
		&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
		ctx->dilithium_prehash_type, ctx->userctx, ctx->userctxlen,
		NULL, 0, ctx->randomizer, ctx->randomizerlen,
		LC_DILITHIUM_NIST_CATEGORY));

out:
	return ret;
}

static int lc_dilithium_verify_update_impl(struct lc_dilithium_ctx *ctx,
					   const uint8_t *m, size_t mlen)
{
	struct lc_hash_ctx *hash_ctx;

	if (!ctx || !m)
		return -EINVAL;

	/* Compute CRH(H(rho, t1), msg) */
	hash_ctx = &ctx->dilithium_hash_ctx;
	lc_hash_update(hash_ctx, m, mlen);

	return 0;
}

static int lc_dilithium_verify_final_impl(const struct lc_dilithium_sig *sig,
					  struct lc_dilithium_ctx *ctx,
					  const struct lc_dilithium_pk *pk)
{
	int ret = 0;

	if (!sig || !ctx || !pk) {
		ret = -EINVAL;
		goto out;
	}

	ret = lc_dilithium_verify_internal(sig, pk, ctx);

out:
	lc_dilithium_ctx_zero(ctx);
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_SIGNATURE_IMPL_H */
