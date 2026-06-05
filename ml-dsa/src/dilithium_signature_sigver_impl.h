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

#ifndef DILITHIUM_SIGNATURE_SIGVER_IMPL_H
#define DILITHIUM_SIGNATURE_SIGVER_IMPL_H

#include "alignment.h"
#include "build_bug_on.h"
#include "dilithium_type.h"
#include "dilithium_pack.h"
#include "dilithium_pct.h"
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

#define _WS_POLY_UNIFORM_BUF_SIZE                                              \
	(POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2)

#ifndef LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER
#error "LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER is not defined"
#endif

#define WS_POLY_UNIFORM_BUF_SIZE                                               \
	(_WS_POLY_UNIFORM_BUF_SIZE * LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER)

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

		/* Apply infinity norm check */
		poly_reduce(&z->vec[i]);
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

	if (unpack_sig_h(&ws->buf.h, sig)) {
		ret = -EINVAL;
		goto out;
	}

	h = &ws->buf.h;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		poly_use_hint(&w1->vec[i], &w1->vec[i], &h->vec[i]);
		polyw1_pack(&ws->tmp.buf[i * LC_DILITHIUM_POLYW1_PACKEDBYTES],
			    &w1->vec[i]);
	}

	if (ctx->external_mu) {
		if (ctx->external_mu_len != LC_DILITHIUM_CRHBYTES) {
			ret = -EINVAL;
			goto out;
		}

		/* Call random oracle and verify challenge */
		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, ctx->external_mu,
			       LC_DILITHIUM_CRHBYTES);
	} else {
		CKINT(lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES));
		lc_hash_final(hash_ctx, ws->buf.mu);

		/* Call random oracle and verify challenge */
		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, ws->buf.mu, LC_DILITHIUM_CRHBYTES);
	}

	lc_hash_update(hash_ctx, ws->tmp.buf,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	CKINT(lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CTILDE_BYTES));
	lc_hash_final(hash_ctx, ws->buf.c2.coeffs);
	lc_hash_zero(hash_ctx);

	/* Signature verification operation */
	CKRET_HARDENED(lc_memcmp_secure(c1, LC_DILITHIUM_CTILDE_BYTES,
					ws->buf.c2.coeffs,
					LC_DILITHIUM_CTILDE_BYTES),
		       -EBADMSG);

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

	/* A composite signature does not work with external-Mu */
	if (ctx->external_mu && ctx->composite_algorithm)
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
			ctx->userctxlen, m, mlen, ctx->composite_algorithm,
			LC_DILITHIUM_NIST_CATEGORY));
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
		NULL, 0, ctx->composite_algorithm, LC_DILITHIUM_NIST_CATEGORY));

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

#endif /* DILITHIUM_SIGNATURE_SIGVER_IMPL_H */
