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

#include "alignment_x86.h"
#include "build_bug_on.h"
#include "dilithium_type.h"
#include "dilithium_pack_avx2.h"
#include "dilithium_poly_avx2.h"
#include "dilithium_poly_common.h"
#include "dilithium_polyvec_avx2.h"
#include "dilithium_pct.h"
#include "dilithium_signature_sigver_avx2.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "lc_memcmp_secure.h"
#include "signature_domain_separation.h"
#include "static_rng.h"
#include "ret_checkers.h"
#include "shake_4x_avx2.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "timecop.h"
#include "visibility.h"

static int lc_dilithium_verify_avx2_internal(const struct lc_dilithium_sig *sig,
					     const struct lc_dilithium_pk *pk,
					     struct lc_dilithium_ctx *ctx)
{
	struct workspace_verify {
		/* polyw1_pack writes additional 14 bytes */
		BUF_ALIGNED_UINT8_M256I(
			LC_DILITHIUM_K *LC_DILITHIUM_POLYW1_PACKEDBYTES + 14)
		buf;
		BUF_ALIGNED_UINT8_M256I(REJ_UNIFORM_BUFLEN + 8)
		poly_uniform_4x_buf[4];
		uint8_t mu[LC_DILITHIUM_CRHBYTES];
		polyvecl rowbuf[2];
		polyvecl z;
		poly c, w1, h;
		keccakx4_state keccak_state;
	};
	const uint8_t *hint = sig->sig + LC_DILITHIUM_CTILDE_BYTES +
			      LC_DILITHIUM_L * LC_DILITHIUM_POLYZ_PACKEDBYTES;
	polyvecl *row;
	const uint8_t *signature = sig->sig + LC_DILITHIUM_CTILDE_BYTES;
	struct lc_hash_ctx *hash_ctx = &ctx->dilithium_hash_ctx;
	unsigned int i, j, pos = 0;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace_verify, 32);

	row = ws->rowbuf;

	/* Expand challenge */
	poly_challenge_avx(&ws->c, sig->sig);
	poly_ntt_avx(&ws->c);

	/* Unpack z; shortness follows from unpacking */
	for (i = 0; i < LC_DILITHIUM_L; i++) {
		polyz_unpack_avx(&ws->z.vec[i],
				 signature +
				 i * LC_DILITHIUM_POLYZ_PACKEDBYTES);

		/* Apply inifity norm check */
		poly_reduce_avx(&ws->z.vec[i]);
		if (poly_chknorm_avx(&ws->z.vec[i],
				     LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA)) {
			ret = -EINVAL;
			goto out;
		}

		poly_ntt_avx(&ws->z.vec[i]);
	}

	for (i = 0; i < LC_DILITHIUM_K; i++) {
		polyvec_matrix_expand_row(&row, ws->rowbuf, pk->pk, i,
					  ws->poly_uniform_4x_buf,
					  &ws->keccak_state);

		/* Compute i-th row of Az - c2^Dt1 */
		polyvecl_pointwise_acc_montgomery_avx(&ws->w1, row, &ws->z);

		polyt1_unpack_avx(&ws->h,
				  pk->pk + LC_DILITHIUM_SEEDBYTES +
					  i * LC_DILITHIUM_POLYT1_PACKEDBYTES);
		poly_shiftl_avx(&ws->h);
		poly_ntt_avx(&ws->h);
		poly_pointwise_montgomery_avx(&ws->h, &ws->c, &ws->h);

		poly_sub_avx(&ws->w1, &ws->w1, &ws->h);
		poly_reduce_avx(&ws->w1);
		poly_invntt_tomont_avx(&ws->w1);

		/* Get hint polynomial and reconstruct w1 */
		memset(ws->h.coeffs, 0, sizeof(poly));
		if (hint[LC_DILITHIUM_OMEGA + i] < pos ||
		    hint[LC_DILITHIUM_OMEGA + i] > LC_DILITHIUM_OMEGA) {
			ret = -1;
			goto out;
		}

		for (j = pos; j < hint[LC_DILITHIUM_OMEGA + i]; ++j) {
			/* Coefficients are ordered for strong unforgeability */
			if (j > pos && hint[j] <= hint[j - 1]) {
				ret = -1;
				goto out;
			}
			ws->h.coeffs[hint[j]] = 1;
		}
		pos = hint[LC_DILITHIUM_OMEGA + i];

		poly_caddq_avx(&ws->w1);
		poly_use_hint_avx(&ws->w1, &ws->w1, &ws->h);
		polyw1_pack_avx(ws->buf.coeffs +
					i * LC_DILITHIUM_POLYW1_PACKEDBYTES,
				&ws->w1);
	}

	/* Extra indices are zero for strong unforgeability */
	for (j = pos; j < LC_DILITHIUM_OMEGA; ++j) {
		if (hint[j]) {
			ret = -1;
			goto out;
		}
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
		lc_hash_final(hash_ctx, ws->mu);

		/* Call random oracle and verify challenge */
		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, ws->mu, LC_DILITHIUM_CRHBYTES);
	}

	lc_hash_update(hash_ctx, ws->buf.coeffs,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CTILDE_BYTES);
	lc_hash_final(hash_ctx, ws->buf.coeffs);
	lc_hash_zero(hash_ctx);

	/* Signature verification operation */
	CKRET_HARDENED(lc_memcmp_secure(ws->buf.coeffs,
					LC_DILITHIUM_CTILDE_BYTES, sig->sig,
					LC_DILITHIUM_CTILDE_BYTES), -EBADMSG);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_ctx_avx2,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
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

	ret = lc_dilithium_verify_avx2_internal(sig, pk, ctx);

out:
	lc_memset_secure(tr, 0, sizeof(tr));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_avx2,
		      const struct lc_dilithium_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_pk *pk)
{
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	int ret = lc_dilithium_verify_ctx_avx2(sig, ctx, m, mlen, pk);

	lc_dilithium_ctx_zero(ctx);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_init_avx2,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	uint8_t tr[LC_DILITHIUM_TRBYTES];
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
	CKINT(lc_xof(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES, tr,
		     LC_DILITHIUM_TRBYTES));

	CKINT(lc_hash_init(hash_ctx));
	lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
	lc_memset_secure(tr, 0, sizeof(tr));

	CKINT(signature_domain_separation(
		&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
		ctx->dilithium_prehash_type, ctx->userctx, ctx->userctxlen,
		NULL, 0, ctx->composite_algorithm, LC_DILITHIUM_NIST_CATEGORY));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_update_avx2,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	struct lc_hash_ctx *hash_ctx;

	if (!ctx || !m)
		return -EINVAL;

	hash_ctx = &ctx->dilithium_hash_ctx;

	/* Compute CRH(H(rho, t1), msg) */
	lc_hash_update(hash_ctx, m, mlen);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_verify_final_avx2,
		      const struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx,
		      const struct lc_dilithium_pk *pk)
{
	int ret = 0;

	if (!sig || !ctx || !pk) {
		ret = -EINVAL;
		goto out;
	}

	ret = lc_dilithium_verify_avx2_internal(sig, pk, ctx);

out:
	lc_dilithium_ctx_zero(ctx);
	return ret;
}
