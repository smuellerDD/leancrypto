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
#include "dilithium_signature_siggen_avx2.h"
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

static int lc_dilithium_sign_avx2_internal(struct lc_dilithium_sig *sig,
					   struct lc_dilithium_ctx *ctx,
					   const struct lc_dilithium_sk *sk,
					   struct lc_rng_ctx *rng_ctx)
{
	struct workspace_sign {
		union {
			BUF_ALIGNED_UINT8_M256I(REJ_UNIFORM_BUFLEN + 8)
			poly_uniform_4x_buf[4];
			BUF_ALIGNED_UINT8_M256I(POLY_UNIFORM_GAMMA1_NBLOCKS *
							LC_SHAKE_256_SIZE_BLOCK +
						14)
			poly_uniform_gamma1[4];
		} buf;
		uint8_t seedbuf[LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_RNDBYTES +
				2 * LC_DILITHIUM_CRHBYTES];
		uint8_t hintbuf[LC_DILITHIUM_N];
		polyvecl mat[LC_DILITHIUM_K], s1, z;
		polyveck t0, s2, w1;
		poly c, tmp;
		union {
			polyvecl y;
			polyveck w0;
		} tmpv;
		keccakx4_state keccak_state;
	};
	unsigned int i, n, pos;
	uint8_t *rho, *key, *mu, *rhoprime, *rnd;
	uint8_t *hint = sig->sig + LC_DILITHIUM_CTILDE_BYTES +
			LC_DILITHIUM_L * LC_DILITHIUM_POLYZ_PACKEDBYTES;
	uint64_t nonce = 0;
	int ret = 0;
	struct lc_hash_ctx *hash_ctx = &ctx->dilithium_hash_ctx;
	LC_DECLARE_MEM(ws, struct workspace_sign, 32);

	/* Skip tr which is in rho + LC_DILITHIUM_SEEDBYTES; */
	key = ws->seedbuf;
	rnd = key + LC_DILITHIUM_SEEDBYTES;
	mu = rnd + LC_DILITHIUM_RNDBYTES;
	rhoprime = mu + LC_DILITHIUM_CRHBYTES;

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

		/* Compute CRH(tr, msg) */
		lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
		lc_hash_final(hash_ctx, mu);
	}

	if (rng_ctx) {
		CKINT(lc_rng_generate(rng_ctx, NULL, 0, rnd,
				      LC_DILITHIUM_RNDBYTES));
	} else {
		memset(rnd, 0, LC_DILITHIUM_RNDBYTES);
	}

	unpack_sk_key_avx2(key, sk);

	/* Timecop: key is secret */
	poison(key, LC_DILITHIUM_SEEDBYTES);

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

	/* Expand matrix and transform vectors */
	rho = ws->seedbuf;
	unpack_sk_rho_avx2(rho, sk);
	polyvec_matrix_expand(ws->mat, rho, ws->buf.poly_uniform_4x_buf,
			      &ws->keccak_state, &ws->z);
	unpack_sk_s1_avx2(&ws->s1, sk);

	/* Timecop: s1 is secret */
	poison(&ws->s1, sizeof(polyvecl));

	unpack_sk_s2_avx2(&ws->s2, sk);

	/* Timecop: s2 is secret */
	poison(&ws->s2, sizeof(polyveck));

	unpack_sk_t0_avx2(&ws->t0, sk);
	polyvecl_ntt_avx(&ws->s1);
	polyveck_ntt_avx(&ws->s2);
	polyveck_ntt_avx(&ws->t0);

rej:
	/* Sample intermediate vector y */
#if LC_DILITHIUM_L == 7
	poly_uniform_gamma1_4x_avx(&ws->z.vec[0], &ws->z.vec[1], &ws->z.vec[2],
				   &ws->z.vec[3], rhoprime, (uint16_t)nonce,
				   (uint16_t)(nonce + 1), (uint16_t)(nonce + 2),
				   (uint16_t)(nonce + 3),
				   ws->buf.poly_uniform_gamma1,
				   &ws->keccak_state);
	poly_uniform_gamma1_4x_avx(&ws->z.vec[4], &ws->z.vec[5], &ws->z.vec[6],
				   &ws->tmp, rhoprime, (uint16_t)(nonce + 4),
				   (uint16_t)(nonce + 5), (uint16_t)(nonce + 6),
				   0, ws->buf.poly_uniform_gamma1,
				   &ws->keccak_state);
	nonce += 7;
#elif LC_DILITHIUM_L == 5
	poly_uniform_gamma1_4x_avx(&ws->z.vec[0], &ws->z.vec[1], &ws->z.vec[2],
				   &ws->z.vec[3], rhoprime, (uint16_t)nonce,
				   (uint16_t)(nonce + 1), (uint16_t)(nonce + 2),
				   (uint16_t)(nonce + 3),
				   ws->buf.poly_uniform_gamma1,
				   &ws->keccak_state);
	poly_uniform_gamma1(&ws->z.vec[4], rhoprime, (uint16_t)(nonce + 4),
			    ws->buf.poly_uniform_gamma1);
	nonce += 5;
#else
#error "Undefined LC_DILITHIUM_K"
#endif

	/* Timecop: s2 is secret */
	poison(&ws->tmpv.y, sizeof(polyvecl));

	/* Matrix-vector product */
	ws->tmpv.y = ws->z;

	polyvecl_ntt_avx(&ws->tmpv.y);
	polyvec_matrix_pointwise_montgomery_avx(&ws->w1, ws->mat, &ws->tmpv.y);
	polyveck_invntt_tomont_avx(&ws->w1);

	/* Decompose w and call the random oracle */
	polyveck_caddq_avx(&ws->w1);
	polyveck_decompose_avx(&ws->w1, &ws->tmpv.w0, &ws->w1);

	polyveck_pack_w1_avx(sig->sig, &ws->w1);

	CKINT(lc_hash_init(hash_ctx));
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, sig->sig,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CTILDE_BYTES);
	lc_hash_final(hash_ctx, sig->sig);
	lc_hash_zero(hash_ctx);

	poly_challenge_avx(&ws->c, sig->sig);
	poly_ntt_avx(&ws->c);

	/* Compute z, reject if it reveals secret */
	for (i = 0; i < LC_DILITHIUM_L; i++) {
		poly_pointwise_montgomery_avx(&ws->tmp, &ws->c, &ws->s1.vec[i]);
		poly_invntt_tomont_avx(&ws->tmp);
		poly_add_avx(&ws->z.vec[i], &ws->z.vec[i], &ws->tmp);
		poly_reduce_avx(&ws->z.vec[i]);

		/*
		 * Timecop: the signature component z is not sensitive any
		 * more.
		 */
		unpoison(&ws->z.vec[i], sizeof(poly));

		/* Siggen - z rejection */
		if (poly_chknorm_avx(&ws->z.vec[i],
				     LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA)) {
			goto rej;
		}
	}

	/* Zero hint vector in signature */
	pos = 0;
	memset(hint, 0, LC_DILITHIUM_OMEGA);

	for (i = 0; i < LC_DILITHIUM_K; i++) {
		/*
		 * Check that subtracting cs2 does not change high bits of
		 * w and low bits do not reveal secret information
		 */
		poly_pointwise_montgomery_avx(&ws->tmp, &ws->c, &ws->s2.vec[i]);
		poly_invntt_tomont_avx(&ws->tmp);
		poly_sub_avx(&ws->tmpv.w0.vec[i], &ws->tmpv.w0.vec[i],
			     &ws->tmp);
		poly_reduce_avx(&ws->tmpv.w0.vec[i]);

		/* Timecop: verification data w0 is not sensitive any more. */
		unpoison(&ws->tmpv.w0.vec[i], sizeof(poly));

		/* Siggen - r0 rejection */
		if (poly_chknorm_avx(&ws->tmpv.w0.vec[i],
				     LC_DILITHIUM_GAMMA2 - LC_DILITHIUM_BETA))
			goto rej;

		/* Compute hints */
		poly_pointwise_montgomery_avx(&ws->tmp, &ws->c, &ws->t0.vec[i]);
		poly_invntt_tomont_avx(&ws->tmp);
		poly_reduce_avx(&ws->tmp);

		/* Timecop: the hint information is not sensitive any more. */
		unpoison(&ws->tmp, sizeof(poly));

		/* Siggen - ct0 rejection */
		if (poly_chknorm_avx(&ws->tmp, LC_DILITHIUM_GAMMA2))
			goto rej;

		poly_add_avx(&ws->tmpv.w0.vec[i], &ws->tmpv.w0.vec[i],
			     &ws->tmp);
		n = poly_make_hint_avx(ws->hintbuf, &ws->tmpv.w0.vec[i],
				       &ws->w1.vec[i]);

		/* Siggen - h rejection */
		if (pos + n > LC_DILITHIUM_OMEGA)
			goto rej;

		/* Store hints in signature */
		memcpy(&hint[pos], ws->hintbuf, n);
		pos = pos + n;
		hint[LC_DILITHIUM_OMEGA + i] = (uint8_t)pos;
	}

	/* Pack z into signature */
	for (i = 0; i < LC_DILITHIUM_L; i++)
		polyz_pack_avx(sig->sig + LC_DILITHIUM_CTILDE_BYTES +
				       i * LC_DILITHIUM_POLYZ_PACKEDBYTES,
			       &ws->z.vec[i]);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_ctx_avx2,
		      struct lc_dilithium_sig *sig,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_sk *sk,
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

	/* A composite signature does not work with external-Mu */
	if (ctx->external_mu && ctx->composite_algorithm)
		return -EINVAL;

	unpack_sk_tr_avx2(tr, sk);

	if (m) {
		/* Compute mu = CRH(tr, msg) */
		struct lc_hash_ctx *hash_ctx = &ctx->dilithium_hash_ctx;

		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, tr, LC_DILITHIUM_TRBYTES);
		CKINT(signature_domain_separation(
			&ctx->dilithium_hash_ctx, ctx->ml_dsa_internal,
			ctx->dilithium_prehash_type, ctx->userctx,
			ctx->userctxlen, m, mlen, ctx->composite_algorithm,
			LC_DILITHIUM_NIST_CATEGORY));
	}

	ret = lc_dilithium_sign_avx2_internal(sig, ctx, sk, rng_ctx);

out:
	lc_memset_secure(tr, 0, sizeof(tr));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_avx2, struct lc_dilithium_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	LC_DILITHIUM_CTX_ON_STACK(ctx);
	int ret = lc_dilithium_sign_ctx_avx2(sig, ctx, m, mlen, sk, rng_ctx);

	lc_dilithium_ctx_zero(ctx);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_init_avx2,
		      struct lc_dilithium_ctx *ctx,
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

	unpack_sk_tr_avx2(tr, sk);

	/* Compute mu = CRH(tr, msg) */
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

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_update_avx2,
		      struct lc_dilithium_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	struct lc_hash_ctx *hash_ctx;

	if (!ctx || !m)
		return -EINVAL;

	hash_ctx = &ctx->dilithium_hash_ctx;

	/* Compute CRH(tr, msg) */
	lc_hash_update(hash_ctx, m, mlen);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_sign_final_avx2,
		      struct lc_dilithium_sig *sig,
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

	ret = lc_dilithium_sign_avx2_internal(sig, ctx, sk, rng_ctx);

out:
	lc_dilithium_ctx_zero(ctx);
	return ret;
}
