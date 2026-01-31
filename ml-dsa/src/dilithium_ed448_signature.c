/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "dilithium_type.h"
#include "ed448_composite.h"
#include "ext_headers_internal.h"
#include "helper.h"
#include "lc_ed448.h"
#include "lc_sha512.h"
#include "ret_checkers.h"
#include "signature_domain_separation.h"
#include "visibility.h"

//TODO we cannot include lc_dilithium.h
void lc_dilithium_ed448_ctx_hash(struct lc_dilithium_ed448_ctx *ctx,
				 const struct lc_hash *hash);
void lc_dilithium_ed448_ctx_userctx(struct lc_dilithium_ed448_ctx *ctx,
				    const uint8_t *userctx, size_t userctxlen);

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_keypair,
		      struct lc_dilithium_ed448_pk *pk,
		      struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKNULL(sk, -EINVAL);
	CKNULL(pk, -EINVAL);

	CKINT(lc_dilithium_keypair(&pk->pk, &sk->sk, rng_ctx));
	CKINT(lc_ed448_keypair(&pk->pk_ed448, &sk->sk_ed448, rng_ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_ctx,
		      struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *ph_m,
		      size_t ph_m_len, const struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	dilithium_ctx->nist_category = LC_DILITHIUM_NIST_CATEGORY;

	CKINT(lc_dilithium_sign_ctx(&sig->sig, &ctx->dilithium_ctx, ph_m,
				    ph_m_len, &sk->sk, rng_ctx));

	CKINT(lc_ed448_sign_ctx(&sig->sig_ed448, ph_m, ph_m_len, &sk->sk_ed448,
				rng_ctx, ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign,
		      struct lc_dilithium_ed448_sig *sig, const uint8_t *ph_m,
		      size_t ph_m_len, const struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	LC_DILITHIUM_ED448_CTX_ON_STACK(ctx);
	int ret = lc_dilithium_ed448_sign_ctx(sig, ctx, ph_m, ph_m_len, sk,
					      rng_ctx);

	lc_dilithium_ed448_ctx_zero(ctx);
	return ret;
}

static int lc_dilithium_ed448_common_init(struct lc_dilithium_ed448_ctx *ctx)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	struct lc_hash_ctx *hash_ctx;
	int ret = 0;

	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	hash_ctx = &dilithium_ctx->dilithium_hash_ctx;

	if (!dilithium_ctx->dilithium_prehash_type) {
		dilithium_ctx->dilithium_prehash_type = lc_shake256;

		/*
		 * No re-initialization of the hash_ctx necessary as
		 * LC_DILITHIUM_CTX_ON_STACK initialized it to lc_shake256
		 */
	} else {
		if ((dilithium_ctx->dilithium_prehash_type != lc_shake256) &&
		    (dilithium_ctx->dilithium_prehash_type != lc_sha3_512)
#ifdef LC_SHA2_512
		    && (dilithium_ctx->dilithium_prehash_type != lc_sha512)
#endif
		)
			return -EOPNOTSUPP;

		/* Re-purpose the hash context */
		LC_HASH_SET_CTX(hash_ctx,
				dilithium_ctx->dilithium_prehash_type);
		lc_hash_zero(hash_ctx);
	}

	CKINT(lc_hash_init(hash_ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_init,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_sk *sk)
{
	(void)sk;

	return lc_dilithium_ed448_common_init(ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_update,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	struct lc_hash_ctx *hash_ctx;
	int ret = 0;

	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	hash_ctx = &dilithium_ctx->dilithium_hash_ctx;
	lc_hash_update(hash_ctx, m, mlen);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_final,
		      struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	struct lc_hash_ctx *hash_ctx;
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	dilithium_ctx->nist_category = LC_DILITHIUM_NIST_CATEGORY;
	hash_ctx = &dilithium_ctx->dilithium_hash_ctx;

	/* Calculate PH(M) */
	CKINT(lc_hash_set_digestsize(hash_ctx, sizeof(digest)));
	lc_hash_final(hash_ctx, digest);

	/*
	 * Now, re-initialize the hash context as SHAKE256 context to comply
	 * with the LC_DILITHIUM_CTX_ON_STACK
	 */
	LC_DILITHIUM_CTX_INIT_HASH(&ctx->dilithium_ctx);

	/* Sign PH(M) */
	CKINT(lc_dilithium_sign_ctx(&sig->sig, &ctx->dilithium_ctx, digest,
				    sizeof(digest), &sk->sk, rng_ctx));

	CKINT(lc_ed448_sign_ctx(&sig->sig_ed448, digest, sizeof(digest),
				&sk->sk_ed448, rng_ctx, ctx));

out:
	lc_memset_secure(digest, 0, sizeof(digest));
	return ret;
}

static inline int lc_dilithium_ed448_verify_check(int retd, int rete)
{
	if (rete == -EBADMSG || retd == -EBADMSG)
		return -EBADMSG;
	else if (rete == -EINVAL || retd == -EINVAL)
		return -EINVAL;
	else
		return rete | retd;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_ctx,
		      const struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *ph_m,
		      size_t ph_m_len, const struct lc_dilithium_ed448_pk *pk)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	int retd, rete, ret = 0;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	dilithium_ctx->nist_category = LC_DILITHIUM_NIST_CATEGORY;

	retd = lc_dilithium_verify_ctx(&sig->sig, &ctx->dilithium_ctx, ph_m,
				       ph_m_len, &pk->pk);

	rete = lc_ed448_verify_ctx(&sig->sig_ed448, ph_m, ph_m_len,
				   &pk->pk_ed448, ctx);

out:
	return ret ? ret : lc_dilithium_ed448_verify_check(retd, rete);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify,
		      const struct lc_dilithium_ed448_sig *sig,
		      const uint8_t *ph_m, size_t ph_m_len,
		      const struct lc_dilithium_ed448_pk *pk)
{
	LC_DILITHIUM_ED448_CTX_ON_STACK(ctx);
	int ret = lc_dilithium_ed448_verify_ctx(sig, ctx, ph_m, ph_m_len, pk);

	lc_dilithium_ed448_ctx_zero(ctx);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_init,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_pk *pk)
{
	(void)pk;

	return lc_dilithium_ed448_common_init(ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_update,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_ed448_sign_update(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_verify_final,
		      const struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx,
		      const struct lc_dilithium_ed448_pk *pk)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	struct lc_hash_ctx *hash_ctx;
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	int retd, rete, ret = 0;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	dilithium_ctx->nist_category = LC_DILITHIUM_NIST_CATEGORY;
	hash_ctx = &dilithium_ctx->dilithium_hash_ctx;

	/* Calculate PH(M) */
	CKINT(lc_hash_set_digestsize(hash_ctx, sizeof(digest)));
	lc_hash_final(hash_ctx, digest);

	/*
	 * Now, re-initialize the hash context as SHAKE256 context to comply
	 * with the LC_DILITHIUM_CTX_ON_STACK
	 */
	LC_DILITHIUM_CTX_INIT_HASH(&ctx->dilithium_ctx);

	/* Verify PH(M) */
	retd = lc_dilithium_verify_ctx(&sig->sig, &ctx->dilithium_ctx, digest,
				       sizeof(digest), &pk->pk);

	rete = lc_ed448_verify_ctx(&sig->sig_ed448, digest, sizeof(digest),
				   &pk->pk_ed448, ctx);

out:
	lc_memset_secure(digest, 0, sizeof(digest));
	return ret ? ret : lc_dilithium_ed448_verify_check(retd, rete);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_ctx_alloc,
		      struct lc_dilithium_ed448_ctx **ctx)
{
	struct lc_dilithium_ed448_ctx *out_ctx = NULL;
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = lc_alloc_aligned((void **)&out_ctx, LC_HASH_COMMON_ALIGNMENT,
			       LC_DILITHIUM_ED448_CTX_SIZE);
	if (ret)
		return -ret;

	LC_DILITHIUM_ED448_SET_CTX(out_ctx);

	LC_SHAKE_256_CTX((&(out_ctx)->dilithium_ctx.dilithium_hash_ctx));

	*ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed448_ctx_zero_free,
		      struct lc_dilithium_ed448_ctx *ctx)
{
	if (!ctx)
		return;

	lc_dilithium_ed448_ctx_zero(ctx);
	lc_free(ctx);
}
