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
#include "ed25519_composite.h"
#include "helper.h"
#include "lc_ed25519.h"
#include "lc_sha512.h"
#include "ret_checkers.h"
#include "signature_domain_separation.h"
#include "visibility.h"

/* OIDs from https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-04.html */
/* id-HashMLDSA44-Ed25519-SHA512 */
static const uint8_t hashmldsa44_ed25519_sha512_oid_der[] __maybe_unused = {
	0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86,
	0xFA, 0x6B, 0x50, 0x08, 0x01, 0x2A
};

/* id-HashMLDSA65-Ed25519-SHA512 */
static const uint8_t hashmldsa65_ed25519_sha512_oid_der[] __maybe_unused = {
	0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86,
	0xFA, 0x6B, 0x50, 0x08, 0x01, 0x32
};

/* id-HashMLDSA87-Ed448-SHA512 */
static const uint8_t hashmldsa87_ed448_sha512_oid_der[] __maybe_unused = {
	0x06, 0x0B, 0x60, 0x86, 0x48, 0x01, 0x86,
	0xFA, 0x6B, 0x50, 0x08, 0x01, 0x35
};

//TODO we cannot include lc_dilithium.h
void lc_dilithium_ed25519_ctx_hash(struct lc_dilithium_ed25519_ctx *ctx,
				   const struct lc_hash *hash);
void lc_dilithium_ed25519_ctx_userctx(struct lc_dilithium_ed25519_ctx *ctx,
				      const uint8_t *userctx,
				      size_t userctxlen);

/*
 * https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-03.html
 * section 4.3.1
 */
static int
composite_hash_signature_domain_separation(struct lc_hash_ctx *hash_ctx,
					   struct lc_dilithium_ed25519_ctx *ctx)
{
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	struct lc_dilithium_ctx *dilithium_ctx = &ctx->dilithium_ctx;
	int ret = 0;

	if (dilithium_ctx->userctxlen > 255)
		return -EINVAL;

	/*
	 * Set the digestsize - for SHA512 this is a noop, for SHAKE256, it
	 * sets the value. The BUILD_BUG_ON is to check that the SHA-512
	 * output size is identical to the expected length.
	 */
	lc_hash_set_digestsize(hash_ctx, LC_SHA512_SIZE_DIGEST);

	/* Get PH(M) */
	lc_hash_final(hash_ctx, digest);

	/*
	 * Create M'
	 */
	lc_hash_init(hash_ctx);

#if LC_DILITHIUM_MODE == 2
	/* Set Domain */
	lc_hash_update(hash_ctx, hashmldsa44_ed25519_sha512_oid_der,
		       sizeof(hashmldsa44_ed25519_sha512_oid_der));

	/* Set len(ctx) */
	lc_hash_update(hash_ctx, (uint8_t *)&dilithium_ctx->userctxlen, 1);

	/* Set ctx */
	lc_hash_update(hash_ctx, dilithium_ctx->userctx,
		       dilithium_ctx->userctxlen);

	/* Set hash OID */
	CKINT(signature_ph_oids(hash_ctx, dilithium_ctx->dilithium_prehash_type,
				sizeof(digest), LC_DILITHIUM_NIST_CATEGORY));

	/* Set context for ML-DSA */
	lc_dilithium_ed25519_ctx_userctx(
		ctx, hashmldsa44_ed25519_sha512_oid_der,
		sizeof(hashmldsa44_ed25519_sha512_oid_der));
#elif LC_DILITHIUM_MODE == 3
	lc_hash_update(hash_ctx, hashmldsa65_ed25519_sha512_oid_der,
		       sizeof(hashmldsa65_ed25519_sha512_oid_der));
	lc_hash_update(hash_ctx, (uint8_t *)&dilithium_ctx->userctxlen, 1);
	lc_hash_update(hash_ctx, dilithium_ctx->userctx,
		       dilithium_ctx->userctxlen);

	CKINT(signature_ph_oids(hash_ctx, dilithium_ctx->dilithium_prehash_type,
				sizeof(digest), LC_DILITHIUM_NIST_CATEGORY));

	/* Set context for ML-DSA */
	lc_dilithium_ed25519_ctx_userctx(
		ctx, hashmldsa65_ed25519_sha512_oid_der,
		sizeof(hashmldsa65_ed25519_sha512_oid_der));
#elif LC_DILITHIUM_MODE == 5
	/*
	 * Yes, this call is for HashML-DSA ED25519 but it uses the OID
	 * for HashML-DSA ED448. As there is no definition for the used
	 * signature type, this code applies the defined context.
	 */
	lc_hash_update(hash_ctx, hashmldsa87_ed448_sha512_oid_der,
		       sizeof(hashmldsa87_ed448_sha512_oid_der));
	lc_hash_update(hash_ctx, (uint8_t *)&dilithium_ctx->userctxlen, 1);
	lc_hash_update(hash_ctx, dilithium_ctx->userctx,
		       dilithium_ctx->userctxlen);

	CKINT(signature_ph_oids(hash_ctx, dilithium_ctx->dilithium_prehash_type,
				sizeof(digest), LC_DILITHIUM_NIST_CATEGORY));

	/* Set context for ML-DSA */
	lc_dilithium_ed25519_ctx_userctx(
		ctx, hashmldsa87_ed448_sha512_oid_der,
		sizeof(hashmldsa87_ed448_sha512_oid_der));
#else
#error "Undefined LC_DILITHIUM_MODE"
#endif

	/* Ensure the next call is ML-DSA */
	lc_dilithium_ed25519_ctx_hash(ctx, NULL);

	/* Set PH(M) */
	lc_hash_update(hash_ctx, digest, sizeof(digest));

out:
	lc_memset_secure(digest, 0, sizeof(digest));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_keypair,
		      struct lc_dilithium_ed25519_pk *pk,
		      struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKNULL(sk, -EINVAL);
	CKNULL(pk, -EINVAL);

	CKINT(lc_dilithium_keypair(&pk->pk, &sk->sk, rng_ctx));
	CKINT(lc_ed25519_keypair(&pk->pk_ed25519, &sk->sk_ed25519, rng_ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_ctx,
		      struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	dilithium_ctx->composite_ml_dsa = LC_DILITHIUM_NIST_CATEGORY;

	CKINT(lc_dilithium_sign_ctx(&sig->sig, &ctx->dilithium_ctx, m, mlen,
				    &sk->sk, rng_ctx));

	CKINT(lc_ed25519_sign_ctx(&sig->sig_ed25519, m, mlen, &sk->sk_ed25519,
				  rng_ctx, ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign,
		      struct lc_dilithium_ed25519_sig *sig, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	LC_DILITHIUM_ED25519_CTX_ON_STACK(ctx);
	int ret = lc_dilithium_ed25519_sign_ctx(sig, ctx, m, mlen, sk, rng_ctx);

	lc_dilithium_ed25519_ctx_zero(ctx);
	return ret;
}

static int
lc_dilithium_ed25519_common_init(struct lc_dilithium_ed25519_ctx *ctx)
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

	lc_hash_init(hash_ctx);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_init,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_sk *sk)
{
	(void)sk;

	return lc_dilithium_ed25519_common_init(ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_update,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
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

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_final,
		      struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_sk *sk,
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
	hash_ctx = &dilithium_ctx->dilithium_hash_ctx;

	CKINT(composite_hash_signature_domain_separation(hash_ctx, ctx));

	/* Calculate M' */
	lc_hash_set_digestsize(hash_ctx, sizeof(digest));
	lc_hash_final(hash_ctx, digest);

	/*
	 * Now, re-initialize the hash context as SHAKE256 context to comply
	 * with the LC_DILITHIUM_CTX_ON_STACK
	 */
	LC_DILITHIUM_CTX_INIT_HASH(&ctx->dilithium_ctx);

	/* Sign M' */
	CKINT(lc_dilithium_sign_ctx(&sig->sig, &ctx->dilithium_ctx, digest,
				    sizeof(digest), &sk->sk, rng_ctx));

	/* Clear out the hash context */
	lc_dilithium_ed25519_ctx_userctx(ctx, NULL, 0);

	CKINT(lc_ed25519_sign(&sig->sig_ed25519, digest, sizeof(digest),
			      &sk->sk_ed25519, rng_ctx));

out:
	lc_memset_secure(digest, 0, sizeof(digest));
	return ret;
}

static inline int lc_dilithium_ed25519_verify_check(int retd, int rete)
{
	if (rete == -EBADMSG || retd == -EBADMSG)
		return -EBADMSG;
	else if (rete == -EINVAL || retd == -EINVAL)
		return -EINVAL;
	else
		return rete | retd;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_ctx,
		      const struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed25519_pk *pk)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	int retd, rete, ret = 0;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	dilithium_ctx->composite_ml_dsa = LC_DILITHIUM_NIST_CATEGORY;

	retd = lc_dilithium_verify_ctx(&sig->sig, &ctx->dilithium_ctx, m, mlen,
				       &pk->pk);

	rete = lc_ed25519_verify_ctx(&sig->sig_ed25519, m, mlen,
				     &pk->pk_ed25519, ctx);

out:
	return ret ? ret : lc_dilithium_ed25519_verify_check(retd, rete);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify,
		      const struct lc_dilithium_ed25519_sig *sig,
		      const uint8_t *m, size_t mlen,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	LC_DILITHIUM_ED25519_CTX_ON_STACK(ctx);
	int ret = lc_dilithium_ed25519_verify_ctx(sig, ctx, m, mlen, pk);

	lc_dilithium_ed25519_ctx_zero(ctx);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_init,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	(void)pk;

	return lc_dilithium_ed25519_common_init(ctx);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_update,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	return lc_dilithium_ed25519_sign_update(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_final,
		      const struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	struct lc_hash_ctx *hash_ctx;
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	int retd, rete, ret = 0;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	hash_ctx = &dilithium_ctx->dilithium_hash_ctx;

	CKINT(composite_hash_signature_domain_separation(hash_ctx, ctx));

	/* Calculate M' */
	lc_hash_set_digestsize(hash_ctx, sizeof(digest));
	lc_hash_final(hash_ctx, digest);

	/*
	 * Now, re-initialize the hash context as SHAKE256 context to comply
	 * with the LC_DILITHIUM_CTX_ON_STACK
	 */
	LC_DILITHIUM_CTX_INIT_HASH(&ctx->dilithium_ctx);

	/* Verify M' */
	retd = lc_dilithium_verify_ctx(&sig->sig, &ctx->dilithium_ctx, digest,
				       sizeof(digest), &pk->pk);

	/* Clear out the hash context */
	lc_dilithium_ed25519_ctx_userctx(ctx, NULL, 0);

	rete = lc_ed25519_verify(&sig->sig_ed25519, digest, sizeof(digest),
				 &pk->pk_ed25519);

out:
	lc_memset_secure(digest, 0, sizeof(digest));
	return ret ? ret : lc_dilithium_ed25519_verify_check(retd, rete);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_ctx_alloc,
		      struct lc_dilithium_ed25519_ctx **ctx)
{
	struct lc_dilithium_ed25519_ctx *out_ctx = NULL;
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = lc_alloc_aligned((void **)&out_ctx, LC_HASH_COMMON_ALIGNMENT,
			       LC_DILITHIUM_ED25519_CTX_SIZE);
	if (ret)
		return -ret;

	LC_SHAKE_256_CTX((&(out_ctx)->dilithium_ctx.dilithium_hash_ctx));

	*ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ed25519_ctx_zero_free,
		      struct lc_dilithium_ed25519_ctx *ctx)
{
	if (!ctx)
		return;

	lc_dilithium_ed25519_ctx_zero(ctx);
	lc_free(ctx);
}
