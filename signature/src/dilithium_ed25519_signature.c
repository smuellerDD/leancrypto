/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
#include "lc_ed25519.h"
#include "lc_sha512.h"
#include "ret_checkers.h"
#include "visibility.h"

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
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	CKINT(lc_dilithium_sign_ctx(&sig->sig, &ctx->dilithium_ctx, m, mlen,
				    &sk->sk, rng_ctx));

	lc_hash(lc_sha512, m, mlen, digest);
	CKINT(lc_ed25519ph_sign(&sig->sig_ed25519, digest, sizeof(digest),
				&sk->sk_ed25519, rng_ctx));

out:
	lc_memset_secure(digest, 0, sizeof(digest));
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

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_init,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_sk *sk)
{
	struct lc_hash_ctx *ed25519_hash_ctx;
	int ret;

	CKNULL(ctx, -EINVAL);
	CKNULL(sk, -EINVAL);

	ed25519_hash_ctx = &ctx->ed25519_hash_ctx;

	/* Require the use of SHA-512 */
	if (ed25519_hash_ctx->hash != lc_sha512)
		return -EOPNOTSUPP;

	CKINT(lc_dilithium_sign_init(&ctx->dilithium_ctx, &sk->sk));

	/* ED25519: Only perform hashing part */
	lc_hash_init(ed25519_hash_ctx);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_update,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	struct lc_hash_ctx *ed25519_hash_ctx;
	int ret;

	CKNULL(ctx, -EINVAL);

	ed25519_hash_ctx = &ctx->ed25519_hash_ctx;

	CKINT(lc_dilithium_sign_update(&ctx->dilithium_ctx, m, mlen));

	/* ED25519: Only perform hashing part */
	lc_hash_update(ed25519_hash_ctx, m, mlen);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_sign_final,
		      struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	struct lc_hash_ctx *ed25519_hash_ctx;
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	ed25519_hash_ctx = &ctx->ed25519_hash_ctx;

	CKINT(lc_dilithium_sign_final(&sig->sig, &ctx->dilithium_ctx, &sk->sk,
				      rng_ctx));

	lc_hash_final(ed25519_hash_ctx, digest);
	CKINT(lc_ed25519ph_sign(&sig->sig_ed25519, digest, sizeof(digest),
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
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	int retd, rete, ret = 0;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	retd = lc_dilithium_verify_ctx(&sig->sig, &ctx->dilithium_ctx, m, mlen,
				       &pk->pk);

	lc_hash(lc_sha512, m, mlen, digest);
	rete = lc_ed25519ph_verify(&sig->sig_ed25519, digest, sizeof(digest),
				   &pk->pk_ed25519);
	lc_memset_secure(digest, 0, sizeof(digest));

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
	struct lc_hash_ctx *ed25519_hash_ctx;
	int ret;

	CKNULL(ctx, -EINVAL);
	CKNULL(pk, -EINVAL);

	ed25519_hash_ctx = &ctx->ed25519_hash_ctx;

	/* Require the use of SHA-512 */
	if (ed25519_hash_ctx->hash != lc_sha512)
		return -EOPNOTSUPP;

	CKINT(lc_dilithium_verify_init(&ctx->dilithium_ctx, &pk->pk));

	/* ED25519: Only perform hashing part */
	lc_hash_init(ed25519_hash_ctx);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_update,
		      struct lc_dilithium_ed25519_ctx *ctx, const uint8_t *m,
		      size_t mlen)
{
	struct lc_hash_ctx *ed25519_hash_ctx;
	int ret;

	CKNULL(ctx, -EINVAL);

	ed25519_hash_ctx = &ctx->ed25519_hash_ctx;

	CKINT(lc_dilithium_verify_update(&ctx->dilithium_ctx, m, mlen));

	/* ED25519: Only perform hashing part */
	lc_hash_update(ed25519_hash_ctx, m, mlen);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_final,
		      const struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	struct lc_hash_ctx *ed25519_hash_ctx;
	int retd, rete, ret = 0;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);
	CKNULL(ctx, -EINVAL);

	ed25519_hash_ctx = &ctx->ed25519_hash_ctx;

	retd = lc_dilithium_verify_final(&sig->sig, &ctx->dilithium_ctx,
					 &pk->pk);

	lc_hash_final(ed25519_hash_ctx, digest);
	rete = lc_ed25519ph_verify(&sig->sig_ed25519, digest, sizeof(digest),
				   &pk->pk_ed25519);
	lc_memset_secure(digest, 0, sizeof(digest));

out:
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
	LC_SHA512_CTX((&(out_ctx)->ed25519_hash_ctx));

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
