/*
 * Copyright (C) 2023 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include "dilithium_internal.h"
#include "ed448_composite.h"
#include "ext_headers_internal.h"
#include "helper.h"
#include "lc_ed448.h"
#include "lc_sha512.h"
#include "ret_checkers.h"
#include "signature_domain_separation.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed448_sign_ctx,
		      struct lc_dilithium_ed448_sig *sig,
		      struct lc_dilithium_ed448_ctx *ctx, const uint8_t *m,
		      size_t mlen, const struct lc_dilithium_ed448_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKINT(lc_dilithium_ed448_sign_init(ctx, sk));
	CKINT(lc_dilithium_ed448_sign_update(ctx, m, mlen));
	CKINT(lc_dilithium_ed448_sign_final(sig, ctx, sk, rng_ctx));

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
