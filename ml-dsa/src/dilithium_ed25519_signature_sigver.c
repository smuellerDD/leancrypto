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
#include "ed25519_composite.h"
#include "ext_headers_internal.h"
#include "helper.h"
#include "lc_ed25519.h"
#include "lc_sha512.h"
#include "ret_checkers.h"
#include "signature_domain_separation.h"
#include "visibility.h"

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
	int ret;

	CKINT(lc_dilithium_ed25519_verify_init(ctx, pk));
	CKINT(lc_dilithium_ed25519_verify_update(ctx, m, mlen));
	CKINT(lc_dilithium_ed25519_verify_final(sig, ctx, pk));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify,
		      const struct lc_dilithium_ed25519_sig *sig,
		      const uint8_t *ph_m, size_t ph_m_len,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	LC_DILITHIUM_ED25519_CTX_ON_STACK(ctx);
	int ret = lc_dilithium_ed25519_verify_ctx(sig, ctx, ph_m, ph_m_len, pk);

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
	return lc_dilithium_ed25519_common_update(ctx, m, mlen);
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ed25519_verify_final,
		      const struct lc_dilithium_ed25519_sig *sig,
		      struct lc_dilithium_ed25519_ctx *ctx,
		      const struct lc_dilithium_ed25519_pk *pk)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	struct lc_hash_ctx *hash_ctx;
	uint8_t digest[LC_SHA512_SIZE_DIGEST];
	int retd = -EBADMSG, rete = -EBADMSG, ret = 0;

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

	rete = lc_ed25519_verify_ctx(&sig->sig_ed25519, digest, sizeof(digest),
				     &pk->pk_ed25519, ctx);

	CKINT_HARDENED(lc_dilithium_ed25519_verify_check(retd, rete));

out:
	lc_memset_secure(digest, 0, sizeof(digest));
	return ret;
}
