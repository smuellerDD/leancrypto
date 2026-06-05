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

int lc_dilithium_ed25519_common_init(struct lc_dilithium_ed25519_ctx *ctx)
{
	struct lc_dilithium_ctx *dilithium_ctx;
	struct lc_hash_ctx *hash_ctx;
	int ret = 0;

	CKNULL(ctx, -EINVAL);

	dilithium_ctx = &ctx->dilithium_ctx;
	hash_ctx = &dilithium_ctx->dilithium_hash_ctx;

	if (!dilithium_ctx->dilithium_prehash_type) {
#ifdef LC_SHA2_512
		dilithium_ctx->dilithium_prehash_type = lc_sha512;
#else
		dilithium_ctx->dilithium_prehash_type = lc_shake256;
#endif
	} else {
		if ((dilithium_ctx->dilithium_prehash_type != lc_shake256) &&
		    (dilithium_ctx->dilithium_prehash_type != lc_sha3_512)
#ifdef LC_SHA2_512
		    && (dilithium_ctx->dilithium_prehash_type != lc_sha512)
#endif
		)
			return -EOPNOTSUPP;
	}

	LC_HASH_SET_CTX(hash_ctx, dilithium_ctx->dilithium_prehash_type);
	lc_hash_zero(hash_ctx);
	CKINT(lc_hash_init(hash_ctx));

out:
	return ret;
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
		return ret;

	LC_DILITHIUM_ED25519_SET_CTX(out_ctx);

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
