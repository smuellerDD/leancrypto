/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
#include "visibility.h"

#include "lc_sha3.h"

LC_INTERFACE_FUNCTION(int, lc_dilithium_ctx_alloc,
		      struct lc_dilithium_ctx **ctx)
{
	struct lc_dilithium_ctx *out_ctx = NULL;
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = lc_alloc_aligned((void **)&out_ctx, LC_HASH_COMMON_ALIGNMENT,
			       LC_DILITHIUM_CTX_SIZE);
	if (ret)
		return -ret;

	LC_DILITHIUM_SET_CTX(out_ctx);

	*ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_ctx_alloc_ahat,
		      struct lc_dilithium_ctx **ctx)
{
	struct lc_dilithium_ctx *out_ctx = NULL;
	int ret;

	if (!ctx)
		return -EINVAL;

#if LC_DILITHIUM_MODE == 2
	ret = lc_alloc_aligned((void **)&out_ctx, LC_HASH_COMMON_ALIGNMENT,
			       LC_DILITHIUM_CTX_SIZE +
				       LC_DILITHIUM_44_AHAT_PAD +
				       LC_DILITHIUM_44_AHAT_SIZE);
	if (ret)
		return -ret;
	out_ctx->ahat = (uint8_t *)out_ctx + LC_DILITHIUM_CTX_SIZE +
			LC_DILITHIUM_44_AHAT_PAD;
	out_ctx->ahat_size = LC_DILITHIUM_44_AHAT_SIZE;
#elif LC_DILITHIUM_MODE == 3
	ret = lc_alloc_aligned((void **)&out_ctx, LC_HASH_COMMON_ALIGNMENT,
			       LC_DILITHIUM_CTX_SIZE +
				       LC_DILITHIUM_65_AHAT_PAD +
				       LC_DILITHIUM_65_AHAT_SIZE);
	if (ret)
		return -ret;
	out_ctx->ahat = (uint8_t *)out_ctx + LC_DILITHIUM_CTX_SIZE +
			LC_DILITHIUM_65_AHAT_PAD;
	out_ctx->ahat_size = LC_DILITHIUM_65_AHAT_SIZE;
#elif LC_DILITHIUM_MODE == 5
	ret = lc_alloc_aligned((void **)&out_ctx, LC_HASH_COMMON_ALIGNMENT,
			       LC_DILITHIUM_CTX_SIZE +
				       LC_DILITHIUM_87_AHAT_PAD +
				       LC_DILITHIUM_87_AHAT_SIZE);
	if (ret)
		return -ret;
	out_ctx->ahat = (uint8_t *)out_ctx + LC_DILITHIUM_CTX_SIZE +
			LC_DILITHIUM_87_AHAT_PAD;
	out_ctx->ahat_size = LC_DILITHIUM_87_AHAT_SIZE;
#endif

	LC_SHAKE_256_CTX((&(out_ctx)->dilithium_hash_ctx));

	*ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_dilithium_ctx_zero_free,
		      struct lc_dilithium_ctx *ctx)
{
	if (!ctx)
		return;

	lc_dilithium_ctx_zero(ctx);
	lc_free(ctx);
}
