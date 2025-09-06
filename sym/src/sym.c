/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_internal.h"
#include "lc_sym.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_sym_init, struct lc_sym_ctx *ctx)
{
	const struct lc_sym *sym;

	if (!ctx)
		return -EINVAL;

	sym = ctx->sym;

	return sym->init(ctx->sym_state);
}

LC_INTERFACE_FUNCTION(int, lc_sym_setkey, struct lc_sym_ctx *ctx,
		      const uint8_t *key, size_t keylen)
{
	const struct lc_sym *sym;

	if (!ctx)
		return -EINVAL;

	sym = ctx->sym;
	return sym->setkey(ctx->sym_state, key, keylen);
}

LC_INTERFACE_FUNCTION(int, lc_sym_setiv, struct lc_sym_ctx *ctx,
		      const uint8_t *iv, size_t ivlen)
{
	const struct lc_sym *sym;

	if (!ctx)
		return -EINVAL;

	sym = ctx->sym;
	return sym->setiv(ctx->sym_state, iv, ivlen);
}

LC_INTERFACE_FUNCTION(void, lc_sym_encrypt, struct lc_sym_ctx *ctx,
		      const uint8_t *in, uint8_t *out, size_t len)
{
	const struct lc_sym *sym;

	if (!ctx)
		return;

	sym = ctx->sym;
	sym->encrypt(ctx->sym_state, in, out, len);
}

LC_INTERFACE_FUNCTION(void, lc_sym_decrypt, struct lc_sym_ctx *ctx,
		      const uint8_t *in, uint8_t *out, size_t len)
{
	const struct lc_sym *sym;

	if (!ctx)
		return;

	sym= ctx->sym;
	sym->decrypt(ctx->sym_state, in, out, len);
}

LC_INTERFACE_FUNCTION(void, lc_sym_zero, struct lc_sym_ctx *ctx)
{
	const struct lc_sym *sym;

	if (!ctx)
		return;

	sym = ctx->sym;
	lc_memset_secure((uint8_t *)ctx + sizeof(struct lc_sym_ctx), 0,
			 LC_SYM_STATE_SIZE(sym));
}

LC_INTERFACE_FUNCTION(int, lc_sym_alloc, const struct lc_sym *sym,
		      struct lc_sym_ctx **ctx)
{
	struct lc_sym_ctx *out_ctx = NULL;
	int ret;

	if (!ctx || !sym)
		return -EINVAL;

	ret = lc_alloc_aligned((void **)&out_ctx, LC_SYM_COMMON_ALIGNMENT,
			       LC_SYM_CTX_SIZE(sym));

	if (ret)
		return -ret;

	LC_SYM_SET_CTX(out_ctx, sym);

	*ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_sym_zero_free, struct lc_sym_ctx *ctx)
{
	if (!ctx)
		return;

	lc_sym_zero(ctx);
	lc_free(ctx);
}
