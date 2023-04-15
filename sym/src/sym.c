/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "lc_sym.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(
int, lc_sym_alloc, const struct lc_sym *sym, struct lc_sym_ctx **ctx)
{
	struct lc_sym_ctx *out_ctx = NULL;
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = lc_alloc_aligned((void **)&out_ctx, LC_SYM_ALIGNMENT_COMMON,
			       LC_SYM_CTX_SIZE(sym));

	if (ret)
		return -ret;

	LC_SYM_SET_CTX(out_ctx, sym);

	*ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(
void, lc_sym_zero_free, struct lc_sym_ctx *ctx)
{
	if (!ctx)
		return;

	lc_sym_zero(ctx);
	lc_free(ctx);
}
