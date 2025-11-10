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

#include "atomic.h"
#include "ext_headers_internal.h"
#include "lc_memory_support.h"
#include "lc_rng.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(void, lc_rng_check, struct lc_rng_ctx **ctx)
{
	if (!ctx)
		return;
	if (!*ctx)
		*ctx = lc_seeded_rng;
}

LC_INTERFACE_FUNCTION(void, lc_rng_zero, struct lc_rng_ctx *ctx)
{
	const struct lc_rng *rng;
	void *rng_state;

	if (!ctx)
		return;

	rng = ctx->rng;
	rng_state = ctx->rng_state;

	rng->zero(rng_state);
}

LC_INTERFACE_FUNCTION(void, lc_rng_zero_free, struct lc_rng_ctx *ctx)
{
	if (!ctx)
		return;

	lc_rng_zero(ctx);
	lc_free(ctx);
}

LC_INTERFACE_FUNCTION(int, lc_rng_generate, struct lc_rng_ctx *ctx,
		      const uint8_t *addtl_input, size_t addtl_input_len,
		      uint8_t *out, size_t outlen)
{
	const struct lc_rng *rng;
	void *rng_state;

	if (!ctx)
		return -EINVAL;

	rng = ctx->rng;
	rng_state = ctx->rng_state;

	return rng->generate(rng_state, addtl_input, addtl_input_len, out,
			     outlen);
}

LC_INTERFACE_FUNCTION(int, lc_rng_seed, struct lc_rng_ctx *ctx,
		      const uint8_t *seed, size_t seedlen,
		      const uint8_t *persbuf, size_t perslen)
{
	const struct lc_rng *rng;
	void *rng_state;

	if (!ctx)
		return -EINVAL;

	rng = ctx->rng;
	rng_state = ctx->rng_state;

	return rng->seed(rng_state, seed, seedlen, persbuf, perslen);
}

LC_INTERFACE_FUNCTION(uint64_t, lc_rng_algorithm_type, const struct lc_rng *rng)
{
	if (!rng)
		return 0;

	return rng->algorithm_type;
}

LC_INTERFACE_FUNCTION(uint64_t, lc_rng_ctx_algorithm_type,
		      const struct lc_rng_ctx *ctx)
{
	if (!ctx)
		return 0;

	return lc_rng_algorithm_type(ctx->rng);
}
