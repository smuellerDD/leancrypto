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

#include "build_bug_on.h"
#include "hash_common.h"
#include "lc_cshake.h"
#include "lc_sha3.h"
#include "left_encode.h"
#include "null_buffer.h"

#include "visibility.h"

static int lc_cshake_init_impl(struct lc_hash_ctx *ctx, const uint8_t *n,
			       size_t nlen, const uint8_t *s, size_t slen,
			       int (*hash_init)(void *state))
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t bytepad_val256[] = { 0x01,
						  LC_SHAKE_256_SIZE_BLOCK };
	LC_FIPS_RODATA_SECTION
	static const uint8_t bytepad_val128[] = { 0x01,
						  LC_SHAKE_128_SIZE_BLOCK };
	uint8_t buf[sizeof(nlen) + 1];
	size_t len;
	/* 2 bytes for the bytepad_val that gets inserted */
	size_t added = 2;
	int ret,
		shake128 = (lc_hash_blocksize(ctx) == LC_SHAKE_128_SIZE_BLOCK) ?
				   1 :
				   0;

	/*
	 * When invoked without any additional values, it should operate as a
	 * regular SHAKE as defined in SP800-185 section 3.3. So, change the
	 * algorithm backend accordingly and initialize it.
	 */
	if (!nlen && !slen) {
		LC_HASH_SET_CTX(ctx, shake128 ? lc_shake128 : lc_shake256);
		return hash_init(ctx->hash_state);
	}

	ret = hash_init(ctx->hash_state);
	if (ret)
		return ret;

	/* bytepad value */
	//len = left_encode(buf, hash_blocksize(ctx));
	//padlen -= len;
	//hash_update(ctx, buf, len);
	if (shake128)
		lc_hash_update(ctx, bytepad_val128, sizeof(bytepad_val128));
	else
		lc_hash_update(ctx, bytepad_val256, sizeof(bytepad_val256));

	/* encode_string n */
	len = lc_left_encode(buf, nlen << 3);
	added += len;
	lc_hash_update(ctx, buf, len);
	lc_hash_update(ctx, n, nlen);
	added += nlen;

	/* encode_string s */
	len = lc_left_encode(buf, slen << 3);
	added += len;
	lc_hash_update(ctx, buf, len);
	lc_hash_update(ctx, s, slen);
	added += slen;

	/*
	 * bytepad pad
	 *
	 * Verify that the null_buffer is of sufficient size.
	 */
	BUILD_BUG_ON(LC_NULL_BUFFER_SIZE < LC_SHAKE_128_SIZE_BLOCK);
	len = (added % lc_hash_blocksize(ctx));
	if (len)
		lc_hash_update(ctx, null_buffer, lc_hash_blocksize(ctx) - len);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_cshake_init, struct lc_hash_ctx *ctx,
		      const uint8_t *n, size_t nlen, const uint8_t *s,
		      size_t slen)
{
	const struct lc_hash *hash;

	if (!ctx)
		return -EINVAL;

	hash = ctx->hash;
	return lc_cshake_init_impl(ctx, n, nlen, s, slen, hash->init);
}

int lc_cshake_init_nocheck(struct lc_hash_ctx *ctx, const uint8_t *n,
			   size_t nlen, const uint8_t *s, size_t slen)
{
	const struct lc_hash *hash;

	if (!ctx)
		return -EINVAL;

	hash = ctx->hash;
	return lc_cshake_init_impl(ctx, n, nlen, s, slen, hash->init_nocheck);
}

LC_INTERFACE_FUNCTION(int, lc_cshake_ctx_init, struct lc_cshake_ctx *cshake_ctx,
		      const uint8_t *n, size_t nlen, const uint8_t *s,
		      size_t slen)
{
	int ret = lc_cshake_init(&cshake_ctx->hash_ctx, n, nlen, s, slen);

	if (ret)
		return ret;

	/* Retain key state */
	if (cshake_ctx->shadow_ctx) {
		memcpy(cshake_ctx->shadow_ctx, cshake_ctx->hash_ctx.hash_state,
		       lc_hash_ctxsize(&cshake_ctx->hash_ctx));
	}

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_cshake_ctx_reinit,
		      struct lc_cshake_ctx *cshake_ctx)
{
	struct lc_hash_ctx *hash_ctx;

	if (!cshake_ctx)
		return;
	hash_ctx = &cshake_ctx->hash_ctx;

	if (!cshake_ctx->shadow_ctx)
		return;

	if (lc_hash_init(hash_ctx))
		return;

	/* Copy retained key state back*/
	memcpy(cshake_ctx->hash_ctx.hash_state, cshake_ctx->shadow_ctx,
	       lc_hash_ctxsize(hash_ctx));
}

LC_INTERFACE_FUNCTION(void, lc_cshake_ctx_update,
		      struct lc_cshake_ctx *cshake_ctx, const uint8_t *in,
		      size_t inlen)
{
	struct lc_hash_ctx *hash_ctx;

	if (!cshake_ctx)
		return;
	hash_ctx = &cshake_ctx->hash_ctx;

	lc_hash_update(hash_ctx, in, inlen);
}

LC_INTERFACE_FUNCTION(void, lc_cshake_ctx_final,
		      struct lc_cshake_ctx *cshake_ctx, uint8_t *mac,
		      size_t maclen)
{
	if (!cshake_ctx)
		return;

	lc_cshake_final(&cshake_ctx->hash_ctx, mac, maclen);
}

LC_INTERFACE_FUNCTION(int, lc_cshake_ctx_alloc, const struct lc_hash *hash,
		      struct lc_cshake_ctx **cshake_ctx, uint32_t flags)
{
	struct lc_cshake_ctx *out_ctx = NULL;
	size_t memsize;
	int ret;

	if (!cshake_ctx)
		return -EINVAL;

	memsize = (flags & LC_CSHAKE_FLAGS_SUPPORT_REINIT) ?
			  LC_CSHAKE_CTX_SIZE_REINIT(hash) :
			  LC_CSHAKE_CTX_SIZE(hash);
	ret = lc_alloc_aligned((void **)&out_ctx, LC_MEM_COMMON_ALIGNMENT,
			       memsize);

	if (ret)
		return -ret;

	if (flags & LC_CSHAKE_FLAGS_SUPPORT_REINIT) {
		LC_CSHAKE_SET_CTX_REINIT(out_ctx, hash);
	} else {
		LC_CSHAKE_SET_CTX(out_ctx, hash);
	}

	*cshake_ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_cshake_ctx_zero_free,
		      struct lc_cshake_ctx *cshake_ctx)
{
	if (!cshake_ctx)
		return;

	lc_cshake_ctx_zero(cshake_ctx);
	lc_free(cshake_ctx);
}
