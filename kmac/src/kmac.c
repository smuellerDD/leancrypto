/* Generic KMAC implementation
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lc_cshake.h"
#include "lc_kmac.h"
#include "left_encode.h"
#include "visibility.h"

static unsigned int right_encode(uint8_t *buf, size_t val)
{
	size_t v;
	unsigned int n, i;

	/* Determine n */
	for (v = val, n = 0; v && (n < sizeof(val)); n++, v >>= 8 )
		;
	if (n == 0)
		n = 1;
	for (i = 0; i < n; i++)
		buf[i] = (uint8_t)(val >> ((n - i - 1) << 3));

	buf[n] = (uint8_t)n;

	return n + 1;
}

DSO_PUBLIC
void lc_kmac_reinit(struct lc_kmac_ctx *kmac_ctx)
{
	struct lc_hash_ctx *hash_ctx = &kmac_ctx->hash_ctx;

	if (!kmac_ctx->shadow_ctx)
		return;

	lc_hash_init(hash_ctx);

	/* Copy retained key state back*/
	memcpy(kmac_ctx->hash_ctx.hash_state, kmac_ctx->shadow_ctx,
	       lc_hash_ctxsize(hash_ctx));
}

DSO_PUBLIC
void lc_kmac_init(struct lc_kmac_ctx *kmac_ctx,
		  const uint8_t *key, size_t klen,
		  const uint8_t *s, size_t slen)
{
	struct lc_hash_ctx *hash_ctx = &kmac_ctx->hash_ctx;
	static const uint8_t zero[LC_SHA3_256_SIZE_BLOCK] = { 0 };
	static const uint8_t bytepad_val[2] = { 0x01, 0x88 };
	uint8_t buf[sizeof(klen) + 1];
	size_t len;
	/* 2 bytes for the bytepad_val that gets inserted */
	size_t added = 2;

	lc_hash_init(hash_ctx);
	lc_cshake_init(hash_ctx, (uint8_t *)"KMAC", 4, s, slen);

	/* bytepad */
	/* This value is precomputed from the code above for SHA3-256 */
	lc_hash_update(hash_ctx, bytepad_val, sizeof(bytepad_val));
	len = lc_left_encode(buf, klen << 3);
	added += len;
	lc_hash_update(hash_ctx, buf, len);
	lc_hash_update(hash_ctx, key, klen);
	added += klen;

	/* bytepad pad */
	len = (added % lc_hash_blocksize(hash_ctx));
	if (len) {
		lc_hash_update(hash_ctx, zero,
			       lc_hash_blocksize(hash_ctx) - len);
	}

	/* Retain key state */
	if (kmac_ctx->shadow_ctx) {
		memcpy(kmac_ctx->shadow_ctx, kmac_ctx->hash_ctx.hash_state,
		       lc_hash_ctxsize(hash_ctx));
	}
}

DSO_PUBLIC
void lc_kmac_update(struct lc_kmac_ctx *kmac_ctx,
		    const uint8_t *in, size_t inlen)
{
	struct lc_hash_ctx *hash_ctx = &kmac_ctx->hash_ctx;

	lc_hash_update(hash_ctx, in, inlen);
}

DSO_PUBLIC
void lc_kmac_final(struct lc_kmac_ctx *kmac_ctx, uint8_t *mac, size_t maclen)
{
	struct lc_hash_ctx *hash_ctx = &kmac_ctx->hash_ctx;
	uint8_t buf[sizeof(size_t) + 1];
	size_t len;

	len = right_encode(buf, maclen << 3);
	lc_hash_update(hash_ctx, buf, len);
	lc_hash_set_digestsize(hash_ctx, maclen);
	lc_hash_final(hash_ctx, mac);
}

DSO_PUBLIC
void lc_kmac_final_xof(struct lc_kmac_ctx *kmac_ctx,
		       uint8_t *mac, size_t maclen)
{
	struct lc_hash_ctx *hash_ctx = &kmac_ctx->hash_ctx;
	static const uint8_t bytepad_val[] = { 0x00, 0x01 };

	lc_hash_update(hash_ctx, bytepad_val, sizeof(bytepad_val));
	lc_cshake_final(hash_ctx, mac, maclen);
}

DSO_PUBLIC
void lc_kmac_final_xof_more(struct lc_kmac_ctx *kmac_ctx, uint8_t *mac,
			    size_t maclen)
{
	struct lc_hash_ctx *hash_ctx = &kmac_ctx->hash_ctx;

	lc_cshake_final(hash_ctx, mac, maclen);
}

DSO_PUBLIC
int lc_kmac_alloc(const struct lc_hash *hash, struct lc_kmac_ctx **kmac_ctx,
		  uint32_t flags)
{
	struct lc_kmac_ctx *out_ctx;
	size_t memsize = (flags & LC_KMAC_FLAGS_SUPPORT_REINIT) ?
			  LC_KMAC_CTX_SIZE_REINIT(hash) :
			  LC_KMAC_CTX_SIZE(hash);
	int ret = posix_memalign((void *)&out_ctx, sizeof(uint64_t), memsize);

	if (ret)
		return -ret;

	if (flags & LC_KMAC_FLAGS_SUPPORT_REINIT) {
		LC_KMAC_SET_CTX_REINIT(out_ctx, hash);
	} else {
		LC_KMAC_SET_CTX(out_ctx, hash);
	}

	*kmac_ctx = out_ctx;

	return 0;
}

DSO_PUBLIC
void lc_kmac_zero_free(struct lc_kmac_ctx *kmac_ctx)
{
	if (!kmac_ctx)
		return;

	lc_kmac_zero(kmac_ctx);
	free(kmac_ctx);
}
