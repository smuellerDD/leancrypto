/* Generic HMAC implementation
 *
 * Copyright (C) 2020 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "compare.h"
#include "fips_mode.h"
#include "hmac_selftest.h"
#include "lc_hmac.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

#define IPAD 0x36
#define OPAD 0x5c

static void hmac_selftest(void)
{
	LC_SELFTEST_RUN(LC_ALG_STATUS_HMAC);

	if (hmac_sha256_selftest())
		return;
	if (hmac_sha512_selftest())
		return;
	hmac_sha3_selftest();
}

LC_INTERFACE_FUNCTION(void, lc_hmac_reinit, struct lc_hmac_ctx *hmac_ctx)
{
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;

	if (lc_hash_init(hash_ctx))
		return;
	lc_hash_update(hash_ctx, hmac_ctx->k_ipad, lc_hash_blocksize(hash_ctx));
}

static int lc_hmac_init_nocheck(struct lc_hmac_ctx *hmac_ctx,
				const uint8_t *key, size_t keylen)
{
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	const struct lc_hash *hash = hash_ctx->hash;
	uint8_t *k_opad, *k_ipad;
	unsigned int i;
	int ret = 0;

	CKINT(fips140_min_keysize(keylen));

	/* Timecop: key is sensitive. */
	poison(key, keylen);

	if (lc_hash_ctxsize(hash_ctx) > LC_HASH_STATE_SIZE(hash) ||
	    lc_hash_blocksize(hash_ctx) > LC_SHA_MAX_SIZE_BLOCK ||
	    lc_hash_digestsize(hash_ctx) > LC_SHA_MAX_SIZE_DIGEST)
		return -EINVAL;

	k_opad = hmac_ctx->k_opad;
	k_ipad = hmac_ctx->k_ipad;

	if (keylen > lc_hash_blocksize(hash_ctx)) {
		CKINT(lc_hash_init(hash_ctx));
		lc_hash_update(hash_ctx, key, keylen);
		lc_hash_final(hash_ctx, k_opad);
		memset(k_opad + lc_hash_digestsize(hash_ctx), 0,
		       lc_hash_blocksize(hash_ctx) -
			       lc_hash_digestsize(hash_ctx));
	} else {
		memcpy(k_opad, key, keylen);
		memset(k_opad + keylen, 0,
		       lc_hash_blocksize(hash_ctx) - keylen);
	}

	for (i = 0; i < lc_hash_blocksize(hash_ctx); i++)
		k_ipad[i] = k_opad[i] ^ IPAD;

	for (i = 0; i < lc_hash_blocksize(hash_ctx); i++)
		k_opad[i] ^= OPAD;

	lc_hmac_reinit(hmac_ctx);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_hmac_init, struct lc_hmac_ctx *hmac_ctx,
		      const uint8_t *key, size_t keylen)
{
	hmac_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_HMAC);

	return lc_hmac_init_nocheck(hmac_ctx, key, keylen);
}

LC_INTERFACE_FUNCTION(void, lc_hmac_update, struct lc_hmac_ctx *hmac_ctx,
		      const uint8_t *in, size_t inlen)
{
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;

	lc_hash_update(hash_ctx, in, inlen);
}

LC_INTERFACE_FUNCTION(void, lc_hmac_final, struct lc_hmac_ctx *hmac_ctx,
		      uint8_t *mac)
{
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	uint8_t *k_opad = hmac_ctx->k_opad;

	lc_hash_final(hash_ctx, mac);

	if (lc_hash_init(hash_ctx)) {
		memset(mac, 0, lc_hash_digestsize(hash_ctx));
		return;
	}
	lc_hash_update(hash_ctx, k_opad, lc_hash_blocksize(hash_ctx));
	lc_hash_update(hash_ctx, mac, lc_hash_digestsize(hash_ctx));
	lc_hash_final(hash_ctx, mac);

	/* Timecop: mac is not sensitive regarding side-channels. */
	unpoison(mac, lc_hash_digestsize(hash_ctx));
}

LC_INTERFACE_FUNCTION(int, lc_hmac_alloc, const struct lc_hash *hash,
		      struct lc_hmac_ctx **hmac_ctx)
{
	struct lc_hmac_ctx *out_ctx = NULL;
	int ret = lc_alloc_aligned((void **)&out_ctx, LC_MEM_COMMON_ALIGNMENT,
				   LC_HMAC_CTX_SIZE(hash));

	if (ret)
		return -ret;

	LC_HMAC_SET_CTX(out_ctx, hash);

	*hmac_ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_hmac_zero_free, struct lc_hmac_ctx *hmac_ctx)
{
	if (!hmac_ctx)
		return;

	lc_hmac_zero(hmac_ctx);
	lc_free(hmac_ctx);
}

LC_INTERFACE_FUNCTION(void, lc_hmac_zero, struct lc_hmac_ctx *hmac_ctx)
{
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;
	const struct lc_hash *hash = hash_ctx->hash;

	lc_memset_secure((uint8_t *)hmac_ctx + sizeof(struct lc_hmac_ctx), 0,
			 LC_HMAC_STATE_SIZE(hash));
}

LC_INTERFACE_FUNCTION(size_t, lc_hmac_macsize, struct lc_hmac_ctx *hmac_ctx)
{
	struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;

	return lc_hash_digestsize(hash_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_hmac, const struct lc_hash *hash,
		      const uint8_t *key, size_t keylen, const uint8_t *in,
		      size_t inlen, uint8_t *mac)
{
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);
	int ret;

	CKINT(lc_hmac_init(hmac_ctx, key, keylen));
	lc_hmac_update(hmac_ctx, in, inlen);
	lc_hmac_final(hmac_ctx, mac);

out:
	lc_hmac_zero(hmac_ctx);
	return ret;
}

void lc_hmac_nocheck(const struct lc_hash *hash, const uint8_t *key,
		     size_t keylen, const uint8_t *in, size_t inlen,
		     uint8_t *mac)
{
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);

	if (lc_hmac_init_nocheck(hmac_ctx, key, keylen)) {
		struct lc_hash_ctx *hash_ctx = &hmac_ctx->hash_ctx;

		memset(mac, 0, lc_hash_digestsize(hash_ctx));
		return;
	}
	lc_hmac_update(hmac_ctx, in, inlen);
	lc_hmac_final(hmac_ctx, mac);

	lc_hmac_zero(hmac_ctx);
}
