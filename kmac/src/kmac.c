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

LC_INTERFACE_FUNCTION(
void, lc_kmac_reinit, struct lc_kmac_ctx *kmac_ctx)
{
	struct lc_hash_ctx *hash_ctx;

	if (!kmac_ctx)
		return;
	hash_ctx = &kmac_ctx->hash_ctx;

	if (!kmac_ctx->shadow_ctx)
		return;

	lc_hash_init(hash_ctx);
	kmac_ctx->final_called = 0;

	/* Copy retained key state back*/
	memcpy(kmac_ctx->hash_ctx.hash_state, kmac_ctx->shadow_ctx,
	       lc_hash_ctxsize(hash_ctx));
}

LC_INTERFACE_FUNCTION(
void, lc_kmac_init, struct lc_kmac_ctx *kmac_ctx,
		    const uint8_t *key, size_t klen,
		    const uint8_t *s, size_t slen)
{
	struct lc_hash_ctx *hash_ctx;
	static const uint8_t zero[LC_SHAKE_128_SIZE_BLOCK] = { 0 };
	static const uint8_t
		bytepad_val256[] = { 0x01, LC_SHAKE_256_SIZE_BLOCK },
		bytepad_val128[] = { 0x01, LC_SHAKE_128_SIZE_BLOCK };
	uint8_t buf[sizeof(klen) + 1];
	size_t len;
	/* 2 bytes for the bytepad_val that gets inserted */
	size_t added = 2;

	if (!kmac_ctx)
		return;
	hash_ctx = &kmac_ctx->hash_ctx;

	lc_cshake_init(hash_ctx, (uint8_t *)"KMAC", 4, s, slen);
	kmac_ctx->final_called = 0;

	/* bytepad */
	if (lc_hash_blocksize(hash_ctx) == LC_SHAKE_128_SIZE_BLOCK)
		lc_hash_update(hash_ctx, bytepad_val128, sizeof(bytepad_val128));
	else
		lc_hash_update(hash_ctx, bytepad_val256, sizeof(bytepad_val256));

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

LC_INTERFACE_FUNCTION(
void, lc_kmac_update, struct lc_kmac_ctx *kmac_ctx,
		      const uint8_t *in, size_t inlen)
{
	struct lc_hash_ctx *hash_ctx;

	if (!kmac_ctx)
		return;
	hash_ctx = &kmac_ctx->hash_ctx;

	lc_hash_update(hash_ctx, in, inlen);
}

LC_INTERFACE_FUNCTION(
void, lc_kmac_final, struct lc_kmac_ctx *kmac_ctx, uint8_t *mac, size_t maclen)
{
	struct lc_hash_ctx *hash_ctx;
	uint8_t buf[sizeof(size_t) + 1];
	size_t len;

	if (!kmac_ctx || !mac)
		return;
	hash_ctx = &kmac_ctx->hash_ctx;

	len = right_encode(buf, maclen << 3);
	lc_hash_update(hash_ctx, buf, len);
	lc_hash_set_digestsize(hash_ctx, maclen);
	lc_hash_final(hash_ctx, mac);
}

LC_INTERFACE_FUNCTION(
void, lc_kmac_final_xof, struct lc_kmac_ctx *kmac_ctx,
			 uint8_t *mac, size_t maclen)
{
	struct lc_hash_ctx *hash_ctx;
	static const uint8_t bytepad_val[] = { 0x00, 0x01 };

	if (!kmac_ctx || !mac)
		return;
	hash_ctx = &kmac_ctx->hash_ctx;

	if (!kmac_ctx->final_called) {
		lc_hash_update(hash_ctx, bytepad_val, sizeof(bytepad_val));
		kmac_ctx->final_called = 1;
	}
	lc_cshake_final(hash_ctx, mac, maclen);
}

LC_INTERFACE_FUNCTION(
int, lc_kmac_alloc, const struct lc_hash *hash, struct lc_kmac_ctx **kmac_ctx,
		    uint32_t flags)
{
	struct lc_kmac_ctx *out_ctx = NULL;
	size_t memsize;
	int ret;

	if (!kmac_ctx)
		return -EINVAL;

	memsize = (flags & LC_KMAC_FLAGS_SUPPORT_REINIT) ?
		  LC_KMAC_CTX_SIZE_REINIT(hash) :
		  LC_KMAC_CTX_SIZE(hash);
	ret = lc_alloc_aligned((void *)&out_ctx, LC_HASH_COMMON_ALIGNMENT,
			       memsize);

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

LC_INTERFACE_FUNCTION(
void, lc_kmac_zero_free, struct lc_kmac_ctx *kmac_ctx)
{
	if (!kmac_ctx)
		return;

	lc_kmac_zero(kmac_ctx);
	lc_free(kmac_ctx);
}

static int lc_kmac_rng_seed(void *_state,
			    const uint8_t *seed, size_t seedlen,
			    const uint8_t *persbuf, size_t perslen)
{
	struct lc_kmac_ctx *state = _state;

	if (state->rng_initialized) {
		lc_kmac_update(state, seed, seedlen);
		lc_kmac_update(state, persbuf, perslen);
		return 0;
	}

	lc_kmac_init(state, seed, seedlen, persbuf, perslen);
	state->rng_initialized = 1;

	return 0;
}

static int
lc_kmac_rng_generate(void *_state,
		     const uint8_t *addtl_input, size_t addtl_input_len,
		     uint8_t *out, size_t outlen)
{
	struct lc_kmac_ctx *kmac_ctx = _state;

	if (!kmac_ctx)
		return -EINVAL;

	if (addtl_input_len)
		lc_kmac_update(kmac_ctx, addtl_input, addtl_input_len);

	lc_kmac_final_xof(kmac_ctx, out, outlen);
	return 0;
}

static void lc_kmac_rng_zero(void *_state)
{
	struct lc_kmac_ctx *state = _state;

	if (!state)
		return;

	lc_kmac_zero(state);
}

LC_INTERFACE_FUNCTION(
int, lc_kmac_rng_alloc, struct lc_rng_ctx **state, const struct lc_hash *hash)
{
	struct lc_rng_ctx *out_state;
	int ret;

	if (!state)
		return -EINVAL;

	ret = lc_alloc_aligned((void *)&out_state, LC_HASH_COMMON_ALIGNMENT,
			       LC_KMAC_KDF_DRNG_CTX_SIZE(hash));
	if (ret)
		return -ret;

	/* prevent paging out of the memory state to swap space */
	ret = mlock(out_state, sizeof(*out_state));
	if (ret && errno != EPERM && errno != EAGAIN) {
		int errsv = errno;

		lc_free(out_state);
		return -errsv;
	}

	LC_KMAC_KDF_RNG_CTX(out_state, hash);

	lc_kmac_rng_zero(out_state->rng_state);

	*state = out_state;

	return 0;
}

static const struct lc_rng _lc_kmac = {
	.generate	= lc_kmac_rng_generate,
	.seed		= lc_kmac_rng_seed,
	.zero		= lc_kmac_rng_zero,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *, lc_kmac_rng) = &_lc_kmac;
