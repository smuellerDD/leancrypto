/* RFC 5869 HKDF
 *
 * Copyright (C) 2016 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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
#include "compare.h"
#include "lc_hkdf.h"
#include "lc_memset_secure.h"
#include "lc_rng.h"
#include "lc_sha256.h"
#include "math_helper.h"
#include "null_buffer.h"
#include "timecop.h"
#include "visibility.h"

static void hkdf_selftest(int *tested, const char *impl)
{
	/* RFC 5869 vector */
	static const uint8_t ikm[] = { 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				       0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
				       0x0b, 0x0b, 0x0b, 0x0b };
	static const uint8_t salt[] = { 0x00, 0x01, 0x02, 0x03, 0x04,
					0x05, 0x06, 0x07, 0x08, 0x09,
					0x0a, 0x0b, 0x0c };
	static const uint8_t info[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4,
					0xf5, 0xf6, 0xf7, 0xf8, 0xf9 };
	static const uint8_t exp[] = {
		0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90,
		0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d,
		0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d,
		0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08,
		0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65
	};
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(tested);

	LC_HKDF_CTX_ON_STACK(hkdf, lc_sha256);

	lc_hkdf_extract(hkdf, ikm, sizeof(ikm), salt, sizeof(salt));
	lc_hkdf_expand(hkdf, info, sizeof(info), act, sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
	lc_hkdf_zero(hkdf);
}

LC_INTERFACE_FUNCTION(int, lc_hkdf_extract, struct lc_hkdf_ctx *hkdf_ctx,
		      const uint8_t *ikm, size_t ikmlen, const uint8_t *salt,
		      size_t saltlen)
{
	struct lc_hmac_ctx *hmac_ctx;
	size_t h;
	uint8_t prk_tmp[LC_SHA_MAX_SIZE_DIGEST];
	static int tested = 0;

	/* Timecop: IKM is sensitive */
	poison(ikm, ikmlen);

	if (!hkdf_ctx)
		return -EINVAL;
	hmac_ctx = &hkdf_ctx->hmac_ctx;
	h = lc_hmac_macsize(hmac_ctx);

	hkdf_selftest(&tested, "HKDF");

	BUILD_BUG_ON(LC_NULL_BUFFER_SIZE < LC_SHA_MAX_SIZE_DIGEST);

	if (!ikm || !ikmlen)
		return -EINVAL;

	/* Extract phase */
	if (salt)
		lc_hmac_init(hmac_ctx, salt, saltlen);
	else
		lc_hmac_init(hmac_ctx, null_buffer, h);

	lc_hmac_update(hmac_ctx, ikm, ikmlen);
	lc_hmac_final(hmac_ctx, prk_tmp);

	/* Prepare for expand phase */
	lc_hmac_init(hmac_ctx, prk_tmp, h);

	lc_memset_secure(prk_tmp, 0, h);

	return 0;
}

static int hkdf_expand_internal(struct lc_hkdf_ctx *hkdf_ctx,
				const uint8_t *info, size_t infolen,
				uint8_t *dst, size_t dlen)
{
	struct lc_hmac_ctx *hmac_ctx = &hkdf_ctx->hmac_ctx;
	size_t h;

	h = lc_hmac_macsize(hmac_ctx);

	if (dlen > h * (255 - (hkdf_ctx->ctr)))
		return -EINVAL;

	/* Expand phase - expects a HMAC handle from the extract phase */

	/* Timecop: generated data is not sensitive for side-channels. */

	/* T(1) and following */
	while (dlen) {
		if (info)
			lc_hmac_update(hmac_ctx, info, infolen);

		lc_hmac_update(hmac_ctx, &hkdf_ctx->ctr, 1);

		if (dlen < h) {
			lc_hmac_final(hmac_ctx, hkdf_ctx->partial);

			/* Prepare it for subsequent calls if needed */
			lc_hmac_reinit(hmac_ctx);
			lc_hmac_update(hmac_ctx, hkdf_ctx->partial, dlen);
			memcpy(dst, hkdf_ctx->partial, dlen);
			unpoison(dst, dlen);
			hkdf_ctx->partial_ptr = dlen;
			hkdf_ctx->ctr++;

			goto out;
		} else {
			lc_hmac_final(hmac_ctx, dst);
			unpoison(dst, h);

			/* Prepare for next round */
			lc_hmac_reinit(hmac_ctx);
			lc_hmac_update(hmac_ctx, dst, h);

			dst += h;
			dlen -= h;
			hkdf_ctx->ctr++;
		}
	}

out:
	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_hkdf_expand, struct lc_hkdf_ctx *hkdf_ctx,
		      const uint8_t *info, size_t infolen, uint8_t *dst,
		      size_t dlen)
{
	struct lc_hmac_ctx *hmac_ctx;

	if (!hkdf_ctx)
		return -EINVAL;

	hmac_ctx = &hkdf_ctx->hmac_ctx;
	if (hkdf_ctx->ctr > 1)
		lc_hmac_reinit(hmac_ctx);

	return hkdf_expand_internal(hkdf_ctx, info, infolen, dst, dlen);
}

LC_INTERFACE_FUNCTION(int, lc_hkdf_alloc, const struct lc_hash *hash,
		      struct lc_hkdf_ctx **hkdf_ctx)
{
	struct lc_hkdf_ctx *out_state = NULL;
	int ret;

	if (!hkdf_ctx)
		return -EINVAL;

	ret = lc_alloc_aligned((void **)&out_state, LC_MEM_COMMON_ALIGNMENT,
			       LC_HKDF_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_HKDF_SET_CTX(out_state, hash);

	lc_hkdf_zero(out_state);

	*hkdf_ctx = out_state;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_hkdf_zero_free, struct lc_hkdf_ctx *hkdf_ctx)
{
	if (!hkdf_ctx)
		return;

	lc_hkdf_zero(hkdf_ctx);
	lc_free(hkdf_ctx);
}

LC_INTERFACE_FUNCTION(void, lc_hkdf_zero, struct lc_hkdf_ctx *hkdf_ctx)
{
	/*
	 * The use of this function implies that ->hmac_ctx is followed
	 * immediately by the state buffer!
	 */
	lc_hmac_zero(&hkdf_ctx->hmac_ctx);
	lc_memset_secure(hkdf_ctx->partial, 0, LC_SHA_MAX_SIZE_DIGEST);
	hkdf_ctx->ctr = 0x01;
	hkdf_ctx->rng_initialized = 0;
	hkdf_ctx->partial_ptr = LC_SHA_MAX_SIZE_DIGEST;
}

LC_INTERFACE_FUNCTION(int, lc_hkdf, const struct lc_hash *hash,
		      const uint8_t *ikm, size_t ikmlen, const uint8_t *salt,
		      size_t saltlen, const uint8_t *info, size_t infolen,
		      uint8_t *dst, size_t dlen)
{
	int ret;
	LC_HKDF_CTX_ON_STACK(hkdf, hash);

	ret = lc_hkdf_extract(hkdf, ikm, ikmlen, salt, saltlen);
	if (ret < 0)
		goto out;
	ret = lc_hkdf_expand(hkdf, info, infolen, dst, dlen);

out:
	lc_hkdf_zero(hkdf);
	return ret;
}

static int lc_hkdf_rng_seed(void *_state, const uint8_t *seed, size_t seedlen,
			    const uint8_t *persbuf, size_t perslen)
{
	struct lc_hkdf_ctx *state = _state;

	/* Timecop: seed is sensitive */
	poison(seed, seedlen);

	if (state->rng_initialized)
		return -EOPNOTSUPP;

	state->rng_initialized = 1;
	return lc_hkdf_extract(state, seed, seedlen, persbuf, perslen);
}

static int lc_hkdf_rng_generate(void *_state, const uint8_t *addtl_input,
				size_t addtl_input_len, uint8_t *out,
				size_t outlen)
{
	struct lc_hkdf_ctx *hkdf_ctx = _state;
	struct lc_hmac_ctx *hmac_ctx;
	size_t h;
	uint8_t *orig_out = out;

	if (!hkdf_ctx)
		return -EINVAL;
	if (!hkdf_ctx->rng_initialized)
		return -EOPNOTSUPP;

	hmac_ctx = &hkdf_ctx->hmac_ctx;
	h = lc_hmac_macsize(hmac_ctx);

	/* Consume partial data */
	if (hkdf_ctx->partial_ptr < h) {
		size_t todo = min_size(outlen, h - hkdf_ctx->partial_ptr);

		memcpy(out, hkdf_ctx->partial + hkdf_ctx->partial_ptr, todo);
		out += todo;
		hkdf_ctx->partial_ptr += todo;
		outlen -= todo;

		/*
		 * Add the returned data to the HKDF state as done in
		 * hkdf_expand_internal.
		 */
		lc_hmac_update(hmac_ctx, orig_out, todo);
	}

	if (!outlen)
		return 0;

	return hkdf_expand_internal(hkdf_ctx, addtl_input, addtl_input_len, out,
				    outlen);
}

static void lc_hkdf_rng_zero(void *_state)
{
	struct lc_hkdf_ctx *state = _state;

	if (!state)
		return;

	lc_hkdf_zero(state);
}

LC_INTERFACE_FUNCTION(int, lc_hkdf_rng_alloc, struct lc_rng_ctx **state,
		      const struct lc_hash *hash)
{
	struct lc_rng_ctx *out_state;
	int ret;

	if (!state)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_HASH_COMMON_ALIGNMENT,
				      LC_HKDF_DRNG_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_HKDF_RNG_CTX(out_state, hash);

	lc_hkdf_rng_zero(out_state->rng_state);

	*state = out_state;

	return 0;
}

static const struct lc_rng _lc_hkdf = {
	.generate = lc_hkdf_rng_generate,
	.seed = lc_hkdf_rng_seed,
	.zero = lc_hkdf_rng_zero,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *, lc_hkdf_rng) = &_lc_hkdf;
