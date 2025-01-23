/* Counter KDF - SP800-108
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

#include "compare.h"
#include "conv_be_le.h"
#include "ext_headers.h"
#include "lc_hmac.h"
#include "lc_kdf_ctr.h"
#include "lc_sha256.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

/*
 * From
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/CounterMode.zip
 */
static void lc_kdf_ctr_selftest(int *tested, const char *impl)
{
	static const uint8_t key[] = { 0xdd, 0x1d, 0x91, 0xb7, 0xd9, 0x0b, 0x2b,
				       0xd3, 0x13, 0x85, 0x33, 0xce, 0x92, 0xb2,
				       0x72, 0xfb, 0xf8, 0xa3, 0x69, 0x31, 0x6a,
				       0xef, 0xe2, 0x42, 0xe6, 0x59, 0xcc, 0x0a,
				       0xe2, 0x38, 0xaf, 0xe0 };
	static const uint8_t label[] = {
		0x01, 0x32, 0x2b, 0x96, 0xb3, 0x0a, 0xcd, 0x19, 0x79, 0x79,
		0x44, 0x4e, 0x46, 0x8e, 0x1c, 0x5c, 0x68, 0x59, 0xbf, 0x1b,
		0x1c, 0xf9, 0x51, 0xb7, 0xe7, 0x25, 0x30, 0x3e, 0x23, 0x7e,
		0x46, 0xb8, 0x64, 0xa1, 0x45, 0xfa, 0xb2, 0x5e, 0x51, 0x7b,
		0x08, 0xf8, 0x68, 0x3d, 0x03, 0x15, 0xbb, 0x29, 0x11, 0xd8,
		0x0a, 0x0e, 0x8a, 0xba, 0x17, 0xf3, 0xb4, 0x13, 0xfa, 0xac
	};
	static const uint8_t exp[] = { 0x10, 0x62, 0x13, 0x42, 0xbf, 0xb0,
				       0xfd, 0x40, 0x04, 0x6c, 0x0e, 0x29,
				       0xf2, 0xcf, 0xdb, 0xf0 };
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(tested);

	lc_kdf_ctr(lc_sha256, key, sizeof(key), label, sizeof(label), act,
		   sizeof(act));
	lc_compare_selftest(act, exp, sizeof(exp), impl);
}

static int lc_kdf_ctr_generate_internal(struct lc_hmac_ctx *hmac_ctx,
					const uint8_t *label, size_t labellen,
					uint8_t *dst, size_t dlen,
					uint32_t *counter)
{
	size_t h;
	uint32_t i = *counter;

	if (!hmac_ctx)
		return -EINVAL;

	if (dlen > INT_MAX)
		return -EMSGSIZE;

	h = lc_hmac_macsize(hmac_ctx);

	/* Timecop: generated data is not sensitive for side-channels. */
	while (dlen) {
		uint32_t ibe = be_bswap32(i);

		lc_hmac_update(hmac_ctx, (uint8_t *)&ibe, sizeof(uint32_t));

		if (label && labellen)
			lc_hmac_update(hmac_ctx, label, labellen);

		if (dlen < h) {
			uint8_t tmp[LC_SHA_MAX_SIZE_DIGEST];

			lc_hmac_final(hmac_ctx, tmp);
			memcpy(dst, tmp, dlen);
			unpoison(dst, dlen);
			lc_memset_secure(tmp, 0, sizeof(tmp));

			/*
			 * Increment counter in case the generate function is
			 * called again with the same context to ensure
			 * it continues from an updated counter.
			 */
			i++;

			goto out;
		} else {
			lc_hmac_final(hmac_ctx, dst);
			unpoison(dst, h);
			lc_hmac_reinit(hmac_ctx);

			dlen -= h;
			dst += h;
			i++;
		}
	}

out:
	*counter = i;
	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_kdf_ctr_generate, struct lc_hmac_ctx *hmac_ctx,
		      const uint8_t *label, size_t labellen, uint8_t *dst,
		      size_t dlen)
{
	uint32_t counter = 1;

	return lc_kdf_ctr_generate_internal(hmac_ctx, label, labellen, dst,
					    dlen, &counter);
}

LC_INTERFACE_FUNCTION(int, lc_kdf_ctr_init, struct lc_hmac_ctx *hmac_ctx,
		      const uint8_t *key, size_t keylen)
{
	static int tested = 0;

	lc_kdf_ctr_selftest(&tested, "SP800-108 CTR KDF");
	lc_hmac_init(hmac_ctx, key, keylen);
	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_kdf_ctr, const struct lc_hash *hash,
		      const uint8_t *key, size_t keylen, const uint8_t *label,
		      size_t labellen, uint8_t *dst, size_t dlen)
{
	int ret;
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);

	/* Timecop: key is sensitive */
	poison(key, keylen);
	CKINT(lc_kdf_ctr_init(hmac_ctx, key, keylen));
	CKINT(lc_kdf_ctr_generate(hmac_ctx, label, labellen, dst, dlen));

out:
	lc_hmac_zero(hmac_ctx);
	return ret;
}

static int lc_kdf_ctr_rng_seed(void *_state, const uint8_t *seed,
			       size_t seedlen, const uint8_t *persbuf,
			       size_t perslen)
{
	struct lc_kdf_ctr_ctx *state = _state;

	/* Timecop: seed is sensitive */
	poison(seed, seedlen);

	if (state->rng_initialized)
		return -EOPNOTSUPP;
	state->rng_initialized = 1;
	state->counter = 1;

	/*
	 * We could concatenate the personalization string with seed, but
	 * do we really want to?
	 */
	(void)persbuf;
	if (perslen)
		return -EOPNOTSUPP;

	return lc_kdf_ctr_init(&state->hmac_ctx, seed, seedlen);
}

static int lc_kdf_ctr_rng_generate(void *_state, const uint8_t *addtl_input,
				   size_t addtl_input_len, uint8_t *out,
				   size_t outlen)
{
	struct lc_kdf_ctr_ctx *kdf_ctr_ctx = _state;

	if (!kdf_ctr_ctx)
		return -EINVAL;
	if (!kdf_ctr_ctx->rng_initialized)
		return -EOPNOTSUPP;

	if (!outlen)
		return 0;

	return lc_kdf_ctr_generate_internal(&kdf_ctr_ctx->hmac_ctx, addtl_input,
					    addtl_input_len, out, outlen,
					    &kdf_ctr_ctx->counter);
}

static void lc_kdf_ctr_rng_zero(void *_state)
{
	struct lc_kdf_ctr_ctx *kdf_ctr_ctx = _state;

	if (!kdf_ctr_ctx)
		return;

	lc_hmac_zero(&kdf_ctr_ctx->hmac_ctx);
	kdf_ctr_ctx->rng_initialized = 0;
	kdf_ctr_ctx->counter = 1;
}

LC_INTERFACE_FUNCTION(int, lc_kdf_ctr_rng_alloc, struct lc_rng_ctx **state,
		      const struct lc_hash *hash)
{
	struct lc_rng_ctx *out_state;
	int ret;

	if (!state)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_HASH_COMMON_ALIGNMENT,
				      LC_CTR_KDF_DRNG_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_CTR_KDF_RNG_CTX(out_state, hash);

	lc_kdf_ctr_rng_zero(out_state->rng_state);

	*state = out_state;

	return 0;
}

static const struct lc_rng _lc_kdf_ctr = {
	.generate = lc_kdf_ctr_rng_generate,
	.seed = lc_kdf_ctr_rng_seed,
	.zero = lc_kdf_ctr_rng_zero,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *, lc_kdf_ctr_rng) = &_lc_kdf_ctr;
