/* Generic KMAC implementation
 *
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
#include "compare.h"
#include "fips_mode.h"
#include "lc_cshake.h"
#include "lc_kmac.h"
#include "left_encode.h"
#include "null_buffer.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

/*
 * SP800-185 section 8.4.2 requires the MAC size to be at least 32 bits. As this
 * requirement is to counter too small MAC sizes which can be guessed, this
 * requirement is not applicable when using KMAC in the RNG use case.
 */
#define LC_KMAC_MIN_MAC_SIZE (32 >> 3)

static int lc_kmac_init_nocheck(struct lc_kmac_ctx *kmac_ctx,
				const uint8_t *key, size_t klen,
				const uint8_t *s, size_t slen);
static void lc_kmac_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t msg[] = { FIPS140_MOD(0x0E),
				       0x8B,
				       0x97,
				       0x33,
				       0x23,
				       0x85,
				       0x6E,
				       0x39,
				       0x03,
				       0xFF,
				       0xD5 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t key[] = { 0x88, 0x4C, 0xFB, 0x2D, 0xBD, 0xBB,
				       0xD7, 0x22, 0xBA, 0x3E, 0x0A, 0x63,
				       0xF1, 0xC9, 0xED, 0x02 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t cust[] = { 0x28, 0x60, 0x7A, 0xF1, 0xD2, 0x68,
					0x0E, 0x36, 0x1F, 0xB8, 0x81 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp[] = { 0x41, 0x27, 0x58, 0x53, 0x5c, 0x45, 0x39,
				       0x79, 0x66, 0x20, 0xc6, 0xb2, 0xac, 0xac,
				       0x53, 0x48, 0x9e, 0x08, 0x34, 0x69, 0x0a,
				       0x2f, 0xdb, 0x21, 0xa4, 0xe5, 0x0c, 0x7c,
				       0x31, 0x09, 0x78, 0xec, 0xff, 0x65, 0x34,
				       0xb6, 0x18, 0xe2, 0x69, 0x2f, 0x53, 0x9c,
				       0xed, 0xd5, 0x61, 0x25, 0xac, 0x18, 0x96,
				       0x8f, 0xc3 };
	uint8_t act[sizeof(exp)];

	LC_SELFTEST_RUN(LC_ALG_STATUS_KMAC);

	LC_KMAC_CTX_ON_STACK(ctx, lc_cshake256);

	if (lc_kmac_init_nocheck(ctx, key, sizeof(key), cust, sizeof(cust)))
		goto out;
	lc_kmac_update(ctx, msg, sizeof(msg));
	lc_kmac_final(ctx, act, sizeof(act));

out:
	lc_compare_selftest(LC_ALG_STATUS_KMAC, act, exp, sizeof(exp), "KMAC");
	lc_kmac_zero(ctx);
}

static unsigned int right_encode(uint8_t *buf, size_t val)
{
	size_t v;
	unsigned int n, i;

	/* Determine n */
	for (v = val, n = 0; v && (n < sizeof(val)); n++, v >>= 8)
		;
	if (n == 0)
		n = 1;
	for (i = 0; i < n; i++)
		buf[i] = (uint8_t)(val >> ((n - i - 1) << 3));

	buf[n] = (uint8_t)n;

	return n + 1;
}

LC_INTERFACE_FUNCTION(void, lc_kmac_reinit, struct lc_kmac_ctx *kmac_ctx)
{
	struct lc_hash_ctx *hash_ctx;

	if (!kmac_ctx)
		return;
	hash_ctx = &kmac_ctx->hash_ctx;

	if (!kmac_ctx->shadow_ctx)
		return;

	if (lc_hash_init(hash_ctx))
		return;

	kmac_ctx->final_called = 0;

	/* Copy retained key state back*/
	memcpy(kmac_ctx->hash_ctx.hash_state, kmac_ctx->shadow_ctx,
	       lc_hash_ctxsize(hash_ctx));
}

static int lc_kmac_init_nocheck(struct lc_kmac_ctx *kmac_ctx,
				const uint8_t *key, size_t klen,
				const uint8_t *s, size_t slen)
{
	struct lc_hash_ctx *hash_ctx;
	LC_FIPS_RODATA_SECTION
	static const uint8_t bytepad_val256[] = { 0x01,
						  LC_SHAKE_256_SIZE_BLOCK };
	LC_FIPS_RODATA_SECTION
	static const uint8_t bytepad_val128[] = { 0x01,
						  LC_SHAKE_128_SIZE_BLOCK };
	uint8_t buf[sizeof(klen) + 1];
	size_t len;
	/* 2 bytes for the bytepad_val that gets inserted */
	size_t added = 2;
	int ret;

	CKINT(fips140_min_keysize(klen));

	/* Timecop: Mark the key as sensitive data. */
	poison(key, klen);

	if (!kmac_ctx)
		return -EINVAL;

	hash_ctx = &kmac_ctx->hash_ctx;

	CKINT(lc_cshake_init(hash_ctx, (uint8_t *)"KMAC", 4, s, slen));

	kmac_ctx->final_called = 0;

	/* bytepad */
	if (lc_hash_blocksize(hash_ctx) == LC_SHAKE_128_SIZE_BLOCK)
		lc_hash_update(hash_ctx, bytepad_val128,
			       sizeof(bytepad_val128));
	else
		lc_hash_update(hash_ctx, bytepad_val256,
			       sizeof(bytepad_val256));

	len = lc_left_encode(buf, klen << 3);
	added += len;
	lc_hash_update(hash_ctx, buf, len);
	lc_hash_update(hash_ctx, key, klen);
	added += klen;

	/*
	 * bytepad pad
	 *
	 * Verify that the null_buffer is of sufficient size.
	 */
	BUILD_BUG_ON(LC_NULL_BUFFER_SIZE < LC_SHAKE_128_SIZE_BLOCK);
	len = (added % lc_hash_blocksize(hash_ctx));
	if (len) {
		lc_hash_update(hash_ctx, null_buffer,
			       lc_hash_blocksize(hash_ctx) - len);
	}

	/* Retain key state */
	if (kmac_ctx->shadow_ctx) {
		memcpy(kmac_ctx->shadow_ctx, kmac_ctx->hash_ctx.hash_state,
		       lc_hash_ctxsize(hash_ctx));
	}

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kmac_init, struct lc_kmac_ctx *kmac_ctx,
		      const uint8_t *key, size_t klen, const uint8_t *s,
		      size_t slen)
{
	lc_kmac_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_KMAC);

	return lc_kmac_init_nocheck(kmac_ctx, key, klen, s, slen);
}

LC_INTERFACE_FUNCTION(void, lc_kmac_update, struct lc_kmac_ctx *kmac_ctx,
		      const uint8_t *in, size_t inlen)
{
	struct lc_hash_ctx *hash_ctx;

	if (!kmac_ctx)
		return;
	hash_ctx = &kmac_ctx->hash_ctx;

	lc_hash_update(hash_ctx, in, inlen);
}

static void lc_kmac_final_internal(struct lc_kmac_ctx *kmac_ctx, uint8_t *mac,
				   size_t maclen)
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

	/* Timecop: Message digest is not sensitive any more */
	unpoison(mac, maclen);
}

LC_INTERFACE_FUNCTION(void, lc_kmac_final, struct lc_kmac_ctx *kmac_ctx,
		      uint8_t *mac, size_t maclen)
{
	if (maclen >= LC_KMAC_MIN_MAC_SIZE)
		lc_kmac_final_internal(kmac_ctx, mac, maclen);
}

static void lc_kmac_final_xof_internal(struct lc_kmac_ctx *kmac_ctx,
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

	/* Timecop: Message digest is not sensitive any more */
	unpoison(mac, maclen);
}

LC_INTERFACE_FUNCTION(void, lc_kmac_final_xof, struct lc_kmac_ctx *kmac_ctx,
		      uint8_t *mac, size_t maclen)
{
	if (maclen >= LC_KMAC_MIN_MAC_SIZE)
		lc_kmac_final_xof_internal(kmac_ctx, mac, maclen);
}

LC_INTERFACE_FUNCTION(int, lc_kmac_alloc, const struct lc_hash *hash,
		      struct lc_kmac_ctx **kmac_ctx, uint32_t flags)
{
	struct lc_kmac_ctx *out_ctx = NULL;
	size_t memsize;
	int ret;

	if (!kmac_ctx)
		return -EINVAL;

	memsize = (flags & LC_KMAC_FLAGS_SUPPORT_REINIT) ?
			  LC_KMAC_CTX_SIZE_REINIT(hash) :
			  LC_KMAC_CTX_SIZE(hash);
	ret = lc_alloc_aligned((void **)&out_ctx, LC_MEM_COMMON_ALIGNMENT,
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

LC_INTERFACE_FUNCTION(void, lc_kmac_zero_free, struct lc_kmac_ctx *kmac_ctx)
{
	if (!kmac_ctx)
		return;

	lc_kmac_zero(kmac_ctx);
	lc_free(kmac_ctx);
}

LC_INTERFACE_FUNCTION(void, lc_kmac_zero, struct lc_kmac_ctx *kmac_ctx)
{
	struct lc_hash_ctx *hash_ctx;
	const struct lc_hash *hash;

	if (!kmac_ctx)
		return;
	hash_ctx = &kmac_ctx->hash_ctx;
	hash = hash_ctx->hash;

	kmac_ctx->final_called = 0;
	kmac_ctx->rng_initialized = 0;

	lc_memset_secure((uint8_t *)kmac_ctx + sizeof(struct lc_kmac_ctx), 0,
			 kmac_ctx->shadow_ctx ?
				 LC_KMAC_STATE_SIZE_REINIT(hash) :
				 LC_KMAC_STATE_SIZE(hash));
}

LC_INTERFACE_FUNCTION(int, lc_kmac, const struct lc_hash *hash,
		      const uint8_t *key, size_t keylen, const uint8_t *s,
		      size_t slen, const uint8_t *in, size_t inlen,
		      uint8_t *mac, size_t maclen)
{
	LC_KMAC_CTX_ON_STACK(kmac_ctx, hash);
	int ret = lc_kmac_init(kmac_ctx, key, keylen, s, slen);

	if (ret)
		return ret;
	lc_kmac_update(kmac_ctx, in, inlen);
	lc_kmac_final(kmac_ctx, mac, maclen);

	lc_kmac_zero(kmac_ctx);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_kmac_xof, const struct lc_hash *hash,
		      const uint8_t *key, size_t keylen, const uint8_t *s,
		      size_t slen, const uint8_t *in, size_t inlen,
		      uint8_t *mac, size_t maclen)
{
	LC_KMAC_CTX_ON_STACK(kmac_ctx, hash);
	int ret = lc_kmac_init(kmac_ctx, key, keylen, s, slen);

	if (ret)
		return ret;
	lc_kmac_update(kmac_ctx, in, inlen);
	lc_kmac_final_xof(kmac_ctx, mac, maclen);

	lc_kmac_zero(kmac_ctx);

	return 0;
}

LC_INTERFACE_FUNCTION(size_t, lc_kmac_macsize, struct lc_kmac_ctx *kmac_ctx)
{
	struct lc_hash_ctx *hash_ctx;

	if (!kmac_ctx)
		return 0;

	hash_ctx = &kmac_ctx->hash_ctx;
	return lc_hash_digestsize(hash_ctx);
}

static int lc_kmac_rng_seed(void *_state, const uint8_t *seed, size_t seedlen,
			    const uint8_t *persbuf, size_t perslen)
{
	struct lc_kmac_ctx *state = _state;
	int ret;

	if (state->rng_initialized) {
		lc_kmac_update(state, seed, seedlen);
		lc_kmac_update(state, persbuf, perslen);
		return 0;
	}

	ret = lc_kmac_init(state, seed, seedlen, persbuf, perslen);
	if (ret)
		return ret;

	state->rng_initialized = 1;

	return 0;
}

static int lc_kmac_rng_generate(void *_state, const uint8_t *addtl_input,
				size_t addtl_input_len, uint8_t *out,
				size_t outlen)
{
	struct lc_kmac_ctx *kmac_ctx = _state;

	if (!kmac_ctx)
		return -EINVAL;

	if (addtl_input_len)
		lc_kmac_update(kmac_ctx, addtl_input, addtl_input_len);

	lc_kmac_final_xof_internal(kmac_ctx, out, outlen);
	return 0;
}

static void lc_kmac_rng_zero(void *_state)
{
	struct lc_kmac_ctx *state = _state;

	if (!state)
		return;

	lc_kmac_zero(state);
}

LC_INTERFACE_FUNCTION(int, lc_kmac_rng_alloc, struct lc_rng_ctx **state,
		      const struct lc_hash *hash)
{
	struct lc_rng_ctx *out_state;
	int ret;

	if (!state)
		return -EINVAL;

	ret = lc_alloc_aligned_secure((void *)&out_state,
				      LC_HASH_COMMON_ALIGNMENT,
				      LC_KMAC_KDF_DRNG_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_KMAC_KDF_RNG_CTX(out_state, hash);

	lc_kmac_rng_zero(out_state->rng_state);

	*state = out_state;

	return 0;
}

static const struct lc_rng _lc_kmac = {
	.generate = lc_kmac_rng_generate,
	.seed = lc_kmac_rng_seed,
	.zero = lc_kmac_rng_zero,
};
LC_INTERFACE_SYMBOL(const struct lc_rng *, lc_kmac_rng) = &_lc_kmac;
