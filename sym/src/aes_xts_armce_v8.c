/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "aes_armce.h"
#include "aes_internal.h"
#include "asm/ARMv8/aes_armv8_ce.h"
#include "compare.h"
#include "ext_headers_arm.h"
#include "fips_mode.h"
#include "lc_memcmp_secure.h"
#include "lc_sym.h"
#include "mode_xts.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct aes_v8_block_ctx enc_block_ctx;
	struct aes_v8_block_ctx dec_block_ctx;
	struct aes_v8_block_ctx tweak_ctx;
	union lc_xts_tweak tweak;
	uint8_t iv_tweaked;
};

#define LC_AES_ARMV8_XTS_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_armce_xts_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
				  uint8_t *out, size_t len)
{
	if (!ctx)
		return;

	LC_NEON_ENABLE;
	aes_v8_xts_encrypt(in, out, len, &ctx->enc_block_ctx, &ctx->tweak_ctx,
			   ctx->tweak.b, ctx->iv_tweaked);
	LC_NEON_DISABLE;

	/* IV was tweaked during first processing. */
	ctx->iv_tweaked = 1;

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, len);
}

static void aes_armce_xts_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
				  uint8_t *out, size_t len)
{
	if (!ctx)
		return;

	LC_NEON_ENABLE;
	aes_v8_xts_decrypt(in, out, len, &ctx->dec_block_ctx, &ctx->tweak_ctx,
			   ctx->tweak.b, ctx->iv_tweaked);
	LC_NEON_DISABLE;

	/* IV was tweaked during first processing. */
	ctx->iv_tweaked = 1;

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, len);
}

static int aes_armce_xts_init_nocheck(struct lc_sym_state *ctx)
{
	(void)ctx;
	return 0;
}

static int aes_armce_xts_init(struct lc_sym_state *ctx)
{
	(void)ctx;

	mode_xts_selftest(lc_aes_xts_armce);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_AES_XTS);

	return 0;
}

static int aes_armce_xts_setkey(struct lc_sym_state *ctx, const uint8_t *key,
				size_t keylen)
{
	size_t one_keylen;
	int ret;

	if (!ctx)
		return -EINVAL;

	one_keylen = keylen >> 1;

	ret = aes_check_keylen(one_keylen);
	if (ret)
		return ret;

	/* Reject XTS key where both parts are identical */
	if (fips140_mode_enabled() &&
	    !lc_memcmp_secure(key, one_keylen, key + one_keylen, one_keylen))
		return -ENOKEY;

	/* Timecop: key is sensitive. */
	poison(key, keylen);

	LC_NEON_ENABLE;
	CKINT(aes_v8_set_encrypt_key(key, (unsigned int)(one_keylen << 3),
				     &ctx->enc_block_ctx));
	CKINT(aes_v8_set_decrypt_key(key, (unsigned int)(one_keylen << 3),
				     &ctx->dec_block_ctx));
	CKINT(aes_v8_set_encrypt_key(key + one_keylen,
				     (unsigned int)(one_keylen << 3),
				     &ctx->tweak_ctx));

	/* Let first enc/dec operation tweak the IV */
	ctx->iv_tweaked = 0;

out:
	LC_NEON_DISABLE;
	unpoison(key, keylen);
	return ret;
}

static int aes_armce_xts_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			       size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(ctx->tweak.b, iv, AES_BLOCKLEN);

	/* Let first enc/dec operation tweak the IV */
	ctx->iv_tweaked = 0;

	return 0;
}

static int aes_armce_xts_getiv(const struct lc_sym_state *ctx, uint8_t *iv,
			       size_t ivlen)
{
	if (!ctx || !iv || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(iv, ctx->tweak.b, AES_BLOCKLEN);
	return 0;
}

static const struct lc_sym _lc_aes_xts_armce = {
	.init = aes_armce_xts_init,
	.init_nocheck = aes_armce_xts_init_nocheck,
	.setkey = aes_armce_xts_setkey,
	.setiv = aes_armce_xts_setiv,
	.getiv = aes_armce_xts_getiv,
	.encrypt = aes_armce_xts_encrypt,
	.decrypt = aes_armce_xts_decrypt,
	.statesize = LC_AES_ARMV8_XTS_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
	.algorithm_type = LC_ALG_STATUS_AES_XTS
};
LC_INTERFACE_SYMBOL(const struct lc_sym *,
		    lc_aes_xts_armce) = &_lc_aes_xts_armce;
