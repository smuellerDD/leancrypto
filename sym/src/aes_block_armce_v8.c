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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/kokke/tiny-AES-c
 *
 * This is free and unencumbered software released into the public domain.
 */

#include "aes_armce.h"
#include "aes_internal.h"
#include "asm/ARMv8/aes_armv8_ce.h"
#include "build_bug_on.h"
#include "ext_headers_arm.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "ret_checkers.h"
#include "visibility.h"

struct lc_sym_state {
	struct aes_v8_block_ctx enc_block_ctx;
	struct aes_v8_block_ctx dec_block_ctx;
};

#define LC_AES_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_armce_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
			      uint8_t *out, size_t len)
{
	if (!ctx || len != AES_BLOCKLEN)
		return;

	LC_NEON_ENABLE;
	aes_v8_encrypt(in, out, &ctx->enc_block_ctx);
	LC_NEON_DISABLE;
}

static void aes_armce_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
			      uint8_t *out, size_t len)
{
	if (!ctx || len != AES_BLOCKLEN)
		return;

	LC_NEON_ENABLE;
	aes_v8_decrypt(in, out, &ctx->dec_block_ctx);
	LC_NEON_DISABLE;
}

static int aes_armce_init(struct lc_sym_state *ctx)
{
	(void)ctx;

	BUILD_BUG_ON(LC_AES_ARMCE_MAX_BLOCK_SIZE < LC_AES_BLOCK_SIZE);

	return 0;
}

static int aes_armce_setkey(struct lc_sym_state *ctx, const uint8_t *key,
			    size_t keylen)
{
	int ret;

	if (!ctx)
		return -EINVAL;

	LC_NEON_ENABLE;
	CKINT(aes_v8_set_encrypt_key(key, (unsigned int)(keylen << 3),
				     &ctx->enc_block_ctx));
	CKINT(aes_v8_set_decrypt_key(key, (unsigned int)(keylen << 3),
				     &ctx->dec_block_ctx));

out:
	LC_NEON_DISABLE;
	return ret;
}

static int aes_armce_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			   size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static int aes_armce_getiv(const struct lc_sym_state *ctx, uint8_t *iv,
			   size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static const struct lc_sym _lc_aes_armce = {
	.init = aes_armce_init,
	.init_nocheck = NULL,
	.setkey = aes_armce_setkey,
	.setiv = aes_armce_setiv,
	.getiv = aes_armce_getiv,
	.encrypt = aes_armce_encrypt,
	.decrypt = aes_armce_decrypt,
	.statesize = LC_AES_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_armce) = &_lc_aes_armce;
