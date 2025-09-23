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
#include "lc_sym.h"
#include "mode_cbc.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct aes_v8_block_ctx enc_block_ctx;
	struct aes_v8_block_ctx dec_block_ctx;
	uint8_t iv[AES_BLOCKLEN];
};

#define LC_AES_ARMV8_CBC_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_armce_cbc_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
				  uint8_t *out, size_t len)
{
	size_t round_len = len & ~(AES_BLOCKLEN - 1);

	if (!ctx)
		return;

	LC_NEON_ENABLE;
	aes_v8_cbc_encrypt(in, out, round_len, &ctx->enc_block_ctx, ctx->iv, 1);
	LC_NEON_DISABLE;

	/*
	 * Trailing data that is not multiple of block len cannot be encrypted
	 * and thus the corresponding part in the output block is zeroized.
	 */
	if (len > round_len)
		memset(out + round_len, 0, len - round_len);
}

static void aes_armce_cbc_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
				  uint8_t *out, size_t len)
{
	size_t round_len = len & ~(AES_BLOCKLEN - 1);

	if (!ctx)
		return;

	LC_NEON_ENABLE;
	aes_v8_cbc_encrypt(in, out, round_len, &ctx->dec_block_ctx, ctx->iv, 0);
	LC_NEON_DISABLE;

	/*
	 * Trailing data that is not multiple of block len cannot be decrypted
	 * and thus the corresponding part in the output block is zeroized.
	 */
	if (len > round_len)
		memset(out + round_len, 0, len - round_len);
}

static int aes_armce_cbc_init_nocheck(struct lc_sym_state *ctx)
{
	(void)ctx;

	return 0;
}

static int aes_armce_cbc_init(struct lc_sym_state *ctx)
{
	(void)ctx;

	mode_cbc_selftest(lc_aes_cbc_armce);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_AES_CBC);

	return 0;
}

static int aes_armce_cbc_setkey(struct lc_sym_state *ctx, const uint8_t *key,
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

static int aes_armce_cbc_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			       size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(ctx->iv, iv, AES_BLOCKLEN);
	return 0;
}

static const struct lc_sym _lc_aes_cbc_armce = {
	.init = aes_armce_cbc_init,
	.init_nocheck = aes_armce_cbc_init_nocheck,
	.setkey = aes_armce_cbc_setkey,
	.setiv = aes_armce_cbc_setiv,
	.encrypt = aes_armce_cbc_encrypt,
	.decrypt = aes_armce_cbc_decrypt,
	.statesize = LC_AES_ARMV8_CBC_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
	.algorithm_type = LC_ALG_STATUS_AES_CBC
};
LC_INTERFACE_SYMBOL(const struct lc_sym *,
		    lc_aes_cbc_armce) = &_lc_aes_cbc_armce;
