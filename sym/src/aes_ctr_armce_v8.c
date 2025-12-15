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
#include "bitshift.h"
#include "compare.h"
#include "ext_headers_arm.h"
#include "lc_sym.h"
#include "mode_ctr.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct aes_v8_block_ctx enc_block_ctx;
	uint8_t iv[AES_BLOCKLEN];
};

#define LC_AES_ARMV8_CTR_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_armce_ctr96_inc(struct lc_sym_state *ctx)
{
	uint32_t ctr32 = ptr_to_be32(&ctx->iv[8]);

	ctr32++;
	be32_to_ptr(&ctx->iv[8], ctr32);
	if (ctr32 == 0) {
		ctr32 = ptr_to_be32(&ctx->iv[4]);
		ctr32++;
		be32_to_ptr(&ctx->iv[4], ctr32);
		if (ctr32 == 0) {
			ctr32 = ptr_to_be32(&ctx->iv[0]);
			ctr32++;
			be32_to_ptr(&ctx->iv[0], ctr32);
		}
	}
}

static void aes_armce_ctr_crypt(struct lc_sym_state *ctx, const uint8_t *in,
				uint8_t *out, size_t len)
{
	size_t blocks = len >> 4, block_bytes = blocks << 4;
	uint32_t ctr32;

	if (!ctx)
		return;

	LC_NEON_ENABLE;

	while (blocks) {
		size_t todo;

		ctr32 = ptr_to_be32(&ctx->iv[12]);

		/* Cipher operation is limited to 32LSB of the counter */
		ctr32 += (uint32_t)blocks;
		if (ctr32 < blocks) {
			/* Do not encrypt more than if it would wrap */
			todo = blocks - ctr32;
			ctr32 = 0;
		} else {
			todo = blocks;
		}

		aes_v8_ctr32_encrypt_blocks(in, out, todo, &ctx->enc_block_ctx,
					    ctx->iv);

		/* CTR is not updated by cipher operation */
		be32_to_ptr(&ctx->iv[12], ctr32);
		if (ctr32 == 0)
			aes_armce_ctr96_inc(ctx);

		blocks -= todo;

		/* Convert todo back into bytes */
		todo <<= 4;

		out += todo;
		in += todo;
	}

	/*
	 * Trailing data that is not multiple of block len are en/decrypted
	 * with this call
	 */
	if (len > block_bytes) {
		uint8_t buffer[AES_BLOCKLEN] = { 0 };
		size_t residual_len = len - block_bytes;

		ctr32 = ptr_to_be32(&ctx->iv[12]);
		ctr32++;

		memcpy(buffer, in, residual_len);

		aes_v8_ctr32_encrypt_blocks(buffer, buffer, 1,
					    &ctx->enc_block_ctx, ctx->iv);
		memcpy(out, buffer, residual_len);

		lc_memset_secure(buffer, 0, sizeof(buffer));

		be32_to_ptr(&ctx->iv[12], ctr32);
		if (ctr32 == 0)
			aes_armce_ctr96_inc(ctx);
	}

	LC_NEON_DISABLE;
}

static int aes_armce_ctr_init_nocheck(struct lc_sym_state *ctx)
{
	(void)ctx;
	return 0;
}

static int aes_armce_ctr_init(struct lc_sym_state *ctx)
{
	(void)ctx;

	mode_ctr_selftest(lc_aes_ctr_armce);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_AES_CTR);

	return 0;
}

static int aes_armce_ctr_setkey(struct lc_sym_state *ctx, const uint8_t *key,
				size_t keylen)
{
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = aes_check_keylen(keylen);
	if (ret)
		return ret;

	LC_NEON_ENABLE;
	CKINT(aes_v8_set_encrypt_key(key, (unsigned int)(keylen << 3),
				     &ctx->enc_block_ctx));

out:
	LC_NEON_DISABLE;
	return ret;
}

static int aes_armce_ctr_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			       size_t ivlen)
{
	if (!ctx || !iv || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(ctx->iv, iv, AES_BLOCKLEN);
	return 0;
}

static int aes_armce_ctr_getiv(const struct lc_sym_state *ctx, uint8_t *iv,
			       size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(iv, ctx->iv, AES_BLOCKLEN);
	return 0;
}

static const struct lc_sym _lc_aes_ctr_armce = {
	.init = aes_armce_ctr_init,
	.init_nocheck = aes_armce_ctr_init_nocheck,
	.setkey = aes_armce_ctr_setkey,
	.setiv = aes_armce_ctr_setiv,
	.getiv = aes_armce_ctr_getiv,
	.encrypt = aes_armce_ctr_crypt,
	.decrypt = aes_armce_ctr_crypt,
	.statesize = LC_AES_ARMV8_CTR_BLOCK_SIZE,
	.blocksize = 1,
	.algorithm_type = LC_ALG_STATUS_AES_CTR
};
LC_INTERFACE_SYMBOL(const struct lc_sym *,
		    lc_aes_ctr_armce) = &_lc_aes_ctr_armce;
