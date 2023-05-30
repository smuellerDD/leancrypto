/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#include "aes_aesni.h"
#include "aes_internal.h"
#include "asm/AESNI_x86_64/aes_aesni_x86_64.h"
#include "bitshift.h"
#include "ext_headers_x86.h"
#include "lc_sym.h"
#include "mode_ctr.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct aes_aesni_block_ctx enc_block_ctx;
	uint8_t iv[AES_BLOCKLEN];
};

#define LC_AES_AESNI_CTR_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_aesni_ctr96_inc(struct lc_sym_state *ctx)
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

static void aes_aesni_ctr_crypt(struct lc_sym_state *ctx,
				const uint8_t *in, uint8_t *out, size_t len)
{
	size_t blocks = len >> 4, block_bytes = blocks << 4;
	uint32_t ctr32;

	if (!ctx)
		return;

	LC_FPU_ENABLE;

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

		aesni_ctr32_encrypt_blocks(in, out, todo, &ctx->enc_block_ctx,
					   ctx->iv);

		/* CTR is not updated by cipher operation */
		be32_to_ptr(&ctx->iv[12], ctr32);
		if (ctr32 == 0)
			aes_aesni_ctr96_inc(ctx);

		blocks -= todo;
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

		memcpy(buffer, in + block_bytes, residual_len);

		aesni_ctr32_encrypt_blocks(buffer, buffer, 1,
					   &ctx->enc_block_ctx, ctx->iv);
		memcpy(out + block_bytes, buffer, residual_len);
		lc_memset_secure(buffer, 0, sizeof(buffer));

		be32_to_ptr(&ctx->iv[12], ctr32);
		if (ctr32 == 0)
			aes_aesni_ctr96_inc(ctx);
	}

	LC_FPU_DISABLE;
}

static void aes_aesni_ctr_init(struct lc_sym_state *ctx)
{
	static int tested = 0;

	(void)ctx;

	mode_ctr_selftest(lc_aes_ctr_aesni, &tested, "AES-CTR");
}

static int aes_aesni_ctr_setkey(struct lc_sym_state *ctx,
				const uint8_t *key, size_t keylen)
{
	int ret;

	if (!ctx)
		return -EINVAL;

	LC_FPU_ENABLE;
	CKINT(aesni_set_encrypt_key(key, (unsigned int)(keylen << 3),
				    &ctx->enc_block_ctx));

out:
	LC_FPU_DISABLE;
	return ret;
}

static int aes_aesni_ctr_setiv(struct lc_sym_state *ctx,
			       const uint8_t *iv, size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(ctx->iv, iv, AES_BLOCKLEN);
	return 0;
}

static struct lc_sym _lc_aes_ctr_aesni = {
	.init		= aes_aesni_ctr_init,
	.setkey		= aes_aesni_ctr_setkey,
	.setiv		= aes_aesni_ctr_setiv,
	.encrypt	= aes_aesni_ctr_crypt,
	.decrypt	= aes_aesni_ctr_crypt,
	.statesize	= LC_AES_AESNI_CTR_BLOCK_SIZE,
	.blocksize	= 1,
};
LC_INTERFACE_SYMBOL(
const struct lc_sym *, lc_aes_ctr_aesni) = &_lc_aes_ctr_aesni;
