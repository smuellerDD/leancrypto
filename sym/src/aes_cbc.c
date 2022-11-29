/*
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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/kokke/tiny-AES-c
 *
 * This is free and unencumbered software released into the public domain.
 */

#include "ext_headers.h"
#include "lc_aes.h"
#include "lc_aes_private.h"
#include "lc_sym.h"
#include "lc_memset_secure.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct aes_block_ctx block_ctx;
	uint8_t iv[AES_BLOCKLEN];
};

#define LC_AES_CBC_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_cbc_encrypt(struct lc_sym_state *ctx,
			    const uint8_t *in, uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx;
	size_t i, rounded_len = len & ~(AES_BLOCKLEN - 1);
	uint8_t *iv = ctx->iv;

	if (!ctx)
		return;
	block_ctx = &ctx->block_ctx;

	if (in != out)
		memcpy(out, in, rounded_len);

	for (i = 0; i < rounded_len; i += AES_BLOCKLEN, out += AES_BLOCKLEN) {
		xor_64(out, iv, AES_BLOCKLEN);
		aes_cipher((state_t*)out, block_ctx);
		iv = out;
	}
	/* store Iv in ctx for next call */
	memcpy(ctx->iv, iv, AES_BLOCKLEN);
}

static void aes_cbc_decrypt(struct lc_sym_state *ctx,
			    const uint8_t *in, uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx;
	size_t i, rounded_len = len & ~(AES_BLOCKLEN - 1);
	uint8_t storeNextIv[AES_BLOCKLEN];

	if (!ctx)
		return;
	block_ctx = &ctx->block_ctx;

	if (in != out)
		memcpy(out, in, rounded_len);

	for (i = 0; i < rounded_len; i += AES_BLOCKLEN, out += AES_BLOCKLEN) {
		memcpy(storeNextIv, out, AES_BLOCKLEN);
		aes_inv_cipher((state_t*)out, block_ctx);
		xor_64(out, ctx->iv, AES_BLOCKLEN);
		memcpy(ctx->iv, storeNextIv, AES_BLOCKLEN);
	}

	lc_memset_secure(storeNextIv, 0, sizeof(storeNextIv));
}

static void aes_cbc_init(struct lc_sym_state *ctx)
{
	(void)ctx;
}

static int aes_cbc_setkey(struct lc_sym_state *ctx,
			  const uint8_t *key, size_t keylen)
{
	int ret;

	if (!ctx)
		return -EINVAL;

	ret = aes_set_type(&ctx->block_ctx, keylen);
	if (!ret)
		KeyExpansion(&ctx->block_ctx, key);

	return ret;
}

static int aes_cbc_setiv(struct lc_sym_state *ctx,
			 const uint8_t *iv, size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(ctx->iv, iv, AES_BLOCKLEN);
	return 0;
}

static struct lc_sym _lc_aes_cbc = {
	.init		= aes_cbc_init,
	.setkey		= aes_cbc_setkey,
	.setiv		= aes_cbc_setiv,
	.encrypt	= aes_cbc_encrypt,
	.decrypt	= aes_cbc_decrypt,
	.statesize	= LC_AES_CBC_BLOCK_SIZE,
	.blocksize	= AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_cbc) = &_lc_aes_cbc;
