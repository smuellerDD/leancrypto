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

#include <errno.h>
#include <string.h>

#include "lc_aes.h"
#include "lc_aes_private.h"
#include "lc_sym.h"
#include "visibility.h"

struct lc_sym_state {
	struct aes_block_ctx block_ctx;
};

#define LC_AES_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_encrypt(struct lc_sym_state* ctx,
			const uint8_t *in, uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx = &ctx->block_ctx;

	if (len != AES_BLOCKLEN)
		return;

	if (in != out)
		memcpy(out, in, AES_BLOCKLEN);

	/* In-place encryption operation of plaintext. */
	aes_cipher((state_t*)out, block_ctx);
}

static void aes_decrypt(struct lc_sym_state* ctx,
			const uint8_t *in, uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx = &ctx->block_ctx;

	if (len != AES_BLOCKLEN)
		return;

	if (in != out)
		memcpy(out, in, AES_BLOCKLEN);

	/* In-place decryption operation of plaintext. */
	aes_inv_cipher((state_t*)out, block_ctx);
}

static void aes_ecb_init(struct lc_sym_state *ctx)
{
	(void)ctx;
}

static int aes_ecb_setkey(struct lc_sym_state *ctx,
			  const uint8_t *key, size_t keylen)
{
	if (!ctx || keylen != AES_KEYLEN)
		return -EINVAL;

	KeyExpansion(&ctx->block_ctx, key);

	return 0;
}

static int aes_ecb_setiv(struct lc_sym_state *ctx,
			 const uint8_t *iv, size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static struct lc_sym _lc_aes = {
	.init		= aes_ecb_init,
	.setkey		= aes_ecb_setkey,
	.setiv		= aes_ecb_setiv,
	.encrypt	= aes_encrypt,
	.decrypt	= aes_decrypt,
	.statesize	= LC_AES_BLOCK_SIZE,
	.blocksize	= AES_BLOCKLEN,
};
DSO_PUBLIC const struct lc_sym *lc_aes = &_lc_aes;
