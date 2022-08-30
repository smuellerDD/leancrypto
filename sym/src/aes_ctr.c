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
#include "lc_ctr_private.h"
#include "lc_sym.h"
#include "math_helper.h"
#include "memset_secure.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct aes_block_ctx block_ctx;
	uint64_t iv[AES_CTR128_64BIT_WORDS];
};

#define LC_AES_CTR_BLOCK_SIZE sizeof(struct lc_sym_state)

/*
 * Symmetrical operation: same function for encrypting as for decrypting.
 * Note any IV/nonce should never be reused with the same key.
 */
static void aes_ctr_crypt(struct lc_sym_state *ctx,
			  const uint8_t *in, uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx = &ctx->block_ctx;
	uint8_t buffer[AES_BLOCKLEN];
	size_t i, todo = min_t(size_t, len, AES_BLOCKLEN);

	if (in != out)
		memcpy(out, in, len);

	for (i = 0; i < len; i += todo) {
		/* we need to regen xor compliment in buffer */
		ctr128_to_ptr(buffer, ctx->iv);
		aes_cipher((state_t*)buffer, block_ctx);
		ctr128_inc(ctx->iv);
		xor_64(out + i, buffer, AES_BLOCKLEN);
		todo = min_t(size_t, len - i, AES_BLOCKLEN);
	}

	memset_secure(buffer, 0, sizeof(buffer));
}

static void aes_ctr_init(struct lc_sym_state *ctx)
{
	(void)ctx;
}

static int aes_ctr_setkey(struct lc_sym_state *ctx,
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

static int aes_ctr_setiv(struct lc_sym_state *ctx,
			 const uint8_t *iv, size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	ptr_to_ctr128(ctx->iv, iv);
	return 0;
}

static struct lc_sym _lc_aes_ctr = {
	.init		= aes_ctr_init,
	.setkey		= aes_ctr_setkey,
	.setiv		= aes_ctr_setiv,
	.encrypt	= aes_ctr_crypt,
	.decrypt	= aes_ctr_crypt,
	.statesize	= LC_AES_CTR_BLOCK_SIZE,
	.blocksize	= 1,
};
DSO_PUBLIC const struct lc_sym *lc_aes_ctr = &_lc_aes_ctr;
