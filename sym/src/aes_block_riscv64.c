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

#include "aes_riscv64.h"
#include "aes_internal.h"
#include "asm/riscv64/riscv64_aes_asm.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "ret_checkers.h"
#include "visibility.h"

struct lc_sym_state {
	struct aes_riscv64_block_ctx enc_block_ctx;
	struct aes_riscv64_block_ctx dec_block_ctx;
};

#define LC_AES_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_riscv64_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
				uint8_t *out, size_t len)
{
	if (!ctx || len != AES_BLOCKLEN)
		return;

	aes_riscv64_encrypt_asm(in, out, &ctx->enc_block_ctx);
}

static void aes_riscv64_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
				uint8_t *out, size_t len)
{
	if (!ctx || len != AES_BLOCKLEN)
		return;

	aes_riscv64_decrypt_asm(in, out, &ctx->dec_block_ctx);
}

static void aes_riscv64_init(struct lc_sym_state *ctx)
{
	(void)ctx;
}

static int aes_riscv64_setkey(struct lc_sym_state *ctx, const uint8_t *key,
			      size_t keylen)
{
	int ret;

	if (!ctx)
		return -EINVAL;

	CKINT(aes_riscv64_set_encrypt_key(key, (unsigned int)(keylen << 3),
					  &ctx->enc_block_ctx));
	CKINT(aes_riscv64_set_decrypt_key(key, (unsigned int)(keylen << 3),
					  &ctx->dec_block_ctx));

out:
	return ret;
}

static int aes_riscv64_setkey_enc_only(struct lc_sym_state *ctx,
				       const uint8_t *key, size_t keylen)
{
	int ret;

	if (!ctx)
		return -EINVAL;

	CKINT(aes_riscv64_set_encrypt_key(key, (unsigned int)(keylen << 3),
					  &ctx->enc_block_ctx));

out:
	return ret;
}

static int aes_riscv64_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			     size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static struct lc_sym _lc_aes_riscv64 = {
	.init = aes_riscv64_init,
	.setkey = aes_riscv64_setkey,
	.setiv = aes_riscv64_setiv,
	.encrypt = aes_riscv64_encrypt,
	.decrypt = aes_riscv64_decrypt,
	.statesize = LC_AES_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_riscv64) = &_lc_aes_riscv64;

static struct lc_sym _lc_aes_riscv64_enc_only = {
	.init = aes_riscv64_init,
	.setkey = aes_riscv64_setkey_enc_only,
	.setiv = aes_riscv64_setiv,
	.encrypt = aes_riscv64_encrypt,
	.decrypt = aes_riscv64_decrypt,
	.statesize = LC_AES_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
const struct lc_sym *lc_aes_riscv64_enc_only = &_lc_aes_riscv64_enc_only;
