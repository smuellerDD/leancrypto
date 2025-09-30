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

#include "aes_riscv64.h"
#include "aes_internal.h"
#include "asm/riscv64/riscv64_aes_asm.h"
#include "compare.h"
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "mode_xts.h"
#include "visibility.h"

struct lc_sym_state {
	struct lc_mode_state xts_state;
	struct aes_riscv64_block_ctx tweak_ctx;
	struct aes_riscv64_block_ctx enc_block_ctx;
	struct aes_riscv64_block_ctx dec_block_ctx;
};

#define LC_AES_XTS_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_riscv64_xts_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
				    uint8_t *out, size_t len)
{
	lc_mode_xts_c->encrypt(&ctx->xts_state, in, out, len);
}

static void aes_riscv64_xts_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
				    uint8_t *out, size_t len)
{
	lc_mode_xts_c->decrypt(&ctx->xts_state, in, out, len);
}

static int aes_riscv64_xts_init_nocheck(struct lc_sym_state *ctx)
{
	lc_mode_xts_c->init(&ctx->xts_state, lc_aes_riscv64,
			    lc_aes_riscv64_enc_only, &ctx->enc_block_ctx,
			    &ctx->tweak_ctx);

	return 0;
}

static int aes_riscv64_xts_init(struct lc_sym_state *ctx)
{
	mode_xts_selftest(lc_aes_xts_riscv64);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_AES_XTS);

	return aes_riscv64_xts_init_nocheck(ctx);
}

static int aes_riscv64_xts_setkey(struct lc_sym_state *ctx, const uint8_t *key,
				  size_t keylen)
{
	if (!ctx)
		return -EINVAL;
	return lc_mode_xts_c->setkey(&ctx->xts_state, key, keylen);
}

static int aes_riscv64_xts_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
				 size_t ivlen)
{
	return lc_mode_xts_c->setiv(&ctx->xts_state, iv, ivlen);
}

static const struct lc_sym _lc_aes_xts_riscv64 = {
	.init = aes_riscv64_xts_init,
	.init_nocheck = aes_riscv64_xts_init_nocheck,
	.setkey = aes_riscv64_xts_setkey,
	.setiv = aes_riscv64_xts_setiv,
	.encrypt = aes_riscv64_xts_encrypt,
	.decrypt = aes_riscv64_xts_decrypt,
	.statesize = LC_AES_XTS_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
	.algorithm_type = LC_ALG_STATUS_AES_XTS
};
LC_INTERFACE_SYMBOL(const struct lc_sym *,
		    lc_aes_xts_riscv64) = &_lc_aes_xts_riscv64;
