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
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "mode_cbc.h"
#include "visibility.h"

struct lc_sym_state {
	struct lc_mode_state cbc_state;
	struct aes_riscv64_block_ctx enc_block_ctx;
	struct aes_riscv64_block_ctx dec_block_ctx;
};

#define LC_AES_CBC_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_riscv64_cbc_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
				    uint8_t *out, size_t len)
{
	lc_mode_cbc_c->encrypt(&ctx->cbc_state, in, out, len);
}

static void aes_riscv64_cbc_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
				    uint8_t *out, size_t len)
{
	lc_mode_cbc_c->decrypt(&ctx->cbc_state, in, out, len);
}

static void aes_riscv64_cbc_init(struct lc_sym_state *ctx)
{
	static int tested = 0;

	(void)ctx;

	mode_cbc_selftest(lc_aes_cbc_riscv64, &tested, "AES-CBC");
	lc_mode_cbc_c->init(&ctx->cbc_state, lc_aes_riscv64,
			    &ctx->enc_block_ctx);
}

static int aes_riscv64_cbc_setkey(struct lc_sym_state *ctx, const uint8_t *key,
				  size_t keylen)
{
	if (!ctx)
		return -EINVAL;
	return lc_mode_cbc_c->setkey(&ctx->cbc_state, key, keylen);
}

static int aes_riscv64_cbc_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
				 size_t ivlen)
{
	return lc_mode_cbc_c->setiv(&ctx->cbc_state, iv, ivlen);
}

static struct lc_sym _lc_aes_cbc_riscv64 = {
	.init = aes_riscv64_cbc_init,
	.setkey = aes_riscv64_cbc_setkey,
	.setiv = aes_riscv64_cbc_setiv,
	.encrypt = aes_riscv64_cbc_encrypt,
	.decrypt = aes_riscv64_cbc_decrypt,
	.statesize = LC_AES_CBC_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *,
		    lc_aes_cbc_riscv64) = &_lc_aes_cbc_riscv64;
