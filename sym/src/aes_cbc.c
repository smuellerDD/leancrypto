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

#include "aes_c.h"
#include "aes_internal.h"
#include "compare.h"
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "mode_cbc.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct lc_mode_state cbc_state;
	struct aes_block_ctx block_ctx;
};

#define LC_AES_CBC_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_cbc_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
			    uint8_t *out, size_t len)
{
	lc_mode_cbc_c->encrypt(&ctx->cbc_state, in, out, len);
}

static void aes_cbc_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
			    uint8_t *out, size_t len)
{
	lc_mode_cbc_c->decrypt(&ctx->cbc_state, in, out, len);
}

static int aes_cbc_init_nocheck(struct lc_sym_state *ctx)
{
	lc_mode_cbc_c->init(&ctx->cbc_state, lc_aes_c, NULL, &ctx->block_ctx,
			    NULL);
	return 0;
}

static int aes_cbc_init(struct lc_sym_state *ctx)
{
	mode_cbc_selftest(lc_aes_cbc_c);
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_AES_CBC);

	return aes_cbc_init_nocheck(ctx);
}

static int aes_cbc_setkey(struct lc_sym_state *ctx, const uint8_t *key,
			  size_t keylen)
{
	if (!ctx)
		return -EINVAL;
	return lc_mode_cbc_c->setkey(&ctx->cbc_state, key, keylen);
}

static int aes_cbc_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			 size_t ivlen)
{
	return lc_mode_cbc_c->setiv(&ctx->cbc_state, iv, ivlen);
}

static const struct lc_sym _lc_aes_cbc_c = { .init = aes_cbc_init,
					     .init_nocheck =
						     aes_cbc_init_nocheck,
					     .setkey = aes_cbc_setkey,
					     .setiv = aes_cbc_setiv,
					     .encrypt = aes_cbc_encrypt,
					     .decrypt = aes_cbc_decrypt,
					     .statesize = LC_AES_CBC_BLOCK_SIZE,
					     .blocksize = AES_BLOCKLEN,
					     .algorithm_type =
						     LC_ALG_STATUS_AES_CBC };
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_cbc_c) = &_lc_aes_cbc_c;

LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_cbc) = &_lc_aes_cbc_c;
