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
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "lc_memset_secure.h"
#include "mode_kw.h"
#include "visibility.h"

struct lc_sym_state {
	struct lc_mode_state kw_state;
	struct aes_block_ctx block_ctx;
};

#define LC_AES_KW_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_kw_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
			   uint8_t *out, size_t len)
{
	lc_mode_kw_c->encrypt(&ctx->kw_state, in, out, len);
}

static void aes_kw_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
			   uint8_t *out, size_t len)
{
	lc_mode_kw_c->decrypt(&ctx->kw_state, in, out, len);
}

static void aes_kw_init(struct lc_sym_state *ctx)
{
	static int tested = 0;

	mode_kw_selftest(lc_aes_kw_c, &tested, "AES-KW");
	lc_mode_kw_c->init(&ctx->kw_state, lc_aes_c, &ctx->block_ctx, NULL);
}

static int aes_kw_setkey(struct lc_sym_state *ctx, const uint8_t *key,
			 size_t keylen)
{
	if (!ctx)
		return -EINVAL;
	return lc_mode_kw_c->setkey(&ctx->kw_state, key, keylen);
}

static int aes_kw_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			size_t ivlen)
{
	return lc_mode_kw_c->setiv(&ctx->kw_state, iv, ivlen);
}

static struct lc_sym _lc_aes_kw_c = {
	.init = aes_kw_init,
	.setkey = aes_kw_setkey,
	.setiv = aes_kw_setiv,
	.encrypt = aes_kw_encrypt,
	.decrypt = aes_kw_decrypt,
	.statesize = LC_AES_KW_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_kw_c) = &_lc_aes_kw_c;

LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_kw) = &_lc_aes_kw_c;
