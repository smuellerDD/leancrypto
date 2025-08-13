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
#include "mode_ctr.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct lc_mode_state ctr_state;
	struct aes_block_ctx block_ctx;
};

#define LC_AES_CTR_BLOCK_SIZE sizeof(struct lc_sym_state)

/*
 * Symmetrical operation: same function for encrypting as for decrypting.
 * Note any IV/nonce should never be reused with the same key.
 */
static void aes_ctr_crypt(struct lc_sym_state *ctx, const uint8_t *in,
			  uint8_t *out, size_t len)
{
	lc_mode_ctr_c->encrypt(&ctx->ctr_state, in, out, len);
}

static void aes_ctr_init(struct lc_sym_state *ctx)
{
	static int tested = 0;

	mode_ctr_selftest(lc_aes_ctr_c, &tested, "AES-CTR");
	lc_mode_ctr_c->init(&ctx->ctr_state, lc_aes_c, &ctx->block_ctx);
}

static int aes_ctr_setkey(struct lc_sym_state *ctx, const uint8_t *key,
			  size_t keylen)
{
	if (!ctx)
		return -EINVAL;
	return lc_mode_ctr_c->setkey(&ctx->ctr_state, key, keylen);
}

static int aes_ctr_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			 size_t ivlen)
{
	return lc_mode_ctr_c->setiv(&ctx->ctr_state, iv, ivlen);
}

static struct lc_sym _lc_aes_ctr_c = {
	.init = aes_ctr_init,
	.setkey = aes_ctr_setkey,
	.setiv = aes_ctr_setiv,
	.encrypt = aes_ctr_crypt,
	.decrypt = aes_ctr_crypt,
	.statesize = LC_AES_CTR_BLOCK_SIZE,
	.blocksize = 1,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_ctr_c) = &_lc_aes_ctr_c;

LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_ctr) = &_lc_aes_ctr_c;
