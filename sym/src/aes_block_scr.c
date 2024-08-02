/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * AES C implementation without using S-BOX
 *
 * This implementation is side-channel-resistant, but is very slow.
 */

#include "aes_c.h"
#include "aes_internal.h"
#include "alignment.h"
#include "build_bug_on.h"
#include "ext_headers.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "timecop.h"
#include "visibility.h"

struct lc_sym_state {
	struct aes_block_ctx block_ctx;
};

#define LC_AES_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_encrypt_scr(struct lc_sym_state *ctx, const uint8_t *in,
			    uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx;

	if (!ctx)
		return;
	block_ctx = &ctx->block_ctx;

	if (len != AES_BLOCKLEN)
		return;

	/* In-place encryption operation of plaintext. */
	if (aligned(out, sizeof(uint32_t) - 1)) {
		if (in != out)
			memcpy(out, in, AES_BLOCKLEN);

			/*
		 * We can ignore the alignment warning as we checked
		 * for proper alignment.
		 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		aes_cipher_scr((state_t *)out, block_ctx);
#pragma GCC diagnostic pop
	} else {
		state_t block;

		BUILD_BUG_ON(sizeof(block) != AES_BLOCKLEN);

		memcpy(&block, in, AES_BLOCKLEN);
		aes_cipher_scr(&block, block_ctx);
		memcpy(out, &block, AES_BLOCKLEN);
	}

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, AES_BLOCKLEN);
}

static void aes_decrypt_scr(struct lc_sym_state *ctx, const uint8_t *in,
			    uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx;

	if (!ctx)
		return;
	block_ctx = &ctx->block_ctx;

	if (len != AES_BLOCKLEN)
		return;

	if (aligned(out, sizeof(uint32_t) - 1)) {
		if (in != out)
			memcpy(out, in, AES_BLOCKLEN);

			/*
		 * We can ignore the alignment warning as we checked
		 * for proper alignment.
		 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		aes_inv_cipher_scr((state_t *)out, block_ctx);
#pragma GCC diagnostic pop
	} else {
		state_t block;

		BUILD_BUG_ON(sizeof(block) != AES_BLOCKLEN);

		memcpy(&block, in, AES_BLOCKLEN);
		aes_inv_cipher_scr(&block, block_ctx);
		memcpy(out, &block, AES_BLOCKLEN);
	}

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, AES_BLOCKLEN);
}

static void aes_init(struct lc_sym_state *ctx)
{
	(void)ctx;
}

static int aes_setkey_scr(struct lc_sym_state *ctx, const uint8_t *key,
			  size_t keylen)
{
	int ret;

	/* Timecop: key is sensitive. */
	poison(key, keylen);

	if (!ctx)
		return -EINVAL;

	ret = aes_set_type(&ctx->block_ctx, keylen);
	if (!ret)
		aes_key_expansion_scr(&ctx->block_ctx, key);

	return 0;
}

static int aes_setiv(struct lc_sym_state *ctx, const uint8_t *iv, size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static struct lc_sym _lc_aes_scr = {
	.init = aes_init,
	.setkey = aes_setkey_scr,
	.setiv = aes_setiv,
	.encrypt = aes_encrypt_scr,
	.decrypt = aes_decrypt_scr,
	.statesize = LC_AES_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_scr) = &_lc_aes_scr;
