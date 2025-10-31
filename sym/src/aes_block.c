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
 * AES C implementation using S-BOX
 *
 * This implementation is implements a side-channel-resistant key handling,
 * but does not prevent side-channels regarding the plaintext or ciphertext.
 * Furthermore it is decently fast compared to the full side-channel-resistant
 * implementation.
 */

#include "aes_c.h"
#include "aes_internal.h"
#include "build_bug_on.h"
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "timecop.h"
#include "visibility.h"

struct lc_sym_state {
	struct aes_block_ctx block_ctx;
};

#define LC_AES_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
			uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx;

	if (!ctx)
		return;
	block_ctx = &ctx->block_ctx;

	if (len != AES_BLOCKLEN)
		return;

	if (in != out)
		memcpy(out, in, AES_BLOCKLEN);

	/* In-place encryption operation of plaintext. */
	aes_cipher((state_t *)out, block_ctx);

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, AES_BLOCKLEN);
}

static void aes_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
			uint8_t *out, size_t len)
{
	const struct aes_block_ctx *block_ctx;

	if (!ctx)
		return;
	block_ctx = &ctx->block_ctx;

	if (len != AES_BLOCKLEN)
		return;

	if (in != out)
		memcpy(out, in, AES_BLOCKLEN);

	/* In-place decryption operation of plaintext. */
	aes_inv_cipher((state_t *)out, block_ctx);

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, AES_BLOCKLEN);
}

static int aes_init(struct lc_sym_state *ctx)
{
	(void)ctx;

	BUILD_BUG_ON(LC_AES_C_MAX_BLOCK_SIZE < LC_AES_BLOCK_SIZE);

	return 0;
}

static int aes_setkey(struct lc_sym_state *ctx, const uint8_t *key,
		      size_t keylen)
{
	int ret;

	/* Timecop: key is sensitive. */
	poison(key, keylen);

	if (!ctx)
		return -EINVAL;

	ret = aes_set_type(&ctx->block_ctx, keylen);
	if (!ret)
		aes_key_expansion(&ctx->block_ctx, key);

	return 0;
}

static int aes_setiv(struct lc_sym_state *ctx, const uint8_t *iv, size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static const struct lc_sym _lc_aes_c = {
	.init = aes_init,
	.init_nocheck = NULL,
	.setkey = aes_setkey,
	.setiv = aes_setiv,
	.encrypt = aes_encrypt,
	.decrypt = aes_decrypt,
	.statesize = LC_AES_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_c) = &_lc_aes_c;

LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes) = &_lc_aes_c;
