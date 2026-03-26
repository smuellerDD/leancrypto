/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
			uint8_t *out, size_t len,
			void (*encrypt)(state_t *state,
					const struct aes_block_ctx *block_ctx))
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
	encrypt((state_t *)out, block_ctx);

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, AES_BLOCKLEN);
}

static void aes_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
			uint8_t *out, size_t len,
			void (*decrypt)(state_t *state,
					const struct aes_block_ctx *block_ctx))
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
	decrypt((state_t *)out, block_ctx);

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, AES_BLOCKLEN);
}

static int aes_init(struct lc_sym_state *ctx)
{
	(void)ctx;

	BUILD_BUG_ON(LC_AES_C_MAX_BLOCK_SIZE < LC_AES_BLOCK_SIZE);

	/*
	 * Verification that the CTX size in LC_AES_CTX_ON_STACK is
	 * sufficient.
	 */
	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE < LC_AES_ARMCE_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE <
		     LC_AES_RISCV64_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE < LC_AES_C_MAX_BLOCK_SIZE);

	return 0;
}

static int
aes_setkey(struct lc_sym_state *ctx, const uint8_t *key, size_t keylen,
	   void (*setkey)(struct aes_block_ctx *block_ctx, const uint8_t *key))
{
	int ret;

	/* Timecop: key is sensitive. */
	poison(key, keylen);

	if (!ctx)
		return -EINVAL;

	ret = aes_set_type(&ctx->block_ctx, keylen);
	if (!ret)
		setkey(&ctx->block_ctx, key);

	return 0;
}

static int aes_setiv(struct lc_sym_state *ctx, const uint8_t *iv, size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static int aes_getiv(const struct lc_sym_state *ctx, uint8_t *iv, size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static int aes_setkey_c_internal(struct lc_sym_state *ctx, const uint8_t *key,
				 size_t keylen)
{
	return aes_setkey(ctx, key, keylen, aes_setkey_c);
}

static void aes_encrypt_c_internal(struct lc_sym_state *ctx, const uint8_t *in,
				   uint8_t *out, size_t len)
{
	aes_encrypt(ctx, in, out, len, aes_encrypt_c);
}

static void aes_decrypt_c_internal(struct lc_sym_state *ctx, const uint8_t *in,
				   uint8_t *out, size_t len)
{
	aes_decrypt(ctx, in, out, len, aes_decrypt_c);
}

static const struct lc_sym _lc_aes_sbox = {
	.init = aes_init,
	.init_nocheck = NULL,
	.setkey = aes_setkey_c_internal,
	.setiv = aes_setiv,
	.getiv = aes_getiv,
	.encrypt = aes_encrypt_c_internal,
	.decrypt = aes_decrypt_c_internal,
	.statesize = LC_AES_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_sbox) = &_lc_aes_sbox;

static int aes_setkey_ct_internal(struct lc_sym_state *ctx, const uint8_t *key,
				  size_t keylen)
{
	return aes_setkey(ctx, key, keylen, aes_setkey_ct);
}

static void aes_encrypt_ct_internal(struct lc_sym_state *ctx, const uint8_t *in,
				    uint8_t *out, size_t len)
{
	aes_encrypt(ctx, in, out, len, aes_encrypt_ct);
}

static void aes_decrypt_ct_internal(struct lc_sym_state *ctx, const uint8_t *in,
				    uint8_t *out, size_t len)
{
	aes_decrypt(ctx, in, out, len, aes_decrypt_ct);
}

static const struct lc_sym _lc_aes_ct = {
	.init = aes_init,
	.init_nocheck = NULL,
	.setkey = aes_setkey_ct_internal,
	.setiv = aes_setiv,
	.getiv = aes_getiv,
	.encrypt = aes_encrypt_ct_internal,
	.decrypt = aes_decrypt_ct_internal,
	.statesize = LC_AES_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_ct) = &_lc_aes_ct;

LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_c) = &_lc_aes_ct;
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes) = &_lc_aes_ct;
