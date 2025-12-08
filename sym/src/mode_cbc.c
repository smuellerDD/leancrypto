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

#include "aes_c.h"
#include "aes_internal.h"
#include "compare.h"
#include "ext_headers_internal.h"
#include "fips_mode.h"
#include "lc_sym.h"
#include "lc_memset_secure.h"
#include "mode_cbc.h"
#include "timecop.h"
#include "visibility.h"
#include "xor.h"

#define LC_AES_CBC_BLOCK_SIZE sizeof(struct lc_mode_state)

void mode_cbc_selftest(const struct lc_sym *aes)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t iv[] = { FIPS140_MOD(0x00),
				      0x01,
				      0x02,
				      0x03,
				      0x04,
				      0x05,
				      0x06,
				      0x07,
				      0x08,
				      0x09,
				      0x0a,
				      0x0b,
				      0x0c,
				      0x0d,
				      0x0e,
				      0x0f };
	LC_FIPS_RODATA_SECTION
	static const uint8_t key256[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca,
					  0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0,
					  0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35,
					  0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
					  0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14,
					  0xdf, 0xf4 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t out256[] = {
		0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e,
		0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96,
		0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70,
		0x2c, 0x7d, 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf,
		0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61, 0xb2, 0xeb,
		0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07,
		0x8c, 0x6a, 0x9d, 0x1b
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t in[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
		0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
		0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
		0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f,
		0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
		0xe6, 0x6c, 0x37, 0x10
	};
	uint8_t out[sizeof(in)];

	LC_SELFTEST_RUN(LC_ALG_STATUS_AES_CBC);

	LC_SYM_CTX_ON_STACK(ctx, aes);

	/* Unpoison key to let implementation poison it */
	unpoison(key256, sizeof(key256));

	aes->init_nocheck(ctx->sym_state);
	if (lc_sym_setkey(ctx, key256, sizeof(key256)))
		goto out;
	lc_sym_setiv(ctx, iv, sizeof(iv));
	lc_sym_encrypt(ctx, in, out, sizeof(in));
	if (lc_compare_selftest(LC_ALG_STATUS_AES_CBC, out256, out,
				sizeof(out256), "AES-CBC encrypt"))
		goto out2;
	lc_sym_zero(ctx);

	aes->init_nocheck(ctx->sym_state);
	lc_sym_setkey(ctx, key256, sizeof(key256));
	lc_sym_setiv(ctx, iv, sizeof(iv));
	lc_sym_decrypt(ctx, out, out, sizeof(out));

out:
	lc_compare_selftest(LC_ALG_STATUS_AES_CBC, in, out, sizeof(in),
			    "AES-CBC decrypt");
out2:
	lc_sym_zero(ctx);
}

static void mode_cbc_encrypt(struct lc_mode_state *ctx, const uint8_t *in,
			     uint8_t *out, size_t len)
{
	const struct lc_sym *wrappeded_cipher;
	size_t i, rounded_len = len & ~(AES_BLOCKLEN - 1);
	uint8_t *iv = ctx->iv;

	if (!ctx || !ctx->wrappeded_cipher)
		return;

	wrappeded_cipher = ctx->wrappeded_cipher;

	if (in != out)
		memcpy(out, in, rounded_len);

	for (i = 0; i < rounded_len; i += AES_BLOCKLEN, out += AES_BLOCKLEN) {
		xor_64(out, iv, AES_BLOCKLEN);
		wrappeded_cipher->encrypt(ctx->wrapped_cipher_ctx, out, out,
					  AES_BLOCKLEN);
		iv = out;
	}
	/* store Iv in ctx for next call */
	memcpy(ctx->iv, iv, AES_BLOCKLEN);
}

static void mode_cbc_decrypt(struct lc_mode_state *ctx, const uint8_t *in,
			     uint8_t *out, size_t len)
{
	const struct lc_sym *wrappeded_cipher;
	size_t i, rounded_len = len & ~(AES_BLOCKLEN - 1);
	uint8_t storeNextIv[AES_BLOCKLEN];

	if (!ctx || !ctx->wrappeded_cipher)
		return;

	wrappeded_cipher = ctx->wrappeded_cipher;

	if (in != out)
		memcpy(out, in, rounded_len);

	for (i = 0; i < rounded_len; i += AES_BLOCKLEN, out += AES_BLOCKLEN) {
		memcpy(storeNextIv, out, AES_BLOCKLEN);
		wrappeded_cipher->decrypt(ctx->wrapped_cipher_ctx, out, out,
					  AES_BLOCKLEN);
		xor_64(out, ctx->iv, AES_BLOCKLEN);
		memcpy(ctx->iv, storeNextIv, AES_BLOCKLEN);
	}

	lc_memset_secure(storeNextIv, 0, sizeof(storeNextIv));
}

static void mode_cbc_init(struct lc_mode_state *ctx,
			  const struct lc_sym *wrapped_cipher,
			  const struct lc_sym *tweak_cipher,
			  void *wrapped_cipher_ctx, void *tweak_ctx)
{
	(void)tweak_cipher;
	(void)tweak_ctx;

	if (!ctx || !wrapped_cipher || !wrapped_cipher_ctx ||
	    wrapped_cipher->blocksize != AES_BLOCKLEN)
		return;

	ctx->wrappeded_cipher = wrapped_cipher;
	ctx->wrapped_cipher_ctx = wrapped_cipher_ctx;
}

static int mode_cbc_setkey(struct lc_mode_state *ctx, const uint8_t *key,
			   size_t keylen)
{
	const struct lc_sym *wrappeded_cipher;
	int ret;

	if (!ctx || !ctx->wrappeded_cipher)
		return -EINVAL;

	ret = aes_check_keylen(keylen);
	if (ret)
		return ret;

	wrappeded_cipher = ctx->wrappeded_cipher;
	return wrappeded_cipher->setkey(ctx->wrapped_cipher_ctx, key, keylen);
}

static int mode_cbc_setiv(struct lc_mode_state *ctx, const uint8_t *iv,
			  size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(ctx->iv, iv, AES_BLOCKLEN);
	return 0;
}

static int mode_cbc_getiv(struct lc_mode_state *ctx, uint8_t *iv, size_t ivlen)
{
	if (!ctx || !iv || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(iv, ctx->iv, AES_BLOCKLEN);
	return 0;
}

static const struct lc_sym_mode _lc_mode_cbc_c = {
	.init = mode_cbc_init,
	.setkey = mode_cbc_setkey,
	.setiv = mode_cbc_setiv,
	.getiv = mode_cbc_getiv,
	.encrypt = mode_cbc_encrypt,
	.decrypt = mode_cbc_decrypt,
	.statesize = LC_AES_CBC_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym_mode *,
		    lc_mode_cbc_c) = &_lc_mode_cbc_c;
