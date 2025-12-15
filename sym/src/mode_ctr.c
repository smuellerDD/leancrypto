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
#include "lc_aes.h"
#include "lc_sym.h"
#include "mode_ctr.h"
#include "math_helper.h"
#include "lc_memset_secure.h"
#include "timecop.h"
#include "visibility.h"
#include "xor.h"

#define LC_AES_CTR_BLOCK_SIZE sizeof(struct lc_mode_state)

void mode_ctr_selftest(const struct lc_sym *aes)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t key256[] = { FIPS140_MOD(0x60),
					  0x3d,
					  0xeb,
					  0x10,
					  0x15,
					  0xca,
					  0x71,
					  0xbe,
					  0x2b,
					  0x73,
					  0xae,
					  0xf0,
					  0x85,
					  0x7d,
					  0x77,
					  0x81,
					  0x1f,
					  0x35,
					  0x2c,
					  0x07,
					  0x3b,
					  0x61,
					  0x08,
					  0xd7,
					  0x2d,
					  0x98,
					  0x10,
					  0xa3,
					  0x09,
					  0x14,
					  0xdf,
					  0xf4 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t in[] = {
		0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7,
		0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28, 0xf4, 0x43, 0xe3, 0xca,
		0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca,
		0xf5, 0xc5, 0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c,
		0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d, 0xdf, 0xc9,
		0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08,
		0x45, 0x79, 0x41, 0xa6
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t iv[] = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
				      0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
				      0xfc, 0xfd, 0xfe, 0xff };
	LC_FIPS_RODATA_SECTION
	static const uint8_t out256[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d,
		0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57,
		0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
		0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f,
		0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
		0xe6, 0x6c, 0x37, 0x10
	};
	uint8_t out[sizeof(in)];

	LC_SELFTEST_RUN(LC_ALG_STATUS_AES_CTR);

	LC_SYM_CTX_ON_STACK(ctx, aes);

	/* Unpoison key to let implementation poison it */
	unpoison(key256, sizeof(key256));

	aes->init_nocheck(ctx->sym_state);
	if (lc_sym_setkey(ctx, key256, sizeof(key256)))
		goto out;
	lc_sym_setiv(ctx, iv, sizeof(iv));
	lc_sym_encrypt(ctx, in, out, sizeof(in));
	if (lc_compare_selftest(LC_ALG_STATUS_AES_CTR, out, out256,
				sizeof(out256), "AES-CTR encrypt"))
		goto out2;
	lc_sym_zero(ctx);

	aes->init_nocheck(ctx->sym_state);
	if (lc_sym_setkey(ctx, key256, sizeof(key256)))
		goto out;
	lc_sym_setiv(ctx, iv, sizeof(iv));
	lc_sym_decrypt(ctx, out, out, sizeof(out));

out:
	lc_compare_selftest(LC_ALG_STATUS_AES_CTR, out, in, sizeof(in),
			    "AES-CTR decrypt");
out2:
	lc_sym_zero(ctx);
}

/*
 * Symmetrical operation: same function for encrypting as for decrypting.
 * Note any IV/nonce should never be reused with the same key.
 */
static void mode_ctr_crypt(struct lc_mode_state *ctx, const uint8_t *in,
			   uint8_t *out, size_t len)
{
	const struct lc_sym *wrappeded_cipher;
	uint8_t buffer[AES_BLOCKLEN];
	size_t i, todo;

	if (!ctx || !ctx->wrappeded_cipher)
		return;

	wrappeded_cipher = ctx->wrappeded_cipher;

	if (in != out)
		memcpy(out, in, len);

	for (i = 0; i < len; i += todo) {
		/* we need to regen xor compliment in buffer */
		ctr128_to_ptr(buffer, ctx->iv);
		wrappeded_cipher->encrypt(ctx->wrapped_cipher_ctx, buffer,
					  buffer, sizeof(buffer));
		ctr128_inc(ctx->iv);
		todo = min_size(len - i, AES_BLOCKLEN);
		xor_64(out + i, buffer, todo);
	}

	lc_memset_secure(buffer, 0, sizeof(buffer));
}

static void mode_ctr_init(struct lc_mode_state *ctx,
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

static int mode_ctr_setkey(struct lc_mode_state *ctx, const uint8_t *key,
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

static int mode_ctr_setiv(struct lc_mode_state *ctx, const uint8_t *iv,
			  size_t ivlen)
{
	if (!ctx || !iv || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	ptr_to_ctr128(ctx->iv, iv);
	return 0;
}

static int mode_ctr_getiv(const struct lc_mode_state *ctx, uint8_t *iv,
			  size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	ctr128_to_ptr(iv, ctx->iv);
	return 0;
}

static const struct lc_sym_mode _lc_mode_ctr_c = {
	.init = mode_ctr_init,
	.setkey = mode_ctr_setkey,
	.setiv = mode_ctr_setiv,
	.getiv = mode_ctr_getiv,
	.encrypt = mode_ctr_crypt,
	.decrypt = mode_ctr_crypt,
	.statesize = LC_AES_CTR_BLOCK_SIZE,
	.blocksize = 1,
};
LC_INTERFACE_SYMBOL(const struct lc_sym_mode *,
		    lc_mode_ctr_c) = &_lc_mode_ctr_c;
