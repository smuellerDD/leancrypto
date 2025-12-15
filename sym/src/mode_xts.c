/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
#include "alignment.h"
#include "conv_be_le.h"
#include "compare.h"
#include "ext_headers_internal.h"
#include "fips_mode.h"
#include "helper.h"
#include "lc_sym.h"
#include "lc_memcmp_secure.h"
#include "lc_memset_secure.h"
#include "mode_xts.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"
#include "xor.h"

#define LC_AES_XTS_BLOCK_SIZE sizeof(struct lc_mode_state)

void mode_xts_selftest(const struct lc_sym *aes)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0x00, 0x00, 0x00 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t key256[] = { FIPS140_MOD(0x27),
					  0x18,
					  0x28,
					  0x18,
					  0x28,
					  0x45,
					  0x90,
					  0x45,
					  0x23,
					  0x53,
					  0x60,
					  0x28,
					  0x74,
					  0x71,
					  0x35,
					  0x26,
					  0x62,
					  0x49,
					  0x77,
					  0x57,
					  0x24,
					  0x70,
					  0x93,
					  0x69,
					  0x99,
					  0x59,
					  0x57,
					  0x49,
					  0x66,
					  0x96,
					  0x76,
					  0x27,
					  0x31,
					  0x41,
					  0x59,
					  0x26,
					  0x53,
					  0x58,
					  0x97,
					  0x93,
					  0x23,
					  0x84,
					  0x62,
					  0x64,
					  0x33,
					  0x83,
					  0x27,
					  0x95,
					  0x02,
					  0x88,
					  0x41,
					  0x97,
					  0x16,
					  0x93,
					  0x99,
					  0x37,
					  0x51,
					  0x05,
					  0x82,
					  0x09,
					  0x74,
					  0x94,
					  0x45,
					  0x92 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t out256[] = {
		0x3a, 0x06, 0x0a, 0x8c, 0xad, 0x11, 0x5a, 0x6f, 0x44, 0x57,
		0x2e, 0x37, 0x59, 0xe4, 0x3c, 0x8f, 0xca, 0xd8, 0xbf, 0xcb,
		0x23, 0x3f, 0xf6, 0xad, 0x71, 0xb7, 0xc1, 0xe7, 0xca, 0x65,
		0x15, 0x08, 0x86, 0x0a, 0xed, 0x34, 0xec, 0x95, 0x06, 0xd3,
		0x68, 0xaa, 0x50, 0x27, 0x4a, 0x31, 0xc1, 0x6d, 0x2d, 0xea,
		0xe4, 0xd6, 0x4c, 0x2a, 0x80, 0x96, 0x09, 0x1c, 0x09, 0x3f,
		0x38, 0x20, 0xfb, 0x6d, 0x21, 0x08, 0x9b, 0xce, 0xda, 0xac,
		0x36, 0x1e, 0x3f, 0xeb, 0xe7, 0x06, 0xca, 0xfe, 0x14, 0xb9,
		0xbc, 0x89, 0xde, 0x34, 0x25, 0x8d, 0x32, 0xec, 0x3a, 0xd5,
		0x9f, 0xd2, 0x98, 0x6a, 0x40, 0x1e, 0x6b, 0xff
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t in[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
		0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31,
		0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
		0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
		0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
		0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61
	};
	uint8_t out[sizeof(in)];

	LC_SELFTEST_RUN(LC_ALG_STATUS_AES_XTS);

	LC_SYM_CTX_ON_STACK(ctx, aes);

	/* Unpoison key to let implementation poison it */
	unpoison(key256, sizeof(key256));

	aes->init_nocheck(ctx->sym_state);
	if (lc_sym_setkey(ctx, key256, sizeof(key256)))
		goto out;
	lc_sym_setiv(ctx, iv, sizeof(iv));
	lc_sym_encrypt(ctx, in, out, sizeof(in));
	if (lc_compare_selftest(LC_ALG_STATUS_AES_XTS, out, out256,
				sizeof(out256), "AES-XTS encrypt"))
		goto out2;
	lc_sym_zero(ctx);

	aes->init_nocheck(ctx->sym_state);
	if (lc_sym_setkey(ctx, key256, sizeof(key256)))
		goto out;
	lc_sym_setiv(ctx, iv, sizeof(iv));
	lc_sym_decrypt(ctx, out, out, sizeof(out));

out:
	lc_compare_selftest(LC_ALG_STATUS_AES_XTS, out, in, sizeof(in),
			    "AES-XTS decrypt");

out2:
	lc_sym_zero(ctx);
}

static void xts_enc_block(struct lc_mode_state *ctx,
			  uint8_t block[AES_BLOCKLEN])
{
	const struct lc_sym *wrapped_cipher = ctx->wrapped_cipher;

	xor_64(block, ctx->tweak.b, AES_BLOCKLEN);

	/*
	 * Timecop: C implementation of AES has side channel problems as
	 * outlined in aes_block.c:aes_setkey
	 */
	unpoison(block, AES_BLOCKLEN);

	wrapped_cipher->encrypt(ctx->wrapped_cipher_ctx, block, block,
				AES_BLOCKLEN);
	xor_64(block, ctx->tweak.b, AES_BLOCKLEN);
}

static void mode_xts_encrypt(struct lc_mode_state *ctx, const uint8_t *in,
			     uint8_t *out, size_t len)
{
	size_t i, rounded_len = len & ~(AES_BLOCKLEN - 1);

	if (!ctx || !ctx->wrapped_cipher)
		return;

	/* We must have 128 bits input data or more */
	if (rounded_len < AES_BLOCKLEN)
		return;

	if (in != out)
		memcpy(out, in, len);

	/* Encryption of all AES blocks except the last two */
	for (i = 0; i < rounded_len - AES_BLOCKLEN;
	     i += AES_BLOCKLEN, out += AES_BLOCKLEN) {
		/* Encrypt */
		xts_enc_block(ctx, out);
		/* Increment the tweak */
		gfmul_alpha(&ctx->tweak);
	}

	if (len == rounded_len) {
		/*
		 * Encrypt the last block, out already points to the right
		 * memory location
		 */
		xts_enc_block(ctx, out);

		/* Update the tweak to allow stream mode operation */
		gfmul_alpha(&ctx->tweak);
	} else {
		/*
		 * Encrypt the last full block and the trailing partial block,
		 * out already points to the beginning of the last full block
		 */
		size_t b = len - rounded_len;
		uint8_t CC[AES_BLOCKLEN] __align(sizeof(uint64_t)),
			PP[AES_BLOCKLEN] __align(sizeof(uint64_t));

		/* Get last full block */
		memcpy(CC, out, AES_BLOCKLEN);
		/* Encrypt */
		xts_enc_block(ctx, CC);
		gfmul_alpha(&ctx->tweak);

		/* Get the final partial block */
		memcpy(PP, out + AES_BLOCKLEN, b);
		/* Add the ciphertext from the last full block */
		memcpy(PP + b, CC + b, AES_BLOCKLEN - b);
		/* Encrypt */
		xts_enc_block(ctx, PP);
		/*
		 * Final tweak increment not needed any more - when we reach
		 * this code, we got the final block. Thus, a stream mode
		 * invocation must take care that the initial data is always
		 * a multiple of 16 bytes.
		 */

		/* Copy PP as last full block */
		memcpy(out, PP, AES_BLOCKLEN);

		/* Copy b-bytes of CC as last partial block */
		memcpy(out + AES_BLOCKLEN, CC, b);

		lc_memset_secure(CC, 0, sizeof(CC));
		lc_memset_secure(PP, 0, sizeof(PP));
	}

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, len);
}

static void xts_dec_block(struct lc_mode_state *ctx,
			  uint8_t block[AES_BLOCKLEN],
			  union lc_xts_tweak *tweak)
{
	const struct lc_sym *wrapped_cipher = ctx->wrapped_cipher;

	xor_64(block, tweak->b, AES_BLOCKLEN);

	/*
	 * Timecop: C implementation of AES has side channel problems as
	 * outlined in aes_block.c:aes_setkey
	 */
	unpoison(block, AES_BLOCKLEN);

	wrapped_cipher->decrypt(ctx->wrapped_cipher_ctx, block, block,
				AES_BLOCKLEN);
	xor_64(block, tweak->b, AES_BLOCKLEN);
}

static void mode_xts_decrypt(struct lc_mode_state *ctx, const uint8_t *in,
			     uint8_t *out, size_t len)
{
	size_t i, rounded_len = len & ~(AES_BLOCKLEN - 1);

	if (!ctx || !ctx->wrapped_cipher)
		return;

	/* We must have 128 bits input data or more */
	if (rounded_len < AES_BLOCKLEN)
		return;

	if (in != out)
		memcpy(out, in, len);

	/* Decryption of all AES blocks except the last two */
	for (i = 0; i < rounded_len - AES_BLOCKLEN;
	     i += AES_BLOCKLEN, out += AES_BLOCKLEN) {
		/* Decrypt */
		xts_dec_block(ctx, out, &ctx->tweak);
		/* Update the tweak */
		gfmul_alpha(&ctx->tweak);
	}

	if (len == rounded_len) {
		/*
		 * Decrypt the last block, out already points to the right
		 * memory location
		 */
		xts_dec_block(ctx, out, &ctx->tweak);

		/* Update the tweak to allow stream mode operation */
		gfmul_alpha(&ctx->tweak);
	} else {
		size_t b = len - rounded_len;
		uint8_t CC[AES_BLOCKLEN] __align(sizeof(uint64_t)),
			PP[AES_BLOCKLEN] __align(sizeof(uint64_t));
		union lc_xts_tweak tweak;

		memcpy(tweak.b, ctx->tweak.b, AES_BLOCKLEN);

		/* Get last full block */
		memcpy(PP, out, AES_BLOCKLEN);
		/* We need the tweak of the last iteration for the decryption */
		gfmul_alpha(&tweak);
		/* Decryption using the last tweak */
		xts_dec_block(ctx, PP, &tweak);

		/* Get the final partial block */
		memcpy(CC, out + AES_BLOCKLEN, b);
		/* Add the plaintext from the last full block */
		memcpy(CC + b, PP + b, AES_BLOCKLEN - b);
		/* Decryption using the last but one tweak */
		xts_dec_block(ctx, CC, &ctx->tweak);
		/*
		 * Final tweak increment not needed any more - when we reach
		 * this code, we got the final block. Thus, a stream mode
		 * invocation must take care that the initial data is always
		 * a multiple of 16 bytes.
		 */

		/* Copy PP as last full block */
		memcpy(out, CC, AES_BLOCKLEN);

		/* Copy b-bytes of CC as last partial block */
		memcpy(out + AES_BLOCKLEN, PP, b);

		lc_memset_secure(CC, 0, sizeof(CC));
		lc_memset_secure(PP, 0, sizeof(PP));
	}

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, len);
}

static void mode_xts_init(struct lc_mode_state *ctx,
			  const struct lc_sym *wrapped_cipher,
			  const struct lc_sym *tweak_cipher,
			  void *wrapped_cipher_ctx, void *tweak_cipher_ctx)
{
	if (!ctx || !wrapped_cipher || !wrapped_cipher_ctx ||
	    !tweak_cipher_ctx || wrapped_cipher->blocksize != AES_BLOCKLEN)
		return;

	ctx->wrapped_cipher = wrapped_cipher;
	ctx->tweak_cipher = tweak_cipher;
	ctx->wrapped_cipher_ctx = wrapped_cipher_ctx;
	ctx->tweak_cipher_ctx = tweak_cipher_ctx;
}

static int mode_xts_setkey(struct lc_mode_state *ctx, const uint8_t *key,
			   size_t keylen)
{
	const struct lc_sym *wrapped_cipher;
	size_t one_keylen;
	int ret;

	if (!ctx || !ctx->wrapped_cipher || !ctx->tweak_cipher_ctx)
		return -EINVAL;

	one_keylen = keylen >> 1;

	ret = aes_check_keylen(one_keylen);
	if (ret)
		return ret;

	/* Reject XTS key where both parts are identical */
	if (fips140_mode_enabled() &&
	    !lc_memcmp_secure(key, one_keylen, key + one_keylen, one_keylen))
		return -ENOKEY;

	/*
	 * Timecop: key is sensitive.
	 */
	poison(key, keylen);

	/* Set encryption / decryption key */
	wrapped_cipher = ctx->wrapped_cipher;
	CKINT(wrapped_cipher->setkey(ctx->wrapped_cipher_ctx, key, one_keylen));

	/* Set tweak key */
	wrapped_cipher = ctx->tweak_cipher;
	CKINT(wrapped_cipher->setkey(ctx->tweak_cipher_ctx, key + one_keylen,
				     one_keylen));

out:
	unpoison(key, keylen);
	return ret;
}

static int mode_xts_setiv(struct lc_mode_state *ctx, const uint8_t *iv,
			  size_t ivlen)
{
	const struct lc_sym *wrapped_cipher;

	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(ctx->tweak.b, iv, AES_BLOCKLEN);

	/*
	 * Generate tweak - the location here implies that the key must already
	 * be set with the setkey call.
	 */
	wrapped_cipher = ctx->wrapped_cipher;
	wrapped_cipher->encrypt(ctx->tweak_cipher_ctx, ctx->tweak.b,
				ctx->tweak.b, AES_BLOCKLEN);

	return 0;
}

static int mode_xts_getiv(const struct lc_mode_state *ctx, uint8_t *iv,
			  size_t ivlen)
{
	if (!ctx || !iv || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(iv, ctx->tweak.b, AES_BLOCKLEN);
	return 0;
}

static const struct lc_sym_mode _lc_mode_xts_c = {
	.init = mode_xts_init,
	.setkey = mode_xts_setkey,
	.setiv = mode_xts_setiv,
	.getiv = mode_xts_getiv,
	.encrypt = mode_xts_encrypt,
	.decrypt = mode_xts_decrypt,
	.statesize = LC_AES_XTS_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym_mode *,
		    lc_mode_xts_c) = &_lc_mode_xts_c;
