/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "aes_aesni.h"
#include "aes_internal.h"
#include "asm/AESNI_x86_64/aes_aesni_x86_64.h"
#include "ext_headers_x86.h"
#include "lc_memcmp_secure.h"
#include "lc_sym.h"
#include "mode_xts.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"
#include "xor.h"

struct lc_sym_state {
	struct aes_aesni_block_ctx enc_block_ctx;
	struct aes_aesni_block_ctx dec_block_ctx;
	struct aes_aesni_block_ctx tweak_ctx;
	uint8_t iv[AES_BLOCKLEN];
};

#define LC_AES_AESNI_XTS_BLOCK_SIZE sizeof(struct lc_sym_state)

static void aes_aesni_xts_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
				  uint8_t *out, size_t len)
{
	if (!ctx)
		return;

	LC_FPU_ENABLE;
	aesni_xts_encrypt(in, out, len, &ctx->enc_block_ctx, &ctx->tweak_ctx,
			  ctx->iv);
	LC_FPU_DISABLE;

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, len);
}

static void aes_aesni_xts_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
				  uint8_t *out, size_t len)
{
	if (!ctx)
		return;

	LC_FPU_ENABLE;
	aesni_xts_decrypt(in, out, len, &ctx->dec_block_ctx, &ctx->tweak_ctx,
			  ctx->iv);
	LC_FPU_DISABLE;

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, len);
}

static void aes_aesni_xts_init(struct lc_sym_state *ctx)
{
	static int tested = 0;

	(void)ctx;

	mode_xts_selftest(lc_aes_xts_aesni, &tested, "AES-XTS");
}

static int aes_aesni_xts_setkey(struct lc_sym_state *ctx, const uint8_t *key,
				size_t keylen)
{
	size_t one_keylen;
	int ret;

	/* Timecop: key is sensitive. */
	poison(key, keylen);

	if (!ctx)
		return -EINVAL;

	one_keylen = keylen / 2;

	/* Reject XTS key where both parts are identical */
	if (!lc_memcmp_secure(key, one_keylen, key + one_keylen, one_keylen))
		return -ENOKEY;
	LC_FPU_ENABLE;
	CKINT(aesni_set_encrypt_key(key, (unsigned int)(one_keylen << 3),
				    &ctx->enc_block_ctx));
	CKINT(aesni_set_decrypt_key(key, (unsigned int)(one_keylen << 3),
				    &ctx->dec_block_ctx));
	CKINT(aesni_set_encrypt_key(key + one_keylen,
				    (unsigned int)(one_keylen << 3),
				    &ctx->tweak_ctx));

out:
	LC_FPU_DISABLE;
	return ret;
}

static int aes_aesni_xts_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			       size_t ivlen)
{
	if (!ctx || ivlen != AES_BLOCKLEN)
		return -EINVAL;

	memcpy(ctx->iv, iv, AES_BLOCKLEN);
	return 0;
}

static struct lc_sym _lc_aes_xts_aesni = {
	.init = aes_aesni_xts_init,
	.setkey = aes_aesni_xts_setkey,
	.setiv = aes_aesni_xts_setiv,
	.encrypt = aes_aesni_xts_encrypt,
	.decrypt = aes_aesni_xts_decrypt,
	.statesize = LC_AES_AESNI_XTS_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *,
		    lc_aes_xts_aesni) = &_lc_aes_xts_aesni;
