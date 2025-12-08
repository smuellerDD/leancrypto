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

#include "aes_aesni.h"
#include "aes_internal.h"
#include "asm/AESNI_x86_64/aes_aesni_x86_64.h"
#include "build_bug_on.h"
#include "ext_headers_x86.h"
#include "lc_aes.h"
#include "lc_sym.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

struct lc_sym_state {
	struct aes_aesni_block_ctx enc_block_ctx;
	struct aes_aesni_block_ctx dec_block_ctx;
};

#define LC_AES_BLOCK_SIZE sizeof(struct lc_sym_state)

unsigned int lc_x86_64_cpuid[4] __attribute__((used)) = { 0 };

static void aes_aesni_encrypt(struct lc_sym_state *ctx, const uint8_t *in,
			      uint8_t *out, size_t len)
{
	if (!ctx || len != AES_BLOCKLEN)
		return;

	LC_FPU_ENABLE;
	aesni_encrypt(in, out, &ctx->enc_block_ctx);
	LC_FPU_DISABLE;

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, AES_BLOCKLEN);
}

static void aes_aesni_decrypt(struct lc_sym_state *ctx, const uint8_t *in,
			      uint8_t *out, size_t len)
{
	if (!ctx || len != AES_BLOCKLEN)
		return;

	LC_FPU_ENABLE;
	aesni_decrypt(in, out, &ctx->dec_block_ctx);
	LC_FPU_DISABLE;

	/* Timecop: output is not sensitive regarding side-channels. */
	unpoison(out, AES_BLOCKLEN);
}

static int aes_aesni_init(struct lc_sym_state *ctx)
{
	(void)ctx;

	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE < LC_AES_BLOCK_SIZE);

	if (!lc_x86_64_cpuid[0])
		lc_cpu_feature_get_cpuid(lc_x86_64_cpuid);

	return 0;
}

static int aes_aesni_setkey(struct lc_sym_state *ctx, const uint8_t *key,
			    size_t keylen)
{
	int ret;

	/* Timecop: key is sensitive. */
	poison(key, keylen);

	if (!ctx)
		return -EINVAL;

	LC_FPU_ENABLE;
	CKINT(aesni_set_encrypt_key(key, (unsigned int)(keylen << 3),
				    &ctx->enc_block_ctx));
	CKINT(aesni_set_decrypt_key(key, (unsigned int)(keylen << 3),
				    &ctx->dec_block_ctx));

out:
	LC_FPU_DISABLE;
	return ret;
}

static int aes_aesni_setiv(struct lc_sym_state *ctx, const uint8_t *iv,
			   size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static int aes_aesni_getiv(struct lc_sym_state *ctx, uint8_t *iv, size_t ivlen)
{
	(void)ctx;
	(void)iv;
	(void)ivlen;
	return -EOPNOTSUPP;
}

static const struct lc_sym _lc_aes_aesni = {
	.init = aes_aesni_init,
	.init_nocheck = NULL,
	.setkey = aes_aesni_setkey,
	.setiv = aes_aesni_setiv,
	.getiv = aes_aesni_getiv,
	.encrypt = aes_aesni_encrypt,
	.decrypt = aes_aesni_decrypt,
	.statesize = LC_AES_BLOCK_SIZE,
	.blocksize = AES_BLOCKLEN,
};
LC_INTERFACE_SYMBOL(const struct lc_sym *, lc_aes_aesni) = &_lc_aes_aesni;
