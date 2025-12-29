// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
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

#include <crypto/aes.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "lc_aes.h"

#include "leancrypto_kernel.h"

static int lc_aes_block_setkey(struct crypto_tfm *tfm, const u8 *key,
			       unsigned int keylen)
{
	struct lc_sym_ctx *ctx = crypto_tfm_ctx(tfm);
	int err;

	err = lc_sym_init(ctx);
	if (err)
		return err;

	return lc_sym_setkey(ctx, key, keylen);
}

static void lc_aes_block_encrypt(struct crypto_tfm *tfm, uint8_t *out,
				 const uint8_t *in)
{
	struct lc_sym_ctx *ctx = crypto_tfm_ctx(tfm);

	lc_sym_encrypt(ctx, in, out, AES_BLOCK_SIZE);
}

static void lc_aes_block_decrypt(struct crypto_tfm *tfm, uint8_t *out,
				 const uint8_t *in)
{
	struct lc_sym_ctx *ctx = crypto_tfm_ctx(tfm);

	lc_sym_decrypt(ctx, in, out, AES_BLOCK_SIZE);
}

static int lc_aes_block_init(struct crypto_tfm *tfm)
{
	struct lc_sym_ctx *ctx = crypto_tfm_ctx(tfm);

	LC_SYM_SET_CTX(ctx, lc_aes);

	return 0;
}

/********************************* Interface  *********************************/

static struct crypto_alg lc_aes_cipher = {
	.cra_name = "aes",
	.cra_driver_name = "aes-leancrypto",
	.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = AES_BLOCK_SIZE,
	.cra_ctxsize = LC_SYM_CTX_SIZE_LEN(LC_AES_AESNI_MAX_BLOCK_SIZE),
	.cra_module = THIS_MODULE,
	.cra_u = { .cipher = { .cia_min_keysize = AES_MIN_KEY_SIZE,
			       .cia_max_keysize = AES_MAX_KEY_SIZE,
			       .cia_setkey = lc_aes_block_setkey,
			       .cia_encrypt = lc_aes_block_encrypt,
			       .cia_decrypt = lc_aes_block_decrypt } },

	.cra_init = lc_aes_block_init
};

int __init lc_kernel_aes_init(void)
{
	return crypto_register_alg(&lc_aes_cipher);
}

void lc_kernel_aes_exit(void)
{
	crypto_unregister_alg(&lc_aes_cipher);
}
