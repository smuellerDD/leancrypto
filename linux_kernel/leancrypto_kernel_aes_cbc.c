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

/* Required for context size */
#include "aes_c.h"
#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_riscv64.h"

#include "leancrypto_kernel.h"

static int lc_aes_cbc_setkey(struct crypto_skcipher *tfm, const u8 *key,
			     unsigned int keylen)
{
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);
	int err;

	err = lc_sym_init(ctx);
	if (err)
		return err;

	return lc_sym_setkey(ctx, key, keylen);
}

static int lc_aes_cbc_common(struct skcipher_request *req,
			     void (*crypt_func)(struct lc_sym_ctx *ctx,
						const uint8_t *in, uint8_t *out,
						size_t len))
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct skcipher_walk walk;
	int err;

	if (unlikely(req->cryptlen % AES_BLOCK_SIZE))
		return -EINVAL;

	err = lc_sym_setiv(ctx, req->iv, AES_BLOCK_SIZE);
	if (err)
		return err;

	err = skcipher_walk_virt(&walk, req, false);

	while (walk.nbytes) {
		crypt_func(ctx, walk.src.virt.addr, walk.dst.virt.addr,
			   walk.nbytes & ~(AES_BLOCK_SIZE - 1));
		err = skcipher_walk_done(&walk,
					 walk.nbytes & (AES_BLOCK_SIZE - 1));
	}

	return err;
}

static int lc_aes_cbc_encrypt(struct skcipher_request *req)
{
	return lc_aes_cbc_common(req, lc_sym_encrypt);
}

static int lc_aes_cbc_decrypt(struct skcipher_request *req)
{
	return lc_aes_cbc_common(req, lc_sym_decrypt);
}

static int lc_aes_cbc_init(struct crypto_skcipher *tfm)
{
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);

	LC_SYM_SET_CTX(ctx, lc_aes_cbc);

	/*
	 * Verification that the setting of .cra_ctxsize is appropriate
	 */
	BUILD_BUG_ON(LC_AES_RISCV64_CBC_MAX_BLOCK_SIZE <
		     LC_AES_ARMCE_CBC_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_AES_RISCV64_CBC_MAX_BLOCK_SIZE <
		     LC_AES_AESNI_CBC_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_AES_RISCV64_CBC_MAX_BLOCK_SIZE <
		     LC_AES_C_CBC_MAX_BLOCK_SIZE);

	return 0;
}

/********************************* Interface  *********************************/

static struct skcipher_alg lc_aes_cbc_skciphers[] = {
	{
		.base = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "cbc-aes-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = LC_SYM_CTX_SIZE_LEN(
					LC_AES_RISCV64_CBC_MAX_BLOCK_SIZE),
			.cra_alignmask = LC_SYM_COMMON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize	 = AES_BLOCK_SIZE,
		.setkey = lc_aes_cbc_setkey,
		.encrypt = lc_aes_cbc_encrypt,
		.decrypt = lc_aes_cbc_decrypt,
		.init = lc_aes_cbc_init
	}
};

int __init lc_kernel_aes_cbc_init(void)
{
	return crypto_register_skciphers(lc_aes_cbc_skciphers,
					 ARRAY_SIZE(lc_aes_cbc_skciphers));
}

void lc_kernel_aes_cbc_exit(void)
{
	crypto_unregister_skciphers(lc_aes_cbc_skciphers,
				    ARRAY_SIZE(lc_aes_cbc_skciphers));
}
