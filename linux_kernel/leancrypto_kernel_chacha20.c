// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2025 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include <crypto/chacha.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "lc_chacha20.h"
#include "lc_chacha20_private.h"

#include "leancrypto_kernel.h"

static int lc_chacha20_setkey(struct crypto_skcipher *tfm, const u8 *key,
			      unsigned int keylen)
{
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);
	int err;

	err = lc_sym_init(ctx);
	if (err)
		return err;

	return lc_sym_setkey(ctx, key, keylen);
}

static int lc_chacha20_common(struct skcipher_request *req,
			      int (*crypt_func)(struct lc_sym_ctx *ctx,
						const uint8_t *in,
						uint8_t *out, size_t len))
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);
	struct lc_sym_state *state = ctx->sym_state;
	struct skcipher_walk walk;
	struct lc_sym_ctx *vola_ctx;
	unsigned int nbytes;
	int err;

	/* Safety measure - should never happen */
	if (!state)
		return -EFAULT;

	/*
	 * We do not use the _iv API here, but create a local copy of the
	 * ChaCha20 context. This avoids the setup of the ChaCha20 context with
	 * each individual call to the _iv function and thus makes this code
	 * more performant.
	 */
	vola_ctx = kzalloc(LC_SYM_CTX_SIZE_LEN(LC_CC20_STATE_SIZE), GFP_KERNEL);
	if (!vola_ctx)
		return -ENOMEM;

	LC_SYM_SET_CTX(vola_ctx, lc_chacha20);

	/* Set up local context */
	err = lc_sym_init(vola_ctx);
	if (err)
		goto out;

	/* Set key from current context */
	err = lc_sym_setkey(vola_ctx, state->key.b, LC_CC20_KEY_SIZE);
	if (err)
		goto out;

	/* Set IV */
        err = lc_sym_setiv(vola_ctx, req->iv, CHACHA_IV_SIZE);
	if (err)
		goto out;

	err = skcipher_walk_virt(&walk, req, false);

	while ((nbytes = walk.nbytes) > 0) {
		err = crypt_func(vola_ctx, walk.src.virt.addr,
				 walk.dst.virt.addr,
				 nbytes & (~(CHACHA_BLOCK_SIZE - 1)));
		if (err)
			goto out;
		nbytes &= CHACHA_BLOCK_SIZE - 1;

		if (walk.nbytes == walk.total && nbytes > 0) {
			err = crypt_func(
				vola_ctx,
				walk.src.virt.addr + walk.nbytes - nbytes,
				walk.dst.virt.addr + walk.nbytes - nbytes,
				nbytes);
			if (err)
				goto out;
			nbytes = 0;
		}
		err = skcipher_walk_done(&walk, nbytes);
	}

	if (err)
		goto out;

	/* Get the IV */
	err = lc_sym_getiv(vola_ctx, req->iv, CHACHA_IV_SIZE);

out:
	lc_sym_zero(vola_ctx);
        kfree(vola_ctx);
	return err;
}

static int lc_chacha20_encrypt(struct skcipher_request *req)
{
	return lc_chacha20_common(req, lc_sym_encrypt);
}

static int lc_chacha20_decrypt(struct skcipher_request *req)
{
	return lc_chacha20_common(req, lc_sym_decrypt);
}

static int lc_chacha20_init(struct crypto_skcipher *tfm)
{
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);

	LC_SYM_SET_CTX(ctx, lc_chacha20);

	return 0;
}

/********************************* Interface  *********************************/

static struct skcipher_alg lc_chacha20_skciphers[] = {
	{
		.base = {
			.cra_name = "chacha20",
			.cra_driver_name = "chacha20-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = LC_SYM_CTX_SIZE_LEN(LC_CC20_STATE_SIZE),
			.cra_alignmask = LC_SYM_COMMON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.min_keysize = CHACHA_KEY_SIZE,
		.max_keysize = CHACHA_KEY_SIZE,
		.ivsize	 = CHACHA_IV_SIZE,
		.chunksize = CHACHA_BLOCK_SIZE,
		.setkey = lc_chacha20_setkey,
		.encrypt = lc_chacha20_encrypt,
		.decrypt = lc_chacha20_decrypt,
		.init = lc_chacha20_init
	}
};

int __init lc_kernel_chacha20_init(void)
{
	return crypto_register_skciphers(lc_chacha20_skciphers,
					 ARRAY_SIZE(lc_chacha20_skciphers));
}

void lc_kernel_chacha20_exit(void)
{
	crypto_unregister_skciphers(lc_chacha20_skciphers,
				    ARRAY_SIZE(lc_chacha20_skciphers));
}
