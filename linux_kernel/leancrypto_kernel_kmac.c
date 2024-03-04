/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include <crypto/internal/hash.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "lc_kmac.h"

#include "leancrypto_kernel.h"

#define LC_KMAC_CTX_SIZE_KERNEL						       \
	(LC_SHA3_256_STATE_SIZE + sizeof(struct lc_kmac_ctx))

static int lc_kernel_kmac256_init_alg(struct shash_desc *desc)
{
	struct lc_kmac_ctx *sctx = shash_desc_ctx(desc);
	struct lc_hash_ctx *shash_ctx = &sctx->hash_ctx;
	struct crypto_shash *tfm = desc->tfm;
	struct lc_kmac_ctx *pctx = crypto_shash_ctx(tfm);
	struct lc_hash_ctx *phash_ctx = &pctx->hash_ctx;

	LC_KMAC_SET_CTX(sctx, lc_cshake256);

	lc_hash_init(shash_ctx);
	sctx->final_called = 0;

	memcpy(sctx->hash_ctx.hash_state, phash_ctx->hash_state,
	       lc_hash_ctxsize(phash_ctx));

	return 0;
}

static int lc_kernel_kmac256_setkey(struct crypto_shash *tfm, const u8 *key,
				    unsigned int keylen)
{
	struct lc_kmac_ctx *sctx = crypto_shash_ctx(tfm);

	LC_KMAC_SET_CTX(sctx, lc_cshake256);

	lc_kmac_init(sctx, key, keylen, NULL, 0);

	return 0;
}

static int lc_kernel_kmac256_update(struct shash_desc *desc, const u8 *data,
				    unsigned int len)
{
	struct lc_kmac_ctx *sctx = shash_desc_ctx(desc);

	lc_kmac_update(sctx, data, len);

	return 0;
}

static int lc_kernel_kmac256_final(struct shash_desc *desc, u8 *out)
{
	struct lc_kmac_ctx *sctx = shash_desc_ctx(desc);
	unsigned int maclen = crypto_shash_digestsize(desc->tfm);

	lc_kmac_final(sctx, out, maclen);

	return 0;
}


static int lc_kernel_kmac256_final_xof(struct shash_desc *desc, u8 *out)
{
	struct lc_kmac_ctx *sctx = shash_desc_ctx(desc);
	unsigned int maclen = crypto_shash_digestsize(desc->tfm);

	lc_kmac_final_xof(sctx, out, maclen);

	return 0;
}

static struct shash_alg lc_kmac256_algs[] = { {
	.digestsize		= LC_SHA3_224_SIZE_DIGEST,
	.init			= lc_kernel_kmac256_init_alg,
	.update			= lc_kernel_kmac256_update,
	.final			= lc_kernel_kmac256_final,
	.setkey			= lc_kernel_kmac256_setkey,
	.descsize		= LC_KMAC_CTX_SIZE_KERNEL,
	/* This memory is used for the state of lc_kernel_kmac256_setkey */
	.base.cra_ctxsize	= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_name		= "kmac256-224",
	.base.cra_driver_name	= "kmac256-224-leancrypto",
	.base.cra_blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= LC_KERNEL_DEFAULT_PRIO,
}, {
	.digestsize		= LC_SHA3_256_SIZE_DIGEST,
	.init			= lc_kernel_kmac256_init_alg,
	.update			= lc_kernel_kmac256_update,
	.final			= lc_kernel_kmac256_final,
	.setkey			= lc_kernel_kmac256_setkey,
	.descsize		= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_ctxsize	= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_name		= "kmac256-256",
	.base.cra_driver_name	= "kmac256-256-leancrypto",
	.base.cra_blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= LC_KERNEL_DEFAULT_PRIO,
}, {
	.digestsize		= LC_SHA3_384_SIZE_DIGEST,
	.init			= lc_kernel_kmac256_init_alg,
	.update			= lc_kernel_kmac256_update,
	.final			= lc_kernel_kmac256_final,
	.setkey			= lc_kernel_kmac256_setkey,
	.descsize		= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_ctxsize	= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_name		= "kmac256-384",
	.base.cra_driver_name	= "kmac256-384-leancrypto",
	.base.cra_blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= LC_KERNEL_DEFAULT_PRIO,
}, {
	.digestsize		= LC_SHA3_512_SIZE_DIGEST,
	.init			= lc_kernel_kmac256_init_alg,
	.update			= lc_kernel_kmac256_update,
	.final			= lc_kernel_kmac256_final,
	.setkey			= lc_kernel_kmac256_setkey,
	.descsize		= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_ctxsize	= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_name		= "kmac256-512",
	.base.cra_driver_name	= "kmac256-512-leancrypto",
	.base.cra_blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= LC_KERNEL_DEFAULT_PRIO,
}, {
	.digestsize		= LC_SHA3_224_SIZE_DIGEST,
	.init			= lc_kernel_kmac256_init_alg,
	.update			= lc_kernel_kmac256_update,
	.final			= lc_kernel_kmac256_final_xof,
	.setkey			= lc_kernel_kmac256_setkey,
	.descsize		= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_ctxsize	= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_name		= "kmac256xof-224",
	.base.cra_driver_name	= "kmac256xof-224-leancrypto",
	.base.cra_blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= LC_KERNEL_DEFAULT_PRIO,
}, {
	.digestsize		= LC_SHA3_256_SIZE_DIGEST,
	.init			= lc_kernel_kmac256_init_alg,
	.update			= lc_kernel_kmac256_update,
	.final			= lc_kernel_kmac256_final_xof,
	.setkey			= lc_kernel_kmac256_setkey,
	.descsize		= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_ctxsize	= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_name		= "kmac256xof-256",
	.base.cra_driver_name	= "kmac256xof-256-leancrypto",
	.base.cra_blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= LC_KERNEL_DEFAULT_PRIO,
}, {
	.digestsize		= LC_SHA3_384_SIZE_DIGEST,
	.init			= lc_kernel_kmac256_init_alg,
	.update			= lc_kernel_kmac256_update,
	.final			= lc_kernel_kmac256_final_xof,
	.setkey			= lc_kernel_kmac256_setkey,
	.descsize		= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_ctxsize	= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_name		= "kmac256xof-384",
	.base.cra_driver_name	= "kmac256xof-384-leancrypto",
	.base.cra_blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= LC_KERNEL_DEFAULT_PRIO,
}, {
	.digestsize		= LC_SHA3_512_SIZE_DIGEST,
	.init			= lc_kernel_kmac256_init_alg,
	.update			= lc_kernel_kmac256_update,
	.final			= lc_kernel_kmac256_final_xof,
	.setkey			= lc_kernel_kmac256_setkey,
	.descsize		= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_ctxsize	= LC_KMAC_CTX_SIZE_KERNEL,
	.base.cra_name		= "kmac256xof-512",
	.base.cra_driver_name	= "kmac256xof-512-leancrypto",
	.base.cra_blocksize	= LC_SHA3_256_SIZE_BLOCK,
	.base.cra_module	= THIS_MODULE,
	.base.cra_priority	= LC_KERNEL_DEFAULT_PRIO,
} };

int __init lc_kernel_kmac256_init(void)
{
	return crypto_register_shashes(lc_kmac256_algs,
				       ARRAY_SIZE(lc_kmac256_algs));
}

void lc_kernel_kmac256_exit(void)
{
	crypto_unregister_shashes(lc_kmac256_algs,
				  ARRAY_SIZE(lc_kmac256_algs));
}
