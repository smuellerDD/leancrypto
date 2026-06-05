/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include "lc_hmac.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "ret_checkers.h"

#include "leancrypto_kernel.h"

#define LC_HMAC_CTX_SIZE_KERNEL                                                \
	(LC_HASH_STATE_SIZE_ALIGN(sizeof(struct lc_hmac_ctx)))
#define LC_HMAC_KEY_SIZE_KERNEL                                                \
	(LC_HASH_STATE_SIZE_ALIGN(sizeof(struct lc_hmac_key)))

static int lc_kernel_hmac_init_alg(struct shash_desc *desc,
				   const struct lc_hash *hash)
{
	struct lc_hmac_ctx *sctx = shash_desc_ctx(desc);
	struct crypto_shash *tfm = desc->tfm;
	struct lc_hmac_key *hmac_key = crypto_shash_ctx(tfm);

	LC_HMAC_SET_CTX(sctx, hash);
	sctx->key = NULL;

	return lc_hmac_init_with_hmac_key(sctx, hmac_key);
}

static int lc_kernel_hmac_setkey(struct crypto_shash *tfm, const u8 *key,
				 unsigned int keylen,
				 const struct lc_hash *hash)
{
	struct lc_hmac_key *hmac_key = crypto_shash_ctx(tfm);

	return lc_hmac_setkey(hmac_key, hash, key, keylen);
}

#ifdef CONFIG_LEANCRYPTO_SHA2_256
static int lc_kernel_hmac_sha2_256_init_alg(struct shash_desc *desc)
{
	return lc_kernel_hmac_init_alg(desc, lc_sha256);
}

static int lc_kernel_hmac_sha2_256_setkey(struct crypto_shash *tfm,
					  const u8 *key, unsigned int keylen)
{
	return lc_kernel_hmac_setkey(tfm, key, keylen, lc_sha256);
}
#endif

#ifdef CONFIG_LEANCRYPTO_SHA2_512
static int lc_kernel_hmac_sha2_384_init_alg(struct shash_desc *desc)
{
	return lc_kernel_hmac_init_alg(desc, lc_sha384);
}

static int lc_kernel_hmac_sha2_512_init_alg(struct shash_desc *desc)
{
	return lc_kernel_hmac_init_alg(desc, lc_sha512);
}

static int lc_kernel_hmac_sha2_384_setkey(struct crypto_shash *tfm,
					  const u8 *key, unsigned int keylen)
{
	return lc_kernel_hmac_setkey(tfm, key, keylen, lc_sha384);
}

static int lc_kernel_hmac_sha2_512_setkey(struct crypto_shash *tfm,
					  const u8 *key, unsigned int keylen)
{
	return lc_kernel_hmac_setkey(tfm, key, keylen, lc_sha512);
}
#endif

#ifdef CONFIG_LEANCRYPTO_SHA3
static int lc_kernel_hmac_sha3_256_init_alg(struct shash_desc *desc)
{
	return lc_kernel_hmac_init_alg(desc, lc_sha3_256);
}

static int lc_kernel_hmac_sha3_384_init_alg(struct shash_desc *desc)
{
	return lc_kernel_hmac_init_alg(desc, lc_sha3_384);
}

static int lc_kernel_hmac_sha3_513_init_alg(struct shash_desc *desc)
{
	return lc_kernel_hmac_init_alg(desc, lc_sha3_512);
}

static int lc_kernel_hmac_sha3_256_setkey(struct crypto_shash *tfm,
					  const u8 *key, unsigned int keylen)
{
	return lc_kernel_hmac_setkey(tfm, key, keylen, lc_sha3_256);
}

static int lc_kernel_hmac_sha3_384_setkey(struct crypto_shash *tfm,
					  const u8 *key, unsigned int keylen)
{
	return lc_kernel_hmac_setkey(tfm, key, keylen, lc_sha3_384);
}

static int lc_kernel_hmac_sha3_513_setkey(struct crypto_shash *tfm,
					  const u8 *key, unsigned int keylen)
{
	return lc_kernel_hmac_setkey(tfm, key, keylen, lc_sha3_512);
}
#endif

static int lc_kernel_hmac_update(struct shash_desc *desc, const u8 *data,
				    unsigned int len)
{
	struct lc_hmac_ctx *sctx = shash_desc_ctx(desc);

	lc_hmac_update(sctx, data, len);

	return 0;
}

static int lc_kernel_hmac_final(struct shash_desc *desc, u8 *out)
{
	struct lc_hmac_ctx *sctx = shash_desc_ctx(desc);

	lc_hmac_final(sctx, out);

	return 0;
}

static struct shash_alg lc_hmac_algs[] = {
#ifdef CONFIG_LEANCRYPTO_SHA2_256
	{
		.digestsize = LC_SHA256_SIZE_DIGEST,
		.init = lc_kernel_hmac_sha2_256_init_alg,
		.update = lc_kernel_hmac_update,
		.final = lc_kernel_hmac_final,
		.setkey = lc_kernel_hmac_sha2_256_setkey,
		.descsize = LC_HMAC_CTX_SIZE_KERNEL,
		.base.cra_ctxsize = LC_HMAC_KEY_SIZE_KERNEL,
		.base.cra_name = "hmac(sha256)",
		.base.cra_driver_name = "hmac-sha256-leancrypto",
		.base.cra_blocksize = LC_SHA256_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
#endif
#ifdef CONFIG_LEANCRYPTO_SHA2_512
	{
		.digestsize = LC_SHA384_SIZE_DIGEST,
		.init = lc_kernel_hmac_sha2_384_init_alg,
		.update = lc_kernel_hmac_update,
		.final = lc_kernel_hmac_final,
		.setkey = lc_kernel_hmac_sha2_384_setkey,
		.descsize = LC_HMAC_CTX_SIZE_KERNEL,
		.base.cra_ctxsize = LC_HMAC_KEY_SIZE_KERNEL,
		.base.cra_name = "hmac(sha384)",
		.base.cra_driver_name = "hmac-sha384-leancrypto",
		.base.cra_blocksize = LC_SHA384_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
	{
		.digestsize = LC_SHA512_SIZE_DIGEST,
		.init = lc_kernel_hmac_sha2_512_init_alg,
		.update = lc_kernel_hmac_update,
		.final = lc_kernel_hmac_final,
		.setkey = lc_kernel_hmac_sha2_512_setkey,
		.descsize = LC_HMAC_CTX_SIZE_KERNEL,
		.base.cra_ctxsize = LC_HMAC_KEY_SIZE_KERNEL,
		.base.cra_name = "hmac(sha512)",
		.base.cra_driver_name = "hmac-sha512-leancrypto",
		.base.cra_blocksize = LC_SHA512_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
#endif
#ifdef CONFIG_LEANCRYPTO_SHA3
	{
		.digestsize = LC_SHA3_256_SIZE_DIGEST,
		.init = lc_kernel_hmac_sha3_256_init_alg,
		.update = lc_kernel_hmac_update,
		.final = lc_kernel_hmac_final,
		.setkey = lc_kernel_hmac_sha3_256_setkey,
		.descsize = LC_HMAC_CTX_SIZE_KERNEL,
		.base.cra_ctxsize = LC_HMAC_KEY_SIZE_KERNEL,
		.base.cra_name = "hmac(sha3-256)",
		.base.cra_driver_name = "hmac-sha3-256-leancrypto",
		.base.cra_blocksize = LC_SHA3_256_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
	{
		.digestsize = LC_SHA3_384_SIZE_DIGEST,
		.init = lc_kernel_hmac_sha3_384_init_alg,
		.update = lc_kernel_hmac_update,
		.final = lc_kernel_hmac_final,
		.setkey = lc_kernel_hmac_sha3_384_setkey,
		.descsize = LC_HMAC_CTX_SIZE_KERNEL,
		.base.cra_ctxsize = LC_HMAC_KEY_SIZE_KERNEL,
		.base.cra_name = "hmac(sha3-384)",
		.base.cra_driver_name = "hmac-sha3-384-leancrypto",
		.base.cra_blocksize = LC_SHA3_384_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
	{
		.digestsize = LC_SHA3_512_SIZE_DIGEST,
		.init = lc_kernel_hmac_sha3_513_init_alg,
		.update = lc_kernel_hmac_update,
		.final = lc_kernel_hmac_final,
		.setkey = lc_kernel_hmac_sha3_513_setkey,
		.descsize = LC_HMAC_CTX_SIZE_KERNEL,
		.base.cra_ctxsize = LC_HMAC_KEY_SIZE_KERNEL,
		.base.cra_name = "hmac(sha3-512)",
		.base.cra_driver_name = "hmac-sha3-512-leancrypto",
		.base.cra_blocksize = LC_SHA3_512_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
#endif
};

int __init lc_kernel_hmac_init(void)
{
	return crypto_register_shashes(lc_hmac_algs,
				       ARRAY_SIZE(lc_hmac_algs));
}

void lc_kernel_hmac_exit(void)
{
	crypto_unregister_shashes(lc_hmac_algs, ARRAY_SIZE(lc_hmac_algs));
}
