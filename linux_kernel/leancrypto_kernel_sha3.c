// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
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

#include "lc_sha3.h"

#include "leancrypto_kernel.h"

static int lc_kernel_sha3_224_init(struct shash_desc *desc)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	LC_SHA3_224_CTX(sctx);
	lc_hash_init(sctx);

	return 0;
}

static int lc_kernel_sha3_256_init(struct shash_desc *desc)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	LC_SHA3_256_CTX(sctx);
	lc_hash_init(sctx);

	return 0;
}

static int lc_kernel_sha3_384_init(struct shash_desc *desc)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	LC_SHA3_384_CTX(sctx);
	lc_hash_init(sctx);

	return 0;
}

static int lc_kernel_sha3_512_init(struct shash_desc *desc)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	LC_SHA3_512_CTX(sctx);
	lc_hash_init(sctx);

	return 0;
}

static int lc_kernel_sha3_update(struct shash_desc *desc, const u8 *data,
				 unsigned int len)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	lc_hash_update(sctx, data, len);

	return 0;
}

static int lc_kernel_sha3_final(struct shash_desc *desc, u8 *out)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	lc_hash_final(sctx, out);

	return 0;
}

static struct shash_alg lc_sha3_algs[] = {
	{
		.digestsize = LC_SHA3_224_SIZE_DIGEST,
		.init = lc_kernel_sha3_224_init,
		.update = lc_kernel_sha3_update,
		.final = lc_kernel_sha3_final,
		.descsize = LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_224_CTX_SIZE),
		.base.cra_name = "sha3-224",
		.base.cra_driver_name = "sha3-224-leancrypto",
		.base.cra_blocksize = LC_SHA3_224_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
	{
		.digestsize = LC_SHA3_256_SIZE_DIGEST,
		.init = lc_kernel_sha3_256_init,
		.update = lc_kernel_sha3_update,
		.final = lc_kernel_sha3_final,
		.descsize = LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_256_CTX_SIZE),
		.base.cra_name = "sha3-256",
		.base.cra_driver_name = "sha3-256-leancrypto",
		.base.cra_blocksize = LC_SHA3_256_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
	{
		.digestsize = LC_SHA3_384_SIZE_DIGEST,
		.init = lc_kernel_sha3_384_init,
		.update = lc_kernel_sha3_update,
		.final = lc_kernel_sha3_final,
		.descsize = LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_384_CTX_SIZE),
		.base.cra_name = "sha3-384",
		.base.cra_driver_name = "sha3-384-leancrypto",
		.base.cra_blocksize = LC_SHA3_384_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
	{
		.digestsize = LC_SHA3_512_SIZE_DIGEST,
		.init = lc_kernel_sha3_512_init,
		.update = lc_kernel_sha3_update,
		.final = lc_kernel_sha3_final,
		.descsize = LC_SHA3_STATE_SIZE_ALIGN(LC_SHA3_512_CTX_SIZE),
		.base.cra_name = "sha3-512",
		.base.cra_driver_name = "sha3-512-leancrypto",
		.base.cra_blocksize = LC_SHA3_512_SIZE_BLOCK,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	}
};

int __init lc_kernel_sha3_init(void)
{
	return crypto_register_shashes(lc_sha3_algs, ARRAY_SIZE(lc_sha3_algs));
}

void lc_kernel_sha3_exit(void)
{
	crypto_unregister_shashes(lc_sha3_algs, ARRAY_SIZE(lc_sha3_algs));
}
