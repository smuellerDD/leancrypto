// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "lc_ascon_hash.h"

#include "leancrypto_kernel.h"

static int lc_kernel_ascon_256_init(struct shash_desc *desc)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	LC_ASCON_CTX(sctx, lc_ascon_256);
	return lc_hash_init(sctx);
}

static int lc_kernel_ascon_update(struct shash_desc *desc, const u8 *data,
				  unsigned int len)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	lc_hash_update(sctx, data, len);

	return 0;
}

static int lc_kernel_ascon_final(struct shash_desc *desc, u8 *out)
{
	struct lc_hash_ctx *sctx = shash_desc_ctx(desc);

	lc_hash_final(sctx, out);

	return 0;
}

static struct shash_alg lc_ascon_algs[] = {
	{
		.digestsize = LC_ASCON_HASH_DIGESTSIZE,
		.init = lc_kernel_ascon_256_init,
		.update = lc_kernel_ascon_update,
		.final = lc_kernel_ascon_final,
		.descsize = LC_ASCON_CTX_SIZE,
		.base.cra_name = "ascon-256",
		.base.cra_driver_name = "ascon-256-leancrypto",
		.base.cra_blocksize = LC_ASCON_HASH_RATE,
		.base.cra_module = THIS_MODULE,
		.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	},
};

int __init lc_kernel_ascon_init(void)
{
	return crypto_register_shashes(lc_ascon_algs,
				       ARRAY_SIZE(lc_ascon_algs));
}

void lc_kernel_ascon_exit(void)
{
	crypto_unregister_shashes(lc_ascon_algs, ARRAY_SIZE(lc_ascon_algs));
}
