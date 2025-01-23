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

#include <crypto/internal/rng.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "lc_xdrbg.h"

#include "leancrypto_kernel.h"

struct lc_kernel_rng_state {
	struct mutex rng_mutex; /* lock around DRBG */
	struct lc_rng_ctx *rng_ctx;
};

static int lc_kernel_rng_generate(struct crypto_rng *tfm, const u8 *src,
				  unsigned int slen, u8 *dst, unsigned int dlen)
{
	struct lc_kernel_rng_state *rng = crypto_rng_ctx(tfm);
	struct lc_rng_ctx *rng_ctx = rng->rng_ctx;
	int ret;

	mutex_lock(&rng->rng_mutex);
	ret = lc_rng_generate(rng_ctx, src, slen, dst, dlen);
	mutex_unlock(&rng->rng_mutex);

	return ret;
}

static int lc_kernel_rng_seed(struct crypto_rng *tfm, const u8 *seed,
			      unsigned int slen)
{
	struct lc_kernel_rng_state *rng = crypto_rng_ctx(tfm);
	struct lc_rng_ctx *rng_ctx = rng->rng_ctx;
	int ret;

	mutex_lock(&rng->rng_mutex);
	ret = lc_rng_seed(rng_ctx, seed, slen, NULL, 0);
	mutex_unlock(&rng->rng_mutex);

	return ret;
}

static int lc_kernel_xdrbg256_init(struct crypto_tfm *tfm)
{
	struct lc_kernel_rng_state *xdrbg = crypto_tfm_ctx(tfm);

	mutex_init(&xdrbg->rng_mutex);
	xdrbg->rng_ctx =
		(struct lc_rng_ctx *)((uint8_t *)xdrbg +
				      sizeof(struct lc_kernel_rng_state));
	LC_XDRBG256_RNG_CTX(xdrbg->rng_ctx);

	return 0;
}

static void lc_kernel_xdrbg256_cleanup(struct crypto_tfm *tfm)
{
	struct lc_kernel_rng_state *xdrbg = crypto_tfm_ctx(tfm);
	struct lc_rng_ctx *rng_ctx = xdrbg->rng_ctx;

	lc_rng_zero(rng_ctx);
}

static int lc_kernel_seeded_init(struct crypto_tfm *tfm)
{
	struct lc_kernel_rng_state *seeded = crypto_tfm_ctx(tfm);

	mutex_init(&seeded->rng_mutex);
	seeded->rng_ctx = lc_seeded_rng;

	return 0;
}

static void lc_kernel_seeded_cleanup(struct crypto_tfm *tfm)
{
	struct lc_kernel_rng_state *seeded = crypto_tfm_ctx(tfm);
	struct lc_rng_ctx *rng_ctx = seeded->rng_ctx;

	/* No cleanup, but simply reseed */
	lc_rng_seed(rng_ctx, NULL, 0, NULL, 0);
}

static struct rng_alg lc_rng_algs[] = {
	{ .generate = lc_kernel_rng_generate,
	  .seed = lc_kernel_rng_seed,
	  .seedsize = 256,
	  .base.cra_name = "stdrng",
	  .base.cra_driver_name = "xdrbg256-leancrypto",
	  .base.cra_ctxsize = LC_XDRBG256_DRNG_CTX_SIZE +
			      sizeof(struct lc_kernel_rng_state),
	  .base.cra_module = THIS_MODULE,
	  .base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
	  .base.cra_init = lc_kernel_xdrbg256_init,
	  .base.cra_exit = lc_kernel_xdrbg256_cleanup },
	{ .generate = lc_kernel_rng_generate,
	  .seed = lc_kernel_rng_seed,
	  .seedsize = 0,
	  .base.cra_name = "stdrng",
	  .base.cra_driver_name = "seededrng-leancrypto",
	  .base.cra_ctxsize = LC_XDRBG256_DRNG_CTX_SIZE,
	  .base.cra_module = THIS_MODULE,
	  .base.cra_priority = LC_KERNEL_DEFAULT_PRIO + 1,
	  .base.cra_init = lc_kernel_seeded_init,
	  .base.cra_exit = lc_kernel_seeded_cleanup }
};

int __init lc_kernel_rng_init(void)
{
	return crypto_register_rngs(lc_rng_algs, ARRAY_SIZE(lc_rng_algs));
}

void lc_kernel_rng_exit(void)
{
	crypto_unregister_rngs(lc_rng_algs, ARRAY_SIZE(lc_rng_algs));
}
