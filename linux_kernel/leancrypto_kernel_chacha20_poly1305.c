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

#include <crypto/chacha.h>
#include <crypto/internal/aead.h>
#include <crypto/poly1305.h>
#include <crypto/scatterwalk.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "lc_chacha20_poly1305.h"

#include "leancrypto_kernel.h"
#include "leancrypto_kernel_aead_helper.h"

struct lc_rfc7539_cc20p1305_ctx {
	union {
		struct lc_aead_ctx ctx;
		uint8_t buffer[LC_CHACHA20_POLY1305_CTX_SIZE];
	} ctx;

	uint8_t saltlen;

#define LC_RFC7539ESP_CC20P1305_SALT_LEN 4
	uint8_t salt[LC_RFC7539ESP_CC20P1305_SALT_LEN];
};

/* Implement the walking of a scatter-gather list for AAD. */
static int lc_cc20p1305_aad(struct aead_request *areq, size_t nbytes)
{
	struct scatter_walk src_walk;
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_rfc7539_cc20p1305_ctx *cc20p1305_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &cc20p1305_ctx->ctx.ctx;
	int ret;

	if (!nbytes)
		return 0;

	scatterwalk_start(&src_walk, areq->src);

	/* Insert the associated data into the sponge */
	while (nbytes) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
		unsigned int todo = scatterwalk_next(&src_walk, nbytes);
		u8 *src_vaddr = src_walk.addr;
#else
		unsigned int todo = scatterwalk_clamp(&src_walk, nbytes);
		u8 *src_vaddr = scatterwalk_map(&src_walk);
#endif
		ret = lc_aead_enc_init(ctx, src_vaddr, todo);
		if (ret)
			return ret;

		nbytes -= todo;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
		scatterwalk_done_src(&src_walk, todo);
#else
		scatterwalk_unmap(src_vaddr);

		scatterwalk_advance(&src_walk, todo);
		scatterwalk_pagedone(&src_walk, 0, nbytes);
#endif
	}

	return 0;
}

static int lc_cc20p1305_enc_final(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_rfc7539_cc20p1305_ctx *cc20p1305_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &cc20p1305_ctx->ctx.ctx;
	unsigned int authsize = crypto_aead_authsize(aead);
	/* Maximum tag size */
	u8 tag[POLY1305_DIGEST_SIZE];
	int ret;

	WARN_ON(sizeof(tag) < authsize);

	ret = lc_aead_enc_final(ctx, tag, authsize);
	if (ret)
		return ret;

	scatterwalk_map_and_copy(tag, areq->dst,
				 areq->assoclen + areq->cryptlen, authsize, 1);

	return 0;
}

static int lc_cc20p1305_setiv(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_rfc7539_cc20p1305_ctx *cc20p1305_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &cc20p1305_ctx->ctx.ctx;
	uint8_t iv[CHACHAPOLY_IV_SIZE];

	memcpy(iv, cc20p1305_ctx->salt, cc20p1305_ctx->saltlen);
	memcpy(iv + cc20p1305_ctx->saltlen, areq->iv,
	       CHACHAPOLY_IV_SIZE - cc20p1305_ctx->saltlen);

	/*
	 * NULL-key implies that the key was already set and now we only set
	 * the IV.
	 */
	return lc_aead_setkey(ctx, NULL, 0, iv, sizeof(iv));
}

static int lc_cc20p1305_enc(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	unsigned int assoclen = areq->assoclen;
	int ret;

	/*
	 * Chacha20-Poly1305 used in ESP context
	 */
	if (crypto_aead_ivsize(aead) == 8) {
		if (assoclen < 8)
			return -EINVAL;
		assoclen -= 8;
	}

	ret = lc_cc20p1305_setiv(areq);
	if (ret)
		return ret;

	lc_cc20p1305_aad(areq, assoclen);

	ret = lc_kernel_aead_update(areq, areq->cryptlen, lc_aead_enc_update);
	if (ret)
		return ret;

	return lc_cc20p1305_enc_final(areq);
}

static int lc_cc20p1305_dec_final(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_rfc7539_cc20p1305_ctx *cc20p1305_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &cc20p1305_ctx->ctx.ctx;
	unsigned int authsize = crypto_aead_authsize(aead);
	unsigned int cryptlen = areq->cryptlen - authsize;
	/* Maximum tag size */
	uint8_t tag[POLY1305_DIGEST_SIZE];

	scatterwalk_map_and_copy(tag, areq->src, areq->assoclen + cryptlen,
				 authsize, 0);

	return lc_aead_dec_final(ctx, tag, authsize);
}

static int lc_cc20p1305_dec(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	unsigned int authsize = crypto_aead_authsize(aead);
	unsigned int assoclen = areq->assoclen;
	int ret;

	/*
	 * Chacha20-Poly1305 used in ESP context
	 */
	if (crypto_aead_ivsize(aead) == 8) {
		if (assoclen < 8)
			return -EINVAL;
		assoclen -= 8;
	}

	if (areq->cryptlen < authsize)
		return -EBADMSG;

	ret = lc_cc20p1305_setiv(areq);
	if (ret)
		return ret;

	lc_cc20p1305_aad(areq, assoclen);

	ret = lc_kernel_aead_update(areq, areq->cryptlen - authsize,
				    lc_aead_dec_update);
	if (ret)
		return ret;

	return lc_cc20p1305_dec_final(areq);
}

static int lc_cc20p1305_setkey(struct crypto_aead *aead, const u8 *key,
			       unsigned int keylen)
{
	struct lc_rfc7539_cc20p1305_ctx *cc20p1305_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &cc20p1305_ctx->ctx.ctx;

	if (keylen != cc20p1305_ctx->saltlen + CHACHA_KEY_SIZE)
		return -EINVAL;

	keylen -= cc20p1305_ctx->saltlen;

	memcpy(cc20p1305_ctx->salt, key + keylen, cc20p1305_ctx->saltlen);

	/* Set the key, but not the IV yet */
	return lc_aead_setkey(ctx, key, keylen, NULL, 0);
}

static int lc_cc20p1305_setauthsize(struct crypto_aead *aead,
				    unsigned int authsize)
{
	if (authsize != POLY1305_DIGEST_SIZE)
		return -EINVAL;

	return 0;
}

static int lc_cc20p1305_init(struct crypto_aead *aead)
{
	struct lc_rfc7539_cc20p1305_ctx *cc20p1305_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &cc20p1305_ctx->ctx.ctx;

	LC_CHACHA20_POLY1305_SET_CTX(ctx);

	cc20p1305_ctx->saltlen = CHACHAPOLY_IV_SIZE - crypto_aead_ivsize(aead);

	return 0;
}

static void lc_cc20p1305_exit(struct crypto_aead *aead)
{
}

/********************************* Interface  *********************************/

static struct aead_alg lc_cc20p1305_algs[] = {
	{
		.base = {
			.cra_name = "chacha20(rfc7539,poly1305)",
			.cra_driver_name = "chacha20-rfc7539-poly1305-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct lc_rfc7539_cc20p1305_ctx),
			.cra_alignmask = LC_MEM_COMMON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_cc20p1305_setkey,
		.setauthsize = lc_cc20p1305_setauthsize,
		.encrypt = lc_cc20p1305_enc,
		.decrypt = lc_cc20p1305_dec,
		.init = lc_cc20p1305_init,
		.exit = lc_cc20p1305_exit,
		.ivsize = CHACHAPOLY_IV_SIZE,
		.maxauthsize = POLY1305_DIGEST_SIZE,
	}, {
		.base = {
			.cra_name = "chacha20(rfc7539esp,poly1305)",
			.cra_driver_name = "chacha20-rfc7539esp-poly1305-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct lc_rfc7539_cc20p1305_ctx),
			.cra_alignmask = LC_MEM_COMMON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_cc20p1305_setkey,
		.setauthsize = lc_cc20p1305_setauthsize,
		.encrypt = lc_cc20p1305_enc,
		.decrypt = lc_cc20p1305_dec,
		.init = lc_cc20p1305_init,
		.exit = lc_cc20p1305_exit,
		.ivsize = CHACHAPOLY_IV_SIZE - LC_RFC7539ESP_CC20P1305_SALT_LEN,
		.maxauthsize = POLY1305_DIGEST_SIZE,
	},
};

int __init lc_kernel_cc20p1305_init(void)
{
	return crypto_register_aeads(lc_cc20p1305_algs,
				     ARRAY_SIZE(lc_cc20p1305_algs));
}

void lc_kernel_cc20p1305_exit(void)
{
	crypto_unregister_aeads(lc_cc20p1305_algs,
				ARRAY_SIZE(lc_cc20p1305_algs));
}
