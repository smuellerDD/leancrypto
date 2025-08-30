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

#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "lc_aes_gcm.h"

/* Required for context size */
#include "aes_c.h"
#include "aes_aesni.h"
#include "aes_armce.h"
#include "aes_riscv64.h"

#include "leancrypto_kernel.h"

/* Implement the walking of a scatter-gather list for AAD. */
static int lc_aes_gcm_aad(struct aead_request *areq)
{
	struct scatter_walk src_walk;
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	size_t nbytes = areq->assoclen;
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

static int lc_aes_gcm_update(struct aead_request *areq, unsigned int nbytes,
				int (*process)(struct lc_aead_ctx *ctx,
					       const uint8_t *in, uint8_t *out,
					       size_t datalen))
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct scatterlist sg_src[2], sg_dst[2];
	struct scatterlist *src, *dst;
	struct scatter_walk src_walk, dst_walk;
	int ret = 0;

	if (!nbytes)
		return 0;

	src = scatterwalk_ffwd(sg_src, areq->src, areq->assoclen);
	if (areq->src == areq->dst)
		dst = src;
	else
		dst = scatterwalk_ffwd(sg_dst, areq->dst, areq->assoclen);

	scatterwalk_start(&src_walk, src);
	scatterwalk_start(&dst_walk, dst);

	while (nbytes) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)

		unsigned int stodo = scatterwalk_next(&src_walk, nbytes);
		unsigned int dtodo = scatterwalk_next(&dst_walk, nbytes);
		unsigned int todo = min(stodo, dtodo);

		u8 *src_vaddr = src_walk.addr;
		u8 *dst_vaddr = dst_walk.addr;

		/* Perform the work */
		ret = process(ctx, src_vaddr, dst_vaddr, todo);

		scatterwalk_done_dst(&dst_walk, todo);
		scatterwalk_done_src(&src_walk, todo);
		if (ret)
			return ret;

		nbytes -= todo;

#else
		unsigned int todo =
			min_t(unsigned int, scatterwalk_pagelen(&src_walk),
			      scatterwalk_pagelen(&dst_walk));
		u8 *src_vaddr, *dst_vaddr;
		todo = min_t(unsigned int, nbytes, todo);

		src_vaddr = scatterwalk_map(&src_walk);
		dst_vaddr = scatterwalk_map(&dst_walk);

		/* Perform the work */
		ret = process(ctx, src_vaddr, dst_vaddr, todo);

		scatterwalk_unmap(src_vaddr);
		scatterwalk_unmap(dst_vaddr);

		if (ret)
			return ret;

		scatterwalk_advance(&src_walk, todo);
		scatterwalk_advance(&dst_walk, todo);
		nbytes -= todo;

		scatterwalk_pagedone(&src_walk, 0, nbytes);
		scatterwalk_pagedone(&dst_walk, 1, nbytes);

#endif
	}

	return ret;
}

static int lc_aes_gcm_enc_final(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	/* Maximum tag size */
	u8 tag[16];
	int ret;

	WARN_ON(sizeof(tag) < crypto_aead_maxauthsize(aead));

	ret = lc_aead_enc_final(ctx, tag, crypto_aead_authsize(aead));
	if (ret)
		return ret;

	scatterwalk_map_and_copy(tag, areq->dst,
				 areq->assoclen + areq->cryptlen,
				 crypto_aead_authsize(aead), 1);

	return 0;
}

static int lc_aes_gcm_enc(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	int ret;

	/*
	 * NULL-key implies that the key was already set and now we only set
	 * the IV.
	 */
	ret = lc_aead_setkey(ctx, NULL, 0, areq->iv, crypto_aead_ivsize(aead));
	if (ret)
		return ret;

	lc_aes_gcm_aad(areq);

	ret = lc_aes_gcm_update(areq, areq->cryptlen, lc_aead_enc_update);
	if (ret)
		return ret;

	return lc_aes_gcm_enc_final(areq);
}

static int lc_aes_gcm_dec_final(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	unsigned int authsize = crypto_aead_authsize(aead);
	unsigned int cryptlen = areq->cryptlen - authsize;
	/* Maximum tag size */
	u8 tag[16];

	WARN_ON(sizeof(tag) < crypto_aead_maxauthsize(aead));

	scatterwalk_map_and_copy(tag, areq->src, areq->assoclen + cryptlen,
				 authsize, 0);

	return lc_aead_dec_final(ctx, tag, authsize);
}

static int lc_aes_gcm_dec(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	int ret;

	if (areq->cryptlen < crypto_aead_authsize(aead))
		return -EBADMSG;

	/* NULL-key implies loading the key set with lc_aes_gcm_load_key */
	ret = lc_aead_setkey(ctx, NULL, 0, areq->iv, crypto_aead_ivsize(aead));
	if (ret)
		return ret;

	lc_aes_gcm_aad(areq);

	ret = lc_aes_gcm_update(areq,
				areq->cryptlen - crypto_aead_authsize(aead),
				lc_aead_dec_update);
	if (ret)
		return ret;

	return lc_aes_gcm_dec_final(areq);
}

static int lc_aes_gcm_setkey(struct crypto_aead *aead, const u8 *key,
				unsigned int keylen)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);

	/* Set the key, but not the IV yet */
	return lc_aead_setkey(ctx, key, keylen, NULL, 0);
}

static int lc_aes_gcm_setauthsize(struct crypto_aead *aead,
				  unsigned int authsize)
{
	switch (authsize) {
        case 8:
        case 12:
        case 13:
        case 14:
        case 15:
        case 16:
                break;
        default:
                return -EINVAL;
        }

        return 0;
}

static int lc_aes_gcm_init(struct crypto_aead *aead)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);

	LC_AES_GCM_SET_CTX(ctx);

	/*
	 * Verification that the setting of .cra_ctxsize is appropriate
	 */
	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE < LC_AES_ARMCE_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE < LC_AES_RISCV64_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE < LC_AES_C_MAX_BLOCK_SIZE);

	return 0;
}

static void lc_aes_gcm_exit(struct crypto_aead *aead)
{
}

static struct aead_alg lc_aes_gcm_algs[] = {
	{
		.base = {
			.cra_name = "gcm(aes)",
			.cra_driver_name = "aes-gcm-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = LC_AES_GCM_CTX_SIZE_LEN(
						LC_AES_AESNI_MAX_BLOCK_SIZE),
			.cra_alignmask = LC_MEM_COMMON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_aes_gcm_setkey,
		.setauthsize = lc_aes_gcm_setauthsize,
		.encrypt = lc_aes_gcm_enc,
		.decrypt = lc_aes_gcm_dec,
		.init = lc_aes_gcm_init,
		.exit = lc_aes_gcm_exit,
		.ivsize = 12,
		.maxauthsize = 16,
	},
};

int __init lc_kernel_aes_gcm_init(void)
{
	return crypto_register_aeads(lc_aes_gcm_algs, ARRAY_SIZE(lc_aes_gcm_algs));
}

void lc_kernel_aes_gcm_exit(void)
{
	crypto_unregister_aeads(lc_aes_gcm_algs, ARRAY_SIZE(lc_aes_gcm_algs));
}
