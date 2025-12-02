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
#include "leancrypto_kernel_aead_helper.h"

/* Implement the walking of a scatter-gather list for AAD. */
static int lc_aes_gcm_aad(struct aead_request *areq, size_t nbytes)
{
	struct scatter_walk src_walk;
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
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

static int lc_aes_gcm_enc_final(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	unsigned int authsize = crypto_aead_authsize(aead);
	/* Maximum tag size */
	u8 tag[16];
	int ret;

	WARN_ON(sizeof(tag) < authsize);

	ret = lc_aead_enc_final(ctx, tag, authsize);
	if (ret)
		return ret;

	scatterwalk_map_and_copy(tag, areq->dst,
				 areq->assoclen + areq->cryptlen, authsize, 1);

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

	lc_aes_gcm_aad(areq, areq->assoclen);

	ret = lc_kernel_aead_update(areq, areq->cryptlen, lc_aead_enc_update);
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

	WARN_ON(sizeof(tag) < authsize);

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

	lc_aes_gcm_aad(areq, areq->assoclen);

	ret = lc_kernel_aead_update(areq,
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
	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE <
		     LC_AES_RISCV64_MAX_BLOCK_SIZE);
	BUILD_BUG_ON(LC_AES_AESNI_MAX_BLOCK_SIZE < LC_AES_C_MAX_BLOCK_SIZE);

	return 0;
}

static void lc_aes_gcm_exit(struct crypto_aead *aead)
{
}

/********************************** RFC4106  **********************************/

struct lc_rfc4106_aes_gcm_ctx {
	union {
		struct lc_aead_ctx ctx;
		uint8_t buffer[LC_AES_GCM_CTX_SIZE_LEN(
			LC_AES_AESNI_MAX_BLOCK_SIZE)];
	} ctx;

#define LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN 4
#define LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN 8
#define LC_RFC4106_AES_GCM_IV_LEN                                              \
	(LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN +                               \
	 LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN)
	uint8_t iv[LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN];
};

static int lc_rfc4106_aes_gcm_setauthsize(struct crypto_aead *aead,
					  unsigned int authsize)
{
	switch (authsize) {
	case 8:
	case 12:
	case 16:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int lc_rfc4106_aes_gcm_setkey(struct crypto_aead *aead, const u8 *key,
				     unsigned int keylen)
{
	struct lc_rfc4106_aes_gcm_ctx *rfc4106_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &rfc4106_ctx->ctx.ctx;

	if (keylen < LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN)
		return -EINVAL;
	keylen -= LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN;

	memcpy(rfc4106_ctx->iv, key + keylen,
	       LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN);

	/* Set the key, but not the IV yet */
	return lc_aead_setkey(ctx, key, keylen, NULL, 0);
}

static int lc_rfc4106_aes_gcm_init(struct crypto_aead *aead)
{
	struct lc_rfc4106_aes_gcm_ctx *rfc4106_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &rfc4106_ctx->ctx.ctx;

	LC_AES_GCM_SET_CTX(ctx);

	return 0;
}

static int lc_rfc4106_aes_gcm_setiv(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_rfc4106_aes_gcm_ctx *rfc4106_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &rfc4106_ctx->ctx.ctx;
	uint8_t iv[LC_RFC4106_AES_GCM_IV_LEN];

	memcpy(iv, rfc4106_ctx->iv, LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN);
	memcpy(iv + LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN, areq->iv,
	       LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN);

	/*
	 * NULL-key implies that the key was already set and now we only set
	 * the IV.
	 */
	return lc_aead_setkey(ctx, NULL, 0, iv, sizeof(iv));
}

static int lc_rfc4106_aes_gcm_enc(struct aead_request *areq)
{
	unsigned int assoclen = areq->assoclen;
	int ret;

	if (unlikely(assoclen != 16 && assoclen != 20))
		return -EINVAL;
	assoclen -= LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN;

	ret = lc_rfc4106_aes_gcm_setiv(areq);
	if (ret)
		return ret;

	lc_aes_gcm_aad(areq, assoclen);

	ret = lc_kernel_aead_update(areq, areq->cryptlen, lc_aead_enc_update);
	if (ret)
		return ret;

	return lc_aes_gcm_enc_final(areq);
}

static int lc_rfc4106_aes_gcm_dec(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	unsigned int assoclen = areq->assoclen;
	int ret;

	if (areq->cryptlen < crypto_aead_authsize(aead))
		return -EBADMSG;

	if (unlikely(assoclen != 16 && assoclen != 20))
		return -EINVAL;
	assoclen -= LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN;

	ret = lc_rfc4106_aes_gcm_setiv(areq);
	if (ret)
		return ret;

	lc_aes_gcm_aad(areq, assoclen);

	ret = lc_kernel_aead_update(areq,
				    areq->cryptlen - crypto_aead_authsize(aead),
				    lc_aead_dec_update);
	if (ret)
		return ret;

	return lc_aes_gcm_dec_final(areq);
}

/********************************* Interface  *********************************/

static struct aead_alg lc_aes_gcm_algs[] = {
	{
		.base = {
			.cra_name = "gcm(aes)",
			.cra_driver_name = "gcm-aes-leancrypto",
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
	}, {
		.base = {
			.cra_name = "rfc4106(gcm(aes))",
			.cra_driver_name = "rfc4106-gcm-aes-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct lc_rfc4106_aes_gcm_ctx),
			.cra_alignmask = LC_MEM_COMMON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_rfc4106_aes_gcm_setkey,
		.setauthsize = lc_rfc4106_aes_gcm_setauthsize,
		.encrypt = lc_rfc4106_aes_gcm_enc,
		.decrypt = lc_rfc4106_aes_gcm_dec,
		.init = lc_rfc4106_aes_gcm_init,
		.exit = lc_aes_gcm_exit,
		.ivsize = LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN,
		.maxauthsize = 16,
	},
};

int __init lc_kernel_aes_gcm_init(void)
{
	return crypto_register_aeads(lc_aes_gcm_algs,
				     ARRAY_SIZE(lc_aes_gcm_algs));
}

void lc_kernel_aes_gcm_exit(void)
{
	crypto_unregister_aeads(lc_aes_gcm_algs, ARRAY_SIZE(lc_aes_gcm_algs));
}
