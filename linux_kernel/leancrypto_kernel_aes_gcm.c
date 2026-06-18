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
#include "aes_internal.h"
#include "aes_riscv64.h"
#include "fips_mode.h"

#include "leancrypto_kernel.h"
#include "leancrypto_kernel_aead_helper.h"

/* Implement the walking of a scatter-gather list for AAD. */
static int lc_aes_gcm_aad(struct aead_request *areq,
			  struct lc_aead_ctx *vola_ctx, size_t nbytes)
{
	struct scatter_walk src_walk;
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

		if (!todo)
			return -EINVAL;

		ret = lc_aead_enc_init(vola_ctx, src_vaddr, todo);
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

static int lc_aes_gcm_enc_final(struct aead_request *areq,
				struct lc_aead_ctx *vola_ctx)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	unsigned int authsize = crypto_aead_authsize(aead);
	/* Maximum tag size */
	u8 tag[16];
	int ret;

	WARN_ON(sizeof(tag) < authsize);

	ret = lc_aead_enc_final(vola_ctx, tag, authsize);
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
	struct lc_aead_ctx *vola_ctx = NULL;
	int ret;

	vola_ctx = kzalloc(LC_AES_GCM_CTX_SIZE_LEN(LC_AES_AESNI_MAX_BLOCK_SIZE),
			   GFP_KERNEL);
	if (!vola_ctx)
		return -ENOMEM;

	LC_AES_GCM_SET_CTX(vola_ctx);

	ret = lc_aead_setkey_from_ctx(vola_ctx, ctx, areq->iv,
				      crypto_aead_ivsize(aead));
	if (ret)
		goto out;

	ret = lc_aes_gcm_aad(areq, vola_ctx, areq->assoclen);
	if (ret)
		goto out;

	ret = lc_kernel_aead_update(areq, vola_ctx, 1, AES_BLOCKLEN,
				    lc_aead_enc_update);
	if (ret)
		goto out;

	ret = lc_aes_gcm_enc_final(areq, vola_ctx);

out:
	lc_aead_zero(vola_ctx);
	kfree(vola_ctx);
	return ret;
}

static int lc_aes_gcm_dec_final(struct aead_request *areq,
				struct lc_aead_ctx *vola_ctx)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	unsigned int authsize = crypto_aead_authsize(aead);
	unsigned int cryptlen;
	/* Maximum tag size */
	u8 tag[16];

	WARN_ON(sizeof(tag) < authsize);

	if (areq->cryptlen < authsize)
		return -EBADMSG;

	cryptlen = areq->cryptlen - authsize;

	scatterwalk_map_and_copy(tag, areq->src, areq->assoclen + cryptlen,
				 authsize, 0);

	return lc_aead_dec_final(vola_ctx, tag, authsize);
}

static int lc_aes_gcm_dec(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *vola_ctx = NULL;
	int ret;

	if (areq->cryptlen < crypto_aead_authsize(aead))
		return -EBADMSG;

	vola_ctx = kzalloc(LC_AES_GCM_CTX_SIZE_LEN(LC_AES_AESNI_MAX_BLOCK_SIZE),
			   GFP_KERNEL);
	if (!vola_ctx)
		return -ENOMEM;

	LC_AES_GCM_SET_CTX(vola_ctx);

	ret = lc_aead_setkey_from_ctx(vola_ctx, ctx, areq->iv,
				      crypto_aead_ivsize(aead));
	if (ret)
		goto out;

	ret = lc_aes_gcm_aad(areq, vola_ctx, areq->assoclen);
	if (ret)
		goto out;

	ret = lc_kernel_aead_update(areq, vola_ctx, 0, AES_BLOCKLEN,
				    lc_aead_dec_update);
	if (ret)
		goto out;

	ret = lc_aes_gcm_dec_final(areq, vola_ctx);

out:
	lc_aead_zero(vola_ctx);
	kfree(vola_ctx);
	return ret;
}

static int lc_aes_gcm_setkey(struct crypto_aead *aead, const u8 *key,
			     unsigned int keylen)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	int ret;

	/*
	 * Force the key check already here when it is retained in the context.
	 * Of course, the key is checked when actually set with GCM, but
	 * checking it here is a defense in depth.
	 */
	ret = aes_check_keylen(keylen);
	if (ret)
		return ret;

	/* Set the key, but not the IV yet */
	return lc_aead_setkey(ctx, key, keylen, NULL, 0);
}

static int lc_aes_gcm_setauthsize(struct crypto_aead *aead,
				  unsigned int authsize)
{
	switch (authsize) {
	case 4:
		/*
		 * In FIPS-mode, GCM will not pass the full test suite due to
		 * this limit.
		 */
		if (fips140_mode_enabled())
			return -EINVAL;
		fallthrough;
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

	LC_AEAD_CTX_NO_STATE(ctx, lc_aes_gcm_aead);

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
	struct lc_aead_ctx ctx;

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
	struct lc_aead_ctx *ctx = &rfc4106_ctx->ctx;
	int ret;

	if (keylen <  LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN)
		return -EINVAL;
	keylen -= LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN;

	/*
	 * Force the key check already here when it is retained in the context.
	 * Of course, the key is checked when actually set with GCM, but
	 * checking it here is a defense in depth.
	 */
	ret = aes_check_keylen(keylen);
	if (ret)
		return ret;

	memcpy(rfc4106_ctx->iv, key + keylen,
	       LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN);

	/* Set the key, but not the IV yet */
	return lc_aead_setkey(ctx, key, keylen, NULL, 0);
}

static int lc_rfc4106_aes_gcm_init(struct crypto_aead *aead)
{
	struct lc_rfc4106_aes_gcm_ctx *rfc4106_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &rfc4106_ctx->ctx;

	LC_AEAD_CTX_NO_STATE(ctx, lc_aes_gcm_aead);

	return 0;
}

static int lc_rfc4106_aes_gcm_setiv(struct aead_request *areq,
				    struct lc_aead_ctx *vola_ctx)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_rfc4106_aes_gcm_ctx *rfc4106_ctx = crypto_aead_ctx(aead);
	struct lc_aead_ctx *ctx = &rfc4106_ctx->ctx;
	uint8_t iv[LC_RFC4106_AES_GCM_IV_LEN];

	memcpy(iv, rfc4106_ctx->iv, LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN);
	memcpy(iv + LC_RFC4106_AES_GCM_IV_FIXED_FIELD_LEN, areq->iv,
	       LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN);

	return lc_aead_setkey_from_ctx(vola_ctx, ctx, iv, sizeof(iv));
}

static int lc_rfc4106_aes_gcm_enc(struct aead_request *areq)
{
	unsigned int assoclen = areq->assoclen;
	struct lc_aead_ctx *vola_ctx = NULL;
	int ret;

	if (unlikely(assoclen != 16 && assoclen != 20))
		return -EINVAL;
	assoclen -= LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN;

	vola_ctx = kzalloc(LC_AES_GCM_CTX_SIZE_LEN(LC_AES_AESNI_MAX_BLOCK_SIZE),
			   GFP_KERNEL);
	if (!vola_ctx)
		return -ENOMEM;

	LC_AES_GCM_SET_CTX(vola_ctx);

	ret = lc_rfc4106_aes_gcm_setiv(areq, vola_ctx);
	if (ret)
		goto out;

	ret = lc_aes_gcm_aad(areq, vola_ctx, assoclen);
	if (ret)
		goto out;

	ret = lc_kernel_aead_update(areq, vola_ctx, 1, AES_BLOCKLEN,
				    lc_aead_enc_update);
	if (ret)
		goto out;

	ret = lc_aes_gcm_enc_final(areq, vola_ctx);

out:
	lc_aead_zero(vola_ctx);
	kfree(vola_ctx);
	return ret;
}

static int lc_rfc4106_aes_gcm_dec(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *vola_ctx = NULL;
	unsigned int assoclen = areq->assoclen;
	int ret;

	if (areq->cryptlen < crypto_aead_authsize(aead))
		return -EBADMSG;

	if (unlikely(assoclen != 16 && assoclen != 20))
		return -EINVAL;
	assoclen -= LC_RFC4106_AES_GCM_IV_INVOCATION_FIELD_LEN;

	vola_ctx = kzalloc(LC_AES_GCM_CTX_SIZE_LEN(LC_AES_AESNI_MAX_BLOCK_SIZE),
			   GFP_KERNEL);
	if (!vola_ctx)
		return -ENOMEM;

	LC_AES_GCM_SET_CTX(vola_ctx);

	ret = lc_rfc4106_aes_gcm_setiv(areq, vola_ctx);
	if (ret)
		goto out;

	ret = lc_aes_gcm_aad(areq, vola_ctx, assoclen);
	if (ret)
		goto out;

	ret = lc_kernel_aead_update(areq, vola_ctx, 0, AES_BLOCKLEN,
				    lc_aead_dec_update);
	if (ret)
		goto out;

	ret = lc_aes_gcm_dec_final(areq, vola_ctx);

out:
	lc_aead_zero(vola_ctx);
	kfree(vola_ctx);
	return ret;
}

/********************************* Interface  *********************************/

static struct aead_alg lc_aes_gcm_algs[] = {
	{
		.base = {
			.cra_name = "gcm(aes)",
			.cra_driver_name = "gcm-aes-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct lc_aead_ctx),
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
		.chunksize = AES_BLOCKLEN,
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
		.chunksize = AES_BLOCKLEN,
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
