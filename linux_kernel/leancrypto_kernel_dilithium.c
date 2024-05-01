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

#include <crypto/internal/akcipher.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#include "lc_dilithium.h"
#include "lc_sha3.h"

#include "leancrypto_kernel.h"

enum lc_kernel_dilithium_key_type {
	lc_kernel_dilithium_key_unset = 0,
	lc_kernel_dilithium_key_sk = 1,
	lc_kernel_dilithium_key_pk = 2,
};

struct lc_kernel_dilithium_ctx {
	union {
		struct lc_dilithium_sk sk;
		struct lc_dilithium_pk pk;
	};
	enum lc_kernel_dilithium_key_type key_type;
};

static int lc_kernel_dilithium_sign(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct lc_dilithium_sig *sig;
	struct sg_mapping_iter miter;
	size_t offset = 0;
	unsigned int sg_flags = SG_MITER_ATOMIC | SG_MITER_FROM_SG;
	int ret;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	/* req->src -> message */
	/* req->dst -> signature */

	if (unlikely(ctx->key_type != lc_kernel_dilithium_key_sk) ||
	    req->dst_len != LC_DILITHIUM_CRYPTO_BYTES)
		return -EINVAL;

	sig = kmalloc(sizeof(struct lc_dilithium_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	lc_dilithium_sign_init(hash_ctx, &ctx->sk);

	sg_miter_start(&miter, req->src,
		       sg_nents_for_len(req->src, req->src_len), sg_flags);

	while ((offset < req->dst_len) && sg_miter_next(&miter)) {
		unsigned int len = min(miter.length, req->dst_len - offset);

		lc_dilithium_sign_update(hash_ctx, miter.addr, len);
		offset += len;
	}

	sg_miter_stop(&miter);

	ret = lc_dilithium_sign_final(sig, hash_ctx, &ctx->sk, lc_seeded_rng);

	lc_hash_zero(hash_ctx);

	if (!ret) {
		sg_pcopy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     sig, LC_DILITHIUM_CRYPTO_BYTES, 0);
	}

	kfree_sensitive(sig);
	return ret;
}

static int lc_kernel_dilithium_verify(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct lc_dilithium_sig *sig;
	struct sg_mapping_iter miter;
	size_t offset = 0;
	unsigned int sg_flags = SG_MITER_ATOMIC | SG_MITER_FROM_SG;
	int ret;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	/* req->src -> signature */
	/* req->dst -> message */

	if (unlikely(ctx->key_type != lc_kernel_dilithium_key_pk) ||
	    req->src_len != LC_DILITHIUM_CRYPTO_BYTES)
		return -EINVAL;

	sig = kmalloc(sizeof(struct lc_dilithium_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	sg_pcopy_to_buffer(req->src, sg_nents_for_len(req->src, req->src_len),
			   sig->sig, LC_DILITHIUM_CRYPTO_BYTES, 0);

	lc_dilithium_verify_init(hash_ctx, &ctx->pk);

	sg_miter_start(&miter, req->dst,
		       sg_nents_for_len(req->dst, req->dst_len), sg_flags);

	while ((offset < req->dst_len) && sg_miter_next(&miter)) {
		unsigned int len = min(miter.length, req->dst_len - offset);

		lc_dilithium_verify_update(hash_ctx, miter.addr, len);
		offset += len;
	}

	sg_miter_stop(&miter);

	ret = lc_dilithium_verify_final(sig, hash_ctx, &ctx->pk);

	lc_hash_zero(hash_ctx);

	kfree_sensitive(sig);

	return ret;
}

static int lc_kernel_dilithium_set_pub_key(struct crypto_akcipher *tfm,
					   const void *key, unsigned int keylen)
{
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);

	ctx->key_type = lc_kernel_dilithium_key_unset;

	if (keylen != LC_DILITHIUM_PUBLICKEYBYTES)
		return -EINVAL;

	memcpy(ctx->pk.pk, key, LC_DILITHIUM_PUBLICKEYBYTES);
	ctx->key_type = lc_kernel_dilithium_key_pk;

	return 0;
}

static int lc_kernel_dilithium_set_priv_key(struct crypto_akcipher *tfm,
					    const void *key,
					    unsigned int keylen)
{
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);

	ctx->key_type = lc_kernel_dilithium_key_unset;

	if (keylen != LC_DILITHIUM_SECRETKEYBYTES)
		return -EINVAL;

	memcpy(ctx->sk.sk, key, LC_DILITHIUM_SECRETKEYBYTES);
	ctx->key_type = lc_kernel_dilithium_key_sk;

	return 0;
}

static unsigned int lc_kernel_dilithium_max_size(struct crypto_akcipher *tfm)
{
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_dilithium_key_sk:
		/* When SK is set -> generate a signature */
		return LC_DILITHIUM_CRYPTO_BYTES;
	case lc_kernel_dilithium_key_pk:
		/* When PK is set, this is a safety valve, result is boolean */
		return LC_DILITHIUM_CRYPTO_BYTES;
	default:
		return 0;
	}
}

static int lc_kernel_dilithium_alg_init(struct crypto_akcipher *tfm)
{
	return 0;
}

static void lc_kernel_dilithium_alg_exit(struct crypto_akcipher *tfm)
{
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);

	ctx->key_type = lc_kernel_dilithium_key_unset;
}

static struct akcipher_alg lc_kernel_dilithium = {
	.sign = lc_kernel_dilithium_sign,
	.verify = lc_kernel_dilithium_verify,
	.set_pub_key = lc_kernel_dilithium_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_set_priv_key,
	.max_size = lc_kernel_dilithium_max_size,
	.init = lc_kernel_dilithium_alg_init,
	.exit = lc_kernel_dilithium_alg_exit,
#if LC_DILITHIUM_MODE == 2
	.base.cra_name = "dilithium44",
	.base.cra_driver_name = "dilithium44-leancrypto",
#elif LC_DILITHIUM_MODE == 3
	.base.cra_name = "dilithium65",
	.base.cra_driver_name = "dilithium65-leancrypto",
#else
	.base.cra_name = "dilithium87",
	.base.cra_driver_name = "dilithium87-leancrypto",
#endif
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

int __init lc_kernel_dilithium_init(void)
{
	return crypto_register_akcipher(&lc_kernel_dilithium);
}

void lc_kernel_dilithium_exit(void)
{
	crypto_unregister_akcipher(&lc_kernel_dilithium);
}
