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

#include <crypto/internal/akcipher.h>
#include <crypto/scatterwalk.h>
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
	enum lc_dilithium_type type;
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(dilithium_ctx);

	/* req->src -> message */
	/* req->dst -> signature */

	if (unlikely(ctx->key_type != lc_kernel_dilithium_key_sk))
		return -EINVAL;

	type = lc_dilithium_sk_type(&ctx->sk);
	if (req->dst_len != lc_dilithium_sig_size(type))
		return -EINVAL;

	sig = kmalloc(sizeof(struct lc_dilithium_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	lc_dilithium_sign_init(dilithium_ctx, &ctx->sk);

	sg_miter_start(&miter, req->src,
		       sg_nents_for_len(req->src, req->src_len), sg_flags);

	while ((offset < req->src_len) && sg_miter_next(&miter)) {
		unsigned int len = min(miter.length, req->src_len - offset);

		ret = lc_dilithium_sign_update(dilithium_ctx, miter.addr, len);
		if (ret)
			goto out;
		offset += len;
	}

	sg_miter_stop(&miter);

	ret = lc_dilithium_sign_final(sig, dilithium_ctx, &ctx->sk,
				      lc_seeded_rng);

	if (!ret) {
		uint8_t *sig_ptr;
		size_t sig_len;

		ret = lc_dilithium_sig_ptr(&sig_ptr, &sig_len, sig);
		if (ret)
			goto out;

		sg_pcopy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     sig_ptr, sig_len, 0);
	}

out:
	free_zero(sig);
	lc_dilithium_ctx_zero(dilithium_ctx);
	return ret;
}

static int lc_kernel_dilithium_verify(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct lc_dilithium_sig *sig;
	struct sg_mapping_iter miter;
	struct scatterlist msg_sg_src[2];
	struct scatterlist *msg_sgl;
	size_t msg_len, offset = 0, sig_len;
	unsigned int sg_flags = SG_MITER_ATOMIC | SG_MITER_FROM_SG;
	enum lc_dilithium_type type;
	uint8_t *sig_ptr;
	int ret;
	LC_DILITHIUM_CTX_ON_STACK(dilithium_ctx);

	/* req->src -> signature || message */

	if (unlikely(ctx->key_type != lc_kernel_dilithium_key_pk))
		return -EINVAL;

	type = lc_dilithium_pk_type(&ctx->pk);
	if (req->src_len < lc_dilithium_sig_size(type))
		return -EINVAL;

	sig = kmalloc(sizeof(struct lc_dilithium_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	/*
	 * Obtain the empty pointers to fill it with a signature. Thus, we
	 * need to set the signature type here as the signature struct is
	 * currently unset.
	 */
	sig->dilithium_type = type;
	ret = lc_dilithium_sig_ptr(&sig_ptr, &sig_len, sig);
	if (ret)
		goto out;

	/* Sanity check - should not be needed as we check length above */
	if (req->src_len < sig_len) {
		ret = -EOVERFLOW;
		goto out;
	}

	/* Copy Dilithium signature into local buffer */
	sg_pcopy_to_buffer(req->src, sg_nents_for_len(req->src, req->src_len),
			   sig_ptr, sig_len, 0);

	/* Forward SGL to the message */
	msg_sgl = scatterwalk_ffwd(msg_sg_src, req->src, sig_len);
	msg_len = req->src_len - sig_len;

	lc_dilithium_verify_init(dilithium_ctx, &ctx->pk);

	sg_miter_start(&miter, msg_sgl,
		       sg_nents_for_len(msg_sgl, msg_len), sg_flags);

	while ((offset < msg_len) && sg_miter_next(&miter)) {
		unsigned int len = min(miter.length, msg_len - offset);

		ret = lc_dilithium_verify_update(dilithium_ctx, miter.addr,
						 len);
		if (ret)
			goto out;
		offset += len;
	}

	sg_miter_stop(&miter);

	ret = lc_dilithium_verify_final(sig, dilithium_ctx, &ctx->pk);

out:
	lc_dilithium_ctx_zero(dilithium_ctx);

	free_zero(sig);

	return ret;
}

static int lc_kernel_dilithium_set_pub_key_int(struct crypto_akcipher *tfm,
					       const void *key,
					       unsigned int keylen,
					       enum lc_dilithium_type type)
{
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	ctx->key_type = lc_kernel_dilithium_key_unset;

	ret = lc_dilithium_pk_load(&ctx->pk, key, keylen);

	if (!ret) {
		if (lc_dilithium_pk_type(&ctx->pk) != type)
			ret = -EOPNOTSUPP;
		else
			ctx->key_type = lc_kernel_dilithium_key_pk;
	}

	return ret;
}

static int lc_kernel_dilithium_44_set_pub_key(struct crypto_akcipher *tfm,
					      const void *key,
					      unsigned int keylen)
{
	return lc_kernel_dilithium_set_pub_key_int(tfm, key, keylen,
						   LC_DILITHIUM_44);
}

static int lc_kernel_dilithium_65_set_pub_key(struct crypto_akcipher *tfm,
					      const void *key,
					      unsigned int keylen)
{
	return lc_kernel_dilithium_set_pub_key_int(tfm, key, keylen,
						   LC_DILITHIUM_65);
}

static int lc_kernel_dilithium_87_set_pub_key(struct crypto_akcipher *tfm,
					      const void *key,
					      unsigned int keylen)
{
	return lc_kernel_dilithium_set_pub_key_int(tfm, key, keylen,
						   LC_DILITHIUM_87);
}

static int lc_kernel_dilithium_set_priv_key_int(struct crypto_akcipher *tfm,
						const void *key,
						unsigned int keylen,
						enum lc_dilithium_type type)
{
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	ctx->key_type = lc_kernel_dilithium_key_unset;

	ret = lc_dilithium_sk_load(&ctx->sk, key, keylen);

	if (!ret) {
		if (lc_dilithium_sk_type(&ctx->sk) != type)
			ret = -EOPNOTSUPP;
		else
			ctx->key_type = lc_kernel_dilithium_key_sk;
	}

	return ret;
}

static int lc_kernel_dilithium_44_set_priv_key(struct crypto_akcipher *tfm,
					       const void *key,
					       unsigned int keylen)
{
	return lc_kernel_dilithium_set_priv_key_int(tfm, key, keylen,
						    LC_DILITHIUM_44);
}

static int lc_kernel_dilithium_65_set_priv_key(struct crypto_akcipher *tfm,
					       const void *key,
					       unsigned int keylen)
{
	return lc_kernel_dilithium_set_priv_key_int(tfm, key, keylen,
						    LC_DILITHIUM_65);
}

static int lc_kernel_dilithium_87_set_priv_key(struct crypto_akcipher *tfm,
					       const void *key,
					       unsigned int keylen)
{
	return lc_kernel_dilithium_set_priv_key_int(tfm, key, keylen,
						    LC_DILITHIUM_87);
}

static unsigned int lc_kernel_dilithium_max_size(struct crypto_akcipher *tfm)
{
	struct lc_kernel_dilithium_ctx *ctx = akcipher_tfm_ctx(tfm);
	enum lc_dilithium_type type;

	switch (ctx->key_type) {
	case lc_kernel_dilithium_key_sk:
		type = lc_dilithium_sk_type(&ctx->sk);
		/* When SK is set -> generate a signature */
		return lc_dilithium_sig_size(type);
	case lc_kernel_dilithium_key_pk:
		type = lc_dilithium_pk_type(&ctx->pk);
		/* When PK is set, this is a safety valve, result is boolean */
		return lc_dilithium_sig_size(type);
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

static struct akcipher_alg lc_kernel_dilithium_87 = {
	.sign = lc_kernel_dilithium_sign,
	.verify = lc_kernel_dilithium_verify,
	.set_pub_key = lc_kernel_dilithium_87_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_87_set_priv_key,
	.max_size = lc_kernel_dilithium_max_size,
	.init = lc_kernel_dilithium_alg_init,
	.exit = lc_kernel_dilithium_alg_exit,
	.base.cra_name = "dilithium87",
	.base.cra_driver_name = "dilithium87-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct akcipher_alg lc_kernel_dilithium_65 = {
	.sign = lc_kernel_dilithium_sign,
	.verify = lc_kernel_dilithium_verify,
	.set_pub_key = lc_kernel_dilithium_65_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_65_set_priv_key,
	.max_size = lc_kernel_dilithium_max_size,
	.init = lc_kernel_dilithium_alg_init,
	.exit = lc_kernel_dilithium_alg_exit,
	.base.cra_name = "dilithium65",
	.base.cra_driver_name = "dilithium65-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct akcipher_alg lc_kernel_dilithium_44 = {
	.sign = lc_kernel_dilithium_sign,
	.verify = lc_kernel_dilithium_verify,
	.set_pub_key = lc_kernel_dilithium_44_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_44_set_priv_key,
	.max_size = lc_kernel_dilithium_max_size,
	.init = lc_kernel_dilithium_alg_init,
	.exit = lc_kernel_dilithium_alg_exit,
	.base.cra_name = "dilithium44",
	.base.cra_driver_name = "dilithium44-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

int __init lc_kernel_dilithium_44_init(void)
{
	return crypto_register_akcipher(&lc_kernel_dilithium_44);
}

void lc_kernel_dilithium_44_exit(void)
{
	crypto_unregister_akcipher(&lc_kernel_dilithium_44);
}

int __init lc_kernel_dilithium_65_init(void)
{
	return crypto_register_akcipher(&lc_kernel_dilithium_65);
}

void lc_kernel_dilithium_65_exit(void)
{
	crypto_unregister_akcipher(&lc_kernel_dilithium_65);
}

int __init lc_kernel_dilithium_init(void)
{
	return crypto_register_akcipher(&lc_kernel_dilithium_87);
}

void lc_kernel_dilithium_exit(void)
{
	crypto_unregister_akcipher(&lc_kernel_dilithium_87);
}
