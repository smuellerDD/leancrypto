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

enum lc_kernel_dilithium_ed25519_key_type {
	lc_kernel_dilithium_ed25519_key_unset = 0,
	lc_kernel_dilithium_ed25519_key_sk = 1,
	lc_kernel_dilithium_ed25519_key_pk = 2,
};

struct lc_kernel_dilithium_ed25519_ctx {
	union {
		struct lc_dilithium_ed25519_sk sk;
		struct lc_dilithium_ed25519_pk pk;
	};
	enum lc_kernel_dilithium_ed25519_key_type key_type;
};

static int lc_kernel_dilithium_ed25519_sign(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct lc_kernel_dilithium_ed25519_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct lc_dilithium_ed25519_sig *sig;
	struct sg_mapping_iter miter;
	unsigned int sg_flags = SG_MITER_ATOMIC | SG_MITER_FROM_SG;
	enum lc_dilithium_type type;
	int ret;

	/* req->src -> message */
	/* req->dst -> signature */

	if (unlikely(ctx->key_type != lc_kernel_dilithium_ed25519_key_sk))
		return -EINVAL;

	type = lc_dilithium_ed25519_sk_type(&ctx->sk);
	if (req->dst_len != lc_dilithium_ed25519_sig_size(type) ||
	    /* We have no init-update-final and we want to avoid a memcpy */
	    sg_nents_for_len(req->src, req->src_len) > 1)
		return -EINVAL;

	sig = kmalloc(lc_dilithium_ed25519_sig_size(type),
		      GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	sg_miter_start(&miter, req->dst,
		       sg_nents_for_len(req->dst, req->dst_len), sg_flags);

	sg_miter_next(&miter);

	/*
	 * Note, this only works because struct lc_dilithium_ed25519_sig
	 * is a linear buffer where the Dilithium and ED25519 signatures
	 * are concatenated in memory.
	 */
	ret = lc_dilithium_ed25519_sign(sig, miter.addr, miter.length, &ctx->sk,
					lc_seeded_rng);
	if (!ret) {
		uint8_t *dilithium_sig_ptr, *ed25519_sig_ptr;
		size_t dilithium_sig_len, ed25519_sig_len;

		ret = lc_dilithium_ed25519_sig_ptr(&dilithium_sig_ptr,
						   &dilithium_sig_len,
						   &ed25519_sig_ptr,
						   &ed25519_sig_len, sig);
		if (ret)
			goto out;

#if 0
		uint8_t *sig;
		sig_len = dilithium_sig_len + ed25519_sig_len;
		sig = kmalloc(sig_len, GFP_KERNEL);
		if (!sig) {
			ret = -ENOMEM;
			goto out;
		}
		memcpy(sig, dilithium_sig_ptr, dilithium_sig_len);
		memcpy(sig, ed25519_sig_ptr, ed25519_sig_len);
#else
		/* Check that we have one linear buffer of both signatures */
		BUG_ON(dilithium_sig_ptr !=
		       ed25519_sig_ptr - dilithium_sig_len);
#endif

		sg_pcopy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     dilithium_sig_ptr,
				     dilithium_sig_len + ed25519_sig_len, 0);
	}

out:
	kfree_sensitive(sig);
	return ret;
}

static int lc_kernel_dilithium_ed25519_verify(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct lc_kernel_dilithium_ed25519_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct lc_dilithium_ed25519_sig *sig;
	struct sg_mapping_iter miter;
	unsigned int sg_flags = SG_MITER_ATOMIC | SG_MITER_FROM_SG;
	enum lc_dilithium_type type;
	int ret;

	/* req->src -> signature */
	/* req->dst -> message */

	if (unlikely(ctx->key_type != lc_kernel_dilithium_ed25519_key_pk))
		return -EINVAL;

	type = lc_dilithium_ed25519_pk_type(&ctx->pk);
	if (req->src_len != lc_dilithium_ed25519_sig_size(type) ||
	    /* We have no init-update-final and we want to avoid a memcpy */
	    sg_nents_for_len(req->dst, req->dst_len) > 1)
		return -EINVAL;

	sig = kmalloc(lc_dilithium_ed25519_sig_size(type), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	sg_pcopy_to_buffer(req->src, sg_nents_for_len(req->src, req->src_len),
			   sig, req->src_len, 0);

	/*
	 * This copy directly into the signature buffer only works because
	 * both signatures are adjacent. If they would not be, use
	 * lc_dilithium_ed25519_sig_ptr as implemented in
	 * lc_kernel_dilithium_verify.
	 */
	sig->dilithium_type = type;
	sg_miter_start(&miter, req->dst,
		       sg_nents_for_len(req->dst, req->dst_len), sg_flags);

	sg_miter_next(&miter);

	/*
	 * Note, this only works because struct lc_dilithium_ed25519_sig
	 * is a linear buffer where the Dilithium and ED25519 signatures
	 * are concatenated in memory.
	 */
	ret = lc_dilithium_ed25519_verify(sig, miter.addr, miter.length,
					  &ctx->pk);

	kfree_sensitive(sig);
	return ret;
}

static int lc_kernel_dilithium_ed25519_set_pub_key_int(
	struct crypto_akcipher *tfm, const void *key, unsigned int keylen,
	enum lc_dilithium_type type)
{
	struct lc_kernel_dilithium_ed25519_ctx *ctx = akcipher_tfm_ctx(tfm);
	size_t dilithium_key_size = lc_dilithium_pk_size(type);
	int ret;

	ctx->key_type = lc_kernel_dilithium_ed25519_key_unset;

	/* Ensure the subtraction below works */
	if (keylen != lc_dilithium_ed25519_pk_size(type))
		return -EINVAL;

	/*
	 * This operation requires that the Dilithium key is concatenated with
	 * the ED25519 key.
	 */
	ret = lc_dilithium_ed25519_pk_load(
		&ctx->pk, key, dilithium_key_size,
		((uint8_t *)key) + dilithium_key_size,
		LC_ED25519_PUBLICKEYBYTES);

	if (!ret) {
		if (lc_dilithium_ed25519_pk_type(&ctx->pk) != type)
			ret = -EOPNOTSUPP;
		else
			ctx->key_type = lc_kernel_dilithium_ed25519_key_pk;
	}

	return 0;
}

static int lc_kernel_dilithium_87_ed25519_set_pub_key(
	struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	return lc_kernel_dilithium_ed25519_set_pub_key_int(tfm, key, keylen,
							   LC_DILITHIUM_87);
}

static int lc_kernel_dilithium_65_ed25519_set_pub_key(
	struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	return lc_kernel_dilithium_ed25519_set_pub_key_int(tfm, key, keylen,
							   LC_DILITHIUM_65);
}

static int lc_kernel_dilithium_44_ed25519_set_pub_key(
	struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	return lc_kernel_dilithium_ed25519_set_pub_key_int(tfm, key, keylen,
							   LC_DILITHIUM_44);
}

static int lc_kernel_dilithium_ed25519_set_priv_key_int(
	struct crypto_akcipher *tfm, const void *key, unsigned int keylen,
	enum lc_dilithium_type type)
{
	struct lc_kernel_dilithium_ed25519_ctx *ctx = akcipher_tfm_ctx(tfm);
	size_t dilithium_key_size = lc_dilithium_sk_size(type);
	const uint8_t *key_int = key;
	int ret;

	ctx->key_type = lc_kernel_dilithium_ed25519_key_unset;

	/* Ensure the subtraction below works */
	if (keylen != lc_dilithium_ed25519_sk_size(type))
		return -EINVAL;

	/*
	 * This operation requires that the Dilithium key is concatenated with
	 * the ED25519 key.
	 */
	ret = lc_dilithium_ed25519_sk_load(
		&ctx->sk, key_int, dilithium_key_size,
		key_int + dilithium_key_size,
		LC_ED25519_SECRETKEYBYTES);

	if (!ret) {
		if (lc_dilithium_ed25519_sk_type(&ctx->sk) != type)
			ret = -EOPNOTSUPP;
		else
			ctx->key_type = lc_kernel_dilithium_ed25519_key_sk;
	}

	return 0;
}

static int lc_kernel_dilithium_87_ed25519_set_priv_key(
	struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	return lc_kernel_dilithium_ed25519_set_priv_key_int(tfm, key, keylen,
							    LC_DILITHIUM_87);
}

static int lc_kernel_dilithium_65_ed25519_set_priv_key(
	struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	return lc_kernel_dilithium_ed25519_set_priv_key_int(tfm, key, keylen,
							    LC_DILITHIUM_65);
}

static int lc_kernel_dilithium_44_ed25519_set_priv_key(
	struct crypto_akcipher *tfm, const void *key, unsigned int keylen)
{
	return lc_kernel_dilithium_ed25519_set_priv_key_int(tfm, key, keylen,
							    LC_DILITHIUM_44);
}

static unsigned int
lc_kernel_dilithium_ed25519_max_size(struct crypto_akcipher *tfm)
{
	struct lc_kernel_dilithium_ed25519_ctx *ctx = akcipher_tfm_ctx(tfm);
	enum lc_dilithium_type type;

	switch (ctx->key_type) {
	case lc_kernel_dilithium_ed25519_key_sk:
		type = lc_dilithium_ed25519_sk_type(&ctx->sk);
		return lc_dilithium_ed25519_sig_size(type);
	case lc_kernel_dilithium_ed25519_key_pk:
		type = lc_dilithium_ed25519_pk_type(&ctx->pk);
		return lc_dilithium_ed25519_sig_size(type);
	default:
		return 0;
	}
}

static int lc_kernel_dilithium_ed25519_alg_init(struct crypto_akcipher *tfm)
{
	return 0;
}

static void lc_kernel_dilithium_ed25519_alg_exit(struct crypto_akcipher *tfm)
{
	struct lc_kernel_dilithium_ed25519_ctx *ctx = akcipher_tfm_ctx(tfm);

	ctx->key_type = lc_kernel_dilithium_ed25519_key_unset;
}

static struct akcipher_alg lc_kernel_dilithium_ed25519_87 = {
	.sign = lc_kernel_dilithium_ed25519_sign,
	.verify = lc_kernel_dilithium_ed25519_verify,
	.set_pub_key = lc_kernel_dilithium_87_ed25519_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_87_ed25519_set_priv_key,
	.max_size = lc_kernel_dilithium_ed25519_max_size,
	.init = lc_kernel_dilithium_ed25519_alg_init,
	.exit = lc_kernel_dilithium_ed25519_alg_exit,
	.base.cra_name = "dilithium-ed25519-87",
	.base.cra_driver_name = "dilithium-ed25519-87-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ed25519_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct akcipher_alg lc_kernel_dilithium_ed25519_65 = {
	.sign = lc_kernel_dilithium_ed25519_sign,
	.verify = lc_kernel_dilithium_ed25519_verify,
	.set_pub_key = lc_kernel_dilithium_65_ed25519_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_65_ed25519_set_priv_key,
	.max_size = lc_kernel_dilithium_ed25519_max_size,
	.init = lc_kernel_dilithium_ed25519_alg_init,
	.exit = lc_kernel_dilithium_ed25519_alg_exit,
	.base.cra_name = "dilithium-ed25519-65",
	.base.cra_driver_name = "dilithium-ed25519-65-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ed25519_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct akcipher_alg lc_kernel_dilithium_ed25519_44 = {
	.sign = lc_kernel_dilithium_ed25519_sign,
	.verify = lc_kernel_dilithium_ed25519_verify,
	.set_pub_key = lc_kernel_dilithium_44_ed25519_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_44_ed25519_set_priv_key,
	.max_size = lc_kernel_dilithium_ed25519_max_size,
	.init = lc_kernel_dilithium_ed25519_alg_init,
	.exit = lc_kernel_dilithium_ed25519_alg_exit,
	.base.cra_name = "dilithium-ed25519-44",
	.base.cra_driver_name = "dilithium-ed25519-44-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ed25519_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

int __init lc_kernel_dilithium_44_ed25519_init(void)
{
	return crypto_register_akcipher(&lc_kernel_dilithium_ed25519_44);
}

void lc_kernel_dilithium_44_ed25519_exit(void)
{
	crypto_unregister_akcipher(&lc_kernel_dilithium_ed25519_44);
}

int __init lc_kernel_dilithium_65_ed25519_init(void)
{
	return crypto_register_akcipher(&lc_kernel_dilithium_ed25519_65);
}

void lc_kernel_dilithium_65_ed25519_exit(void)
{
	crypto_unregister_akcipher(&lc_kernel_dilithium_ed25519_65);
}

int __init lc_kernel_dilithium_ed25519_init(void)
{
	return crypto_register_akcipher(&lc_kernel_dilithium_ed25519_87);
}

void lc_kernel_dilithium_ed25519_exit(void)
{
	crypto_unregister_akcipher(&lc_kernel_dilithium_ed25519_87);
}
