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

#include <crypto/internal/sig.h>
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

/* src -> message */
/* dst -> signature */
static int lc_kernel_dilithium_sign(struct crypto_sig *tfm,
				    const void *src, unsigned int slen,
				    void *dst, unsigned int dlen)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);
	struct lc_dilithium_sig *sig;
	enum lc_dilithium_type type;
	uint8_t *sig_ptr;
	size_t sig_len;
	int ret;

	if (unlikely(ctx->key_type != lc_kernel_dilithium_key_sk))
		return -EINVAL;

	type = lc_dilithium_sk_type(&ctx->sk);
	if (dlen != lc_dilithium_sig_size(type))
		return -EINVAL;

	sig = kmalloc(sizeof(struct lc_dilithium_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	ret = lc_dilithium_sign(sig, src, slen, &ctx->sk, lc_seeded_rng);
	if (ret)
		goto out;

	ret = lc_dilithium_sig_ptr(&sig_ptr, &sig_len, sig);
	if (ret)
		goto out;

	memcpy(dst, sig_ptr, sig_len);

out:
	free_zero(sig);
	return ret;
}

/* src -> signature */
/* msg -> message */
static int lc_kernel_dilithium_verify(struct crypto_sig *tfm,
				      const void *src, unsigned int slen,
				      const void *msg, unsigned int msg_len)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);
	struct lc_dilithium_sig *sig;
	size_t sig_len;
	enum lc_dilithium_type type;
	int ret;

	if (unlikely(ctx->key_type != lc_kernel_dilithium_key_pk))
		return -EINVAL;

	type = lc_dilithium_pk_type(&ctx->pk);
	sig_len = lc_dilithium_sig_size(type);
	if (slen < sig_len)
		return -EINVAL;

	sig = kmalloc(sizeof(struct lc_dilithium_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	ret = lc_dilithium_sig_load(sig, src, sig_len);
	if (ret)
		goto out;

	ret = lc_dilithium_verify(sig, msg, msg_len, &ctx->pk);

out:
	free_zero(sig);
	return ret;
}

static unsigned int lc_kernel_dilithium_87_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_dilithium_key_sk:
		return sizeof(struct lc_dilithium_87_sk);

	case lc_kernel_dilithium_key_unset:
	case lc_kernel_dilithium_key_pk:
	default:
		return sizeof(struct lc_dilithium_87_pk);
	}
}

static unsigned int lc_kernel_dilithium_65_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_dilithium_key_sk:
		return sizeof(struct lc_dilithium_65_sk);

	case lc_kernel_dilithium_key_unset:
	case lc_kernel_dilithium_key_pk:
	default:
		return sizeof(struct lc_dilithium_65_pk);
	}
}

static unsigned int lc_kernel_dilithium_44_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_dilithium_key_sk:
		return sizeof(struct lc_dilithium_44_sk);

	case lc_kernel_dilithium_key_unset:
	case lc_kernel_dilithium_key_pk:
	default:
		return sizeof(struct lc_dilithium_44_pk);
	}
}

static int lc_kernel_dilithium_set_pub_key_int(struct crypto_sig *tfm,
					       const void *key,
					       unsigned int keylen,
					       enum lc_dilithium_type type)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);
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

static int lc_kernel_dilithium_44_set_pub_key(struct crypto_sig *tfm,
					      const void *key,
					      unsigned int keylen)
{
	return lc_kernel_dilithium_set_pub_key_int(tfm, key, keylen,
						   LC_DILITHIUM_44);
}

static int lc_kernel_dilithium_65_set_pub_key(struct crypto_sig *tfm,
					      const void *key,
					      unsigned int keylen)
{
	return lc_kernel_dilithium_set_pub_key_int(tfm, key, keylen,
						   LC_DILITHIUM_65);
}

static int lc_kernel_dilithium_87_set_pub_key(struct crypto_sig *tfm,
					      const void *key,
					      unsigned int keylen)
{
	return lc_kernel_dilithium_set_pub_key_int(tfm, key, keylen,
						   LC_DILITHIUM_87);
}

static int lc_kernel_dilithium_set_priv_key_int(struct crypto_sig *tfm,
						const void *key,
						unsigned int keylen,
						enum lc_dilithium_type type)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);
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

static int lc_kernel_dilithium_44_set_priv_key(struct crypto_sig *tfm,
					       const void *key,
					       unsigned int keylen)
{
	return lc_kernel_dilithium_set_priv_key_int(tfm, key, keylen,
						    LC_DILITHIUM_44);
}

static int lc_kernel_dilithium_65_set_priv_key(struct crypto_sig *tfm,
					       const void *key,
					       unsigned int keylen)
{
	return lc_kernel_dilithium_set_priv_key_int(tfm, key, keylen,
						    LC_DILITHIUM_65);
}

static int lc_kernel_dilithium_87_set_priv_key(struct crypto_sig *tfm,
					       const void *key,
					       unsigned int keylen)
{
	return lc_kernel_dilithium_set_priv_key_int(tfm, key, keylen,
						    LC_DILITHIUM_87);
}

static unsigned int lc_kernel_dilithium_max_size(struct crypto_sig *tfm)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);
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

static int lc_kernel_dilithium_alg_init(struct crypto_sig *tfm)
{
	return 0;
}

static void lc_kernel_dilithium_alg_exit(struct crypto_sig *tfm)
{
	struct lc_kernel_dilithium_ctx *ctx = crypto_sig_ctx(tfm);

	ctx->key_type = lc_kernel_dilithium_key_unset;
}

static struct sig_alg lc_kernel_dilithium_87 = {
	.sign = lc_kernel_dilithium_sign,
	.verify = lc_kernel_dilithium_verify,
	.set_pub_key = lc_kernel_dilithium_87_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_87_set_priv_key,
	.key_size = lc_kernel_dilithium_87_key_size,
	.max_size = lc_kernel_dilithium_max_size,
	.init = lc_kernel_dilithium_alg_init,
	.exit = lc_kernel_dilithium_alg_exit,
	.base.cra_name = "dilithium87",
	.base.cra_driver_name = "dilithium87-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct sig_alg lc_kernel_dilithium_65 = {
	.sign = lc_kernel_dilithium_sign,
	.verify = lc_kernel_dilithium_verify,
	.set_pub_key = lc_kernel_dilithium_65_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_65_set_priv_key,
	.key_size = lc_kernel_dilithium_65_key_size,
	.max_size = lc_kernel_dilithium_max_size,
	.init = lc_kernel_dilithium_alg_init,
	.exit = lc_kernel_dilithium_alg_exit,
	.base.cra_name = "dilithium65",
	.base.cra_driver_name = "dilithium65-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_dilithium_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct sig_alg lc_kernel_dilithium_44 = {
	.sign = lc_kernel_dilithium_sign,
	.verify = lc_kernel_dilithium_verify,
	.set_pub_key = lc_kernel_dilithium_44_set_pub_key,
	.set_priv_key = lc_kernel_dilithium_44_set_priv_key,
	.key_size = lc_kernel_dilithium_44_key_size,
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
	return crypto_register_sig(&lc_kernel_dilithium_44);
}

void lc_kernel_dilithium_44_exit(void)
{
	crypto_unregister_sig(&lc_kernel_dilithium_44);
}

int __init lc_kernel_dilithium_65_init(void)
{
	return crypto_register_sig(&lc_kernel_dilithium_65);
}

void lc_kernel_dilithium_65_exit(void)
{
	crypto_unregister_sig(&lc_kernel_dilithium_65);
}

int __init lc_kernel_dilithium_init(void)
{
	return crypto_register_sig(&lc_kernel_dilithium_87);
}

void lc_kernel_dilithium_exit(void)
{
	crypto_unregister_sig(&lc_kernel_dilithium_87);
}
