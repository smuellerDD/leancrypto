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

#include "lc_sphincs.h"
#include "lc_sha3.h"

#include "leancrypto_kernel.h"

enum lc_kernel_sphincs_key_type {
	lc_kernel_sphincs_key_unset = 0,
	lc_kernel_sphincs_key_sk = 1,
	lc_kernel_sphincs_key_pk = 2,
};

struct lc_kernel_sphincs_ctx {
	union {
		struct lc_sphincs_sk sk;
		struct lc_sphincs_pk pk;
	};
	enum lc_kernel_sphincs_key_type key_type;
};

/* src -> message */
/* dst -> signature */
static int lc_kernel_sphincs_sign(struct crypto_sig *tfm, const void *src,
				  unsigned int slen, void *dst,
				  unsigned int dlen)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);
	struct lc_sphincs_sig *sig;
	enum lc_sphincs_type type;
	uint8_t *sig_ptr;
	size_t sig_len;
	int ret;

	if (unlikely(ctx->key_type != lc_kernel_sphincs_key_sk))
		return -EINVAL;

	type = lc_sphincs_sk_type(&ctx->sk);
	if (dlen != lc_sphincs_sig_size(type))
		return -EINVAL;

	sig = kmalloc(sizeof(struct lc_sphincs_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	ret = lc_sphincs_sign(sig, src, slen, &ctx->sk, lc_seeded_rng);
	if (ret)
		goto out;

	ret = lc_sphincs_sig_ptr(&sig_ptr, &sig_len, sig);
	if (ret)
		goto out;

	memcpy(dst, sig_ptr, sig_len);

out:
	free_zero(sig);
	return ret;
}

/* src -> signature */
/* msg -> message */
static int lc_kernel_sphincs_verify(struct crypto_sig *tfm, const void *src,
				    unsigned int slen, const void *msg,
				    unsigned int msg_len)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);
	struct lc_sphincs_sig *sig;
	size_t sig_len;
	enum lc_sphincs_type type;
	int ret;

	if (unlikely(ctx->key_type != lc_kernel_sphincs_key_pk))
		return -EINVAL;

	type = lc_sphincs_pk_type(&ctx->pk);
	sig_len = lc_sphincs_sig_size(type);
	if (slen < sig_len)
		return -EINVAL;

	sig = kmalloc(sizeof(struct lc_sphincs_sig), GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	ret = lc_sphincs_sig_load(sig, src, sig_len);
	if (ret)
		goto out;

	ret = lc_sphincs_verify(sig, msg, msg_len, &ctx->pk);

out:
	free_zero(sig);
	return ret;
}

static int lc_kernel_sphincs_set_pub_key_int(
	struct crypto_sig *tfm, const void *key, unsigned int keylen,
	enum lc_sphincs_type type, enum lc_sphincs_type type2, int fast)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	ctx->key_type = lc_kernel_sphincs_key_unset;

	ret = lc_sphincs_pk_load(&ctx->pk, key, keylen);

	if (!ret) {
		if ((lc_sphincs_pk_type(&ctx->pk) != type) &&
		    (lc_sphincs_pk_type(&ctx->pk) != type2)) {
			ret = -EOPNOTSUPP;
		} else {
			if (fast) {
				ret = lc_sphincs_pk_set_keytype_fast(&ctx->pk);
				if (ret)
					return ret;
			} else {
				ret = lc_sphincs_pk_set_keytype_small(&ctx->pk);
				if (ret)
					return ret;
			}
			ctx->key_type = lc_kernel_sphincs_key_pk;
		}
	}

	return ret;
}

static unsigned int lc_kernel_sphincs_256s_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_sphincs_key_sk:
		return sizeof(struct lc_sphincs_shake_256s_sk);

	case lc_kernel_sphincs_key_unset:
	case lc_kernel_sphincs_key_pk:
	default:
		return sizeof(struct lc_sphincs_shake_256s_pk);
	}
}

static unsigned int lc_kernel_sphincs_256f_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_sphincs_key_sk:
		return sizeof(struct lc_sphincs_shake_256f_sk);

	case lc_kernel_sphincs_key_unset:
	case lc_kernel_sphincs_key_pk:
	default:
		return sizeof(struct lc_sphincs_shake_256f_pk);
	}
}

static unsigned int lc_kernel_sphincs_192s_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_sphincs_key_sk:
		return sizeof(struct lc_sphincs_shake_192s_sk);

	case lc_kernel_sphincs_key_unset:
	case lc_kernel_sphincs_key_pk:
	default:
		return sizeof(struct lc_sphincs_shake_192s_pk);
	}
}

static unsigned int lc_kernel_sphincs_192f_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_sphincs_key_sk:
		return sizeof(struct lc_sphincs_shake_192f_sk);

	case lc_kernel_sphincs_key_unset:
	case lc_kernel_sphincs_key_pk:
	default:
		return sizeof(struct lc_sphincs_shake_192f_pk);
	}
}

static unsigned int lc_kernel_sphincs_128s_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_sphincs_key_sk:
		return sizeof(struct lc_sphincs_shake_128s_sk);

	case lc_kernel_sphincs_key_unset:
	case lc_kernel_sphincs_key_pk:
	default:
		return sizeof(struct lc_sphincs_shake_128s_pk);
	}
}

static unsigned int lc_kernel_sphincs_128f_key_size(struct crypto_sig *tfm)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);

	switch (ctx->key_type) {
	case lc_kernel_sphincs_key_sk:
		return sizeof(struct lc_sphincs_shake_128f_sk);

	case lc_kernel_sphincs_key_unset:
	case lc_kernel_sphincs_key_pk:
	default:
		return sizeof(struct lc_sphincs_shake_128f_pk);
	}
}

static int lc_kernel_sphincs_shake_128f_set_pub_key(struct crypto_sig *tfm,
						    const void *key,
						    unsigned int keylen)
{
	return lc_kernel_sphincs_set_pub_key_int(tfm, key, keylen,
						 LC_SPHINCS_SHAKE_128f,
						 LC_SPHINCS_SHAKE_128s, 1);
}

static int lc_kernel_sphincs_shake_128s_set_pub_key(struct crypto_sig *tfm,
						    const void *key,
						    unsigned int keylen)
{
	return lc_kernel_sphincs_set_pub_key_int(tfm, key, keylen,
						 LC_SPHINCS_SHAKE_128s,
						 LC_SPHINCS_SHAKE_128f, 0);
}

static int lc_kernel_sphincs_shake_192f_set_pub_key(struct crypto_sig *tfm,
						    const void *key,
						    unsigned int keylen)
{
	return lc_kernel_sphincs_set_pub_key_int(tfm, key, keylen,
						 LC_SPHINCS_SHAKE_192f,
						 LC_SPHINCS_SHAKE_192s, 1);
}

static int lc_kernel_sphincs_shake_192s_set_pub_key(struct crypto_sig *tfm,
						    const void *key,
						    unsigned int keylen)
{
	return lc_kernel_sphincs_set_pub_key_int(tfm, key, keylen,
						 LC_SPHINCS_SHAKE_192s,
						 LC_SPHINCS_SHAKE_192f, 0);
}

static int lc_kernel_sphincs_shake_256f_set_pub_key(struct crypto_sig *tfm,
						    const void *key,
						    unsigned int keylen)
{
	return lc_kernel_sphincs_set_pub_key_int(tfm, key, keylen,
						 LC_SPHINCS_SHAKE_256f,
						 LC_SPHINCS_SHAKE_256s, 1);
}

static int lc_kernel_sphincs_shake_256s_set_pub_key(struct crypto_sig *tfm,
						    const void *key,
						    unsigned int keylen)
{
	return lc_kernel_sphincs_set_pub_key_int(tfm, key, keylen,
						 LC_SPHINCS_SHAKE_256s,
						 LC_SPHINCS_SHAKE_256f, 0);
}

static int lc_kernel_sphincs_set_priv_key_int(
	struct crypto_sig *tfm, const void *key, unsigned int keylen,
	enum lc_sphincs_type type, enum lc_sphincs_type type2, int fast)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);
	int ret;

	ctx->key_type = lc_kernel_sphincs_key_unset;

	ret = lc_sphincs_sk_load(&ctx->sk, key, keylen);

	if (!ret) {
		if ((lc_sphincs_sk_type(&ctx->sk) != type) &&
		    (lc_sphincs_sk_type(&ctx->sk) != type2)) {
			ret = -EOPNOTSUPP;
		} else {
			if (fast) {
				ret = lc_sphincs_sk_set_keytype_fast(&ctx->sk);
				if (ret)
					return ret;
			} else {
				ret = lc_sphincs_sk_set_keytype_small(&ctx->sk);
				if (ret)
					return ret;
			}
			ctx->key_type = lc_kernel_sphincs_key_sk;
		}
	}

	return ret;
}

static int lc_kernel_sphincs_shake_128f_set_priv_key(struct crypto_sig *tfm,
						     const void *key,
						     unsigned int keylen)
{
	return lc_kernel_sphincs_set_priv_key_int(tfm, key, keylen,
						  LC_SPHINCS_SHAKE_128f,
						  LC_SPHINCS_SHAKE_128s, 1);
}

static int lc_kernel_sphincs_shake_128s_set_priv_key(struct crypto_sig *tfm,
						     const void *key,
						     unsigned int keylen)
{
	return lc_kernel_sphincs_set_priv_key_int(tfm, key, keylen,
						  LC_SPHINCS_SHAKE_128s,
						  LC_SPHINCS_SHAKE_128f, 0);
}

static int lc_kernel_sphincs_shake_192f_set_priv_key(struct crypto_sig *tfm,
						     const void *key,
						     unsigned int keylen)
{
	return lc_kernel_sphincs_set_priv_key_int(tfm, key, keylen,
						  LC_SPHINCS_SHAKE_192f,
						  LC_SPHINCS_SHAKE_192s, 1);
}

static int lc_kernel_sphincs_shake_192s_set_priv_key(struct crypto_sig *tfm,
						     const void *key,
						     unsigned int keylen)
{
	return lc_kernel_sphincs_set_priv_key_int(tfm, key, keylen,
						  LC_SPHINCS_SHAKE_192s,
						  LC_SPHINCS_SHAKE_192f, 0);
}

static int lc_kernel_sphincs_shake_256f_set_priv_key(struct crypto_sig *tfm,
						     const void *key,
						     unsigned int keylen)
{
	return lc_kernel_sphincs_set_priv_key_int(tfm, key, keylen,
						  LC_SPHINCS_SHAKE_256f,
						  LC_SPHINCS_SHAKE_256s, 1);
}

static int lc_kernel_sphincs_shake_256s_set_priv_key(struct crypto_sig *tfm,
						     const void *key,
						     unsigned int keylen)
{
	return lc_kernel_sphincs_set_priv_key_int(tfm, key, keylen,
						  LC_SPHINCS_SHAKE_256s,
						  LC_SPHINCS_SHAKE_256s, 0);
}

static unsigned int lc_kernel_sphincs_max_size(struct crypto_sig *tfm)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);
	enum lc_sphincs_type type;

	switch (ctx->key_type) {
	case lc_kernel_sphincs_key_sk:
		type = lc_sphincs_sk_type(&ctx->sk);
		/* When SK is set -> generate a signature */
		return lc_sphincs_sig_size(type);
	case lc_kernel_sphincs_key_pk:
		type = lc_sphincs_pk_type(&ctx->pk);
		/* When PK is set, this is a safety valve */
		return lc_sphincs_sig_size(type);
	default:
		return 0;
	}
}

static int lc_kernel_sphincs_alg_init(struct crypto_sig *tfm)
{
	return 0;
}

static void lc_kernel_sphincs_alg_exit(struct crypto_sig *tfm)
{
	struct lc_kernel_sphincs_ctx *ctx = crypto_sig_ctx(tfm);

	ctx->key_type = lc_kernel_sphincs_key_unset;
}

/*
 * NOTE: All algorithm definitions refer to HashSLH-DSA and thus contain
 * the hash used for processing the provided data. Due to the use of SGL
 * the kernel crypto API interface for SLH-DSA does not offer "plain"
 * SLH-DSA.
 */
static struct sig_alg lc_kernel_sphincs_shake_256s = {
	.sign = lc_kernel_sphincs_sign,
	.verify = lc_kernel_sphincs_verify,
	.set_pub_key = lc_kernel_sphincs_shake_256s_set_pub_key,
	.set_priv_key = lc_kernel_sphincs_shake_256s_set_priv_key,
	.key_size = lc_kernel_sphincs_256s_key_size,
	.max_size = lc_kernel_sphincs_max_size,
	.init = lc_kernel_sphincs_alg_init,
	.exit = lc_kernel_sphincs_alg_exit,
	.base.cra_name = "sphincs-shake-256s(sha3-512)",
	.base.cra_driver_name = "sphincs-shake-256s-sha3-512-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_sphincs_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct sig_alg lc_kernel_sphincs_shake_256f = {
	.sign = lc_kernel_sphincs_sign,
	.verify = lc_kernel_sphincs_verify,
	.set_pub_key = lc_kernel_sphincs_shake_256f_set_pub_key,
	.set_priv_key = lc_kernel_sphincs_shake_256f_set_priv_key,
	.key_size = lc_kernel_sphincs_256f_key_size,
	.max_size = lc_kernel_sphincs_max_size,
	.init = lc_kernel_sphincs_alg_init,
	.exit = lc_kernel_sphincs_alg_exit,
	.base.cra_name = "sphincs-shake-256f(sha3-512)",
	.base.cra_driver_name = "sphincs-shake-256f-sha3-512-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_sphincs_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct sig_alg lc_kernel_sphincs_shake_192s = {
	.sign = lc_kernel_sphincs_sign,
	.verify = lc_kernel_sphincs_verify,
	.set_pub_key = lc_kernel_sphincs_shake_192s_set_pub_key,
	.set_priv_key = lc_kernel_sphincs_shake_192s_set_priv_key,
	.key_size = lc_kernel_sphincs_192s_key_size,
	.max_size = lc_kernel_sphincs_max_size,
	.init = lc_kernel_sphincs_alg_init,
	.exit = lc_kernel_sphincs_alg_exit,
	.base.cra_name = "sphincs-shake-192s(sha3-384)",
	.base.cra_driver_name = "sphincs-shake-192s-sha3-384-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_sphincs_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct sig_alg lc_kernel_sphincs_shake_192f = {
	.sign = lc_kernel_sphincs_sign,
	.verify = lc_kernel_sphincs_verify,
	.set_pub_key = lc_kernel_sphincs_shake_192f_set_pub_key,
	.set_priv_key = lc_kernel_sphincs_shake_192f_set_priv_key,
	.key_size = lc_kernel_sphincs_192f_key_size,
	.max_size = lc_kernel_sphincs_max_size,
	.init = lc_kernel_sphincs_alg_init,
	.exit = lc_kernel_sphincs_alg_exit,
	.base.cra_name = "sphincs-shake-192f(sha3-384)",
	.base.cra_driver_name = "sphincs-shake-192f-sha3-384-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_sphincs_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct sig_alg lc_kernel_sphincs_shake_128s = {
	.sign = lc_kernel_sphincs_sign,
	.verify = lc_kernel_sphincs_verify,
	.set_pub_key = lc_kernel_sphincs_shake_128s_set_pub_key,
	.set_priv_key = lc_kernel_sphincs_shake_128s_set_priv_key,
	.key_size = lc_kernel_sphincs_128s_key_size,
	.max_size = lc_kernel_sphincs_max_size,
	.init = lc_kernel_sphincs_alg_init,
	.exit = lc_kernel_sphincs_alg_exit,
	.base.cra_name = "sphincs-shake-128s(sha3-256)",
	.base.cra_driver_name = "sphincs-shake-128s-sha3-256-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_sphincs_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

static struct sig_alg lc_kernel_sphincs_shake_128f = {
	.sign = lc_kernel_sphincs_sign,
	.verify = lc_kernel_sphincs_verify,
	.set_pub_key = lc_kernel_sphincs_shake_128f_set_pub_key,
	.set_priv_key = lc_kernel_sphincs_shake_128f_set_priv_key,
	.key_size = lc_kernel_sphincs_128f_key_size,
	.max_size = lc_kernel_sphincs_max_size,
	.init = lc_kernel_sphincs_alg_init,
	.exit = lc_kernel_sphincs_alg_exit,
	.base.cra_name = "sphincs-shake-128f(sha3-256)",
	.base.cra_driver_name = "sphincs-shake-128f-sha3-256-leancrypto",
	.base.cra_ctxsize = sizeof(struct lc_kernel_sphincs_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

int __init lc_kernel_sphincs_shake_128f_init(void)
{
	return crypto_register_sig(&lc_kernel_sphincs_shake_128f);
}

void lc_kernel_sphincs_shake_128f_exit(void)
{
	crypto_unregister_sig(&lc_kernel_sphincs_shake_128f);
}

int __init lc_kernel_sphincs_shake_128s_init(void)
{
	return crypto_register_sig(&lc_kernel_sphincs_shake_128s);
}

void lc_kernel_sphincs_shake_128s_exit(void)
{
	crypto_unregister_sig(&lc_kernel_sphincs_shake_128s);
}

int __init lc_kernel_sphincs_shake_192f_init(void)
{
	return crypto_register_sig(&lc_kernel_sphincs_shake_192f);
}

void lc_kernel_sphincs_shake_192f_exit(void)
{
	crypto_unregister_sig(&lc_kernel_sphincs_shake_192f);
}

int __init lc_kernel_sphincs_shake_192s_init(void)
{
	return crypto_register_sig(&lc_kernel_sphincs_shake_192s);
}

void lc_kernel_sphincs_shake_192s_exit(void)
{
	crypto_unregister_sig(&lc_kernel_sphincs_shake_192s);
}

int __init lc_kernel_sphincs_shake_256f_init(void)
{
	return crypto_register_sig(&lc_kernel_sphincs_shake_256f);
}

void lc_kernel_sphincs_shake_256f_exit(void)
{
	crypto_unregister_sig(&lc_kernel_sphincs_shake_256f);
}

int __init lc_kernel_sphincs_init(void)
{
	return crypto_register_sig(&lc_kernel_sphincs_shake_256s);
}

void lc_kernel_sphincs_exit(void)
{
	crypto_unregister_sig(&lc_kernel_sphincs_shake_256s);
}
