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

#include <crypto/aes.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>
#include <crypto/xts.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "lc_aes.h"

#include "leancrypto_kernel.h"

static int lc_aes_xts_setkey(struct crypto_skcipher *tfm, const u8 *key,
			     unsigned int keylen)
{
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);
	int err;

	err = xts_verify_key(tfm, key, keylen);
	if (err)
		return err;

	err = lc_sym_init(ctx);
	if (err)
		return err;

	err = lc_sym_setkey(ctx, key, keylen);

	/* The Linux kernel enhanced tester wants this */
	if (err == -EINVAL)
		err = -ENOENT;
	return err;
}

/* This handles cases where the source and/or destination span pages. */
static noinline int lc_aes_xts_slowpath(
	struct skcipher_request *req,
	int (*crypt_func)(const struct lc_sym_ctx *ctx, const uint8_t *in,
			  uint8_t *out, size_t len, uint8_t *iv, size_t ivlen))
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);
	unsigned int tail = req->cryptlen % AES_BLOCK_SIZE;
	struct scatterlist sg_src[2], sg_dst[2];
	struct skcipher_request subreq;
	struct skcipher_walk walk;
	struct scatterlist *src, *dst;
	int err;

	if (req->cryptlen < AES_BLOCK_SIZE)
		return -EINVAL;

	/*
	 * If the message length isn't divisible by the AES block size, then
	 * separate off the last full block and the partial block.  This ensures
	 * that they are processed in the same call to the assembly function,
	 * which is required for ciphertext stealing.
	 */
	if (tail) {
		unsigned int xts_blocks =
			DIV_ROUND_UP(req->cryptlen, AES_BLOCK_SIZE) - 2;
		skcipher_request_set_tfm(&subreq, tfm);
		skcipher_request_set_callback(
			&subreq, skcipher_request_flags(req), NULL, NULL);

		skcipher_request_set_crypt(&subreq, req->src, req->dst,
					   xts_blocks * AES_BLOCK_SIZE,
					   req->iv);

		req = &subreq;
	}

	err = skcipher_walk_virt(&walk, req, false);

	while (walk.nbytes) {
		unsigned int nbytes = walk.nbytes & ~(AES_BLOCK_SIZE - 1);

		err = crypt_func(ctx, walk.src.virt.addr, walk.dst.virt.addr,
				 nbytes, walk.iv, AES_BLOCK_SIZE);
		if (err)
			goto out;
		err = skcipher_walk_done(&walk,
					 walk.nbytes & (AES_BLOCK_SIZE - 1));
	}

	if (err || !tail)
		return err;

	/* Do ciphertext stealing with the last full block and partial block. */

	dst = src = scatterwalk_ffwd(sg_src, req->src, req->cryptlen);
	if (req->dst != req->src)
		dst = scatterwalk_ffwd(sg_dst, req->dst, req->cryptlen);

	skcipher_request_set_crypt(req, src, dst, AES_BLOCK_SIZE + tail,
				   req->iv);

	err = skcipher_walk_virt(&walk, req, false);
	if (err)
		goto out;

	err = crypt_func(ctx, walk.src.virt.addr, walk.dst.virt.addr,
			 walk.nbytes, walk.iv, AES_BLOCK_SIZE);

out:
	if (err)
		skcipher_walk_done(&walk, 0);
	else
		err = skcipher_walk_done(&walk, 0);
	return err;
}

static int lc_aes_xts_common(struct skcipher_request *req,
			     int (*crypt_func)(const struct lc_sym_ctx *ctx,
					       const uint8_t *in, uint8_t *out,
					       size_t len, uint8_t *iv,
					       size_t ivlen))
{
	struct crypto_skcipher *tfm = crypto_skcipher_reqtfm(req);
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);
	int err;

	if (unlikely(req->cryptlen < AES_BLOCK_SIZE))
		return -EINVAL;

	err = lc_sym_init_iv(ctx, req->iv, AES_BLOCK_SIZE);
	if (err)
		return err;

	/*
	 * In practice, virtually all XTS plaintexts and ciphertexts are either
	 * 512 or 4096 bytes and do not use multiple scatterlist elements.  To
	 * optimize the performance of these cases, the below fast-path handles
	 * single-scatterlist-element messages as efficiently as possible.  The
	 * code is 64-bit specific, as it assumes no page mapping is needed.
	 */
	if (likely(req->src->length >= req->cryptlen &&
		   req->dst->length >= req->cryptlen)) {
		return crypt_func(ctx, sg_virt(req->src), sg_virt(req->dst),
				  req->cryptlen, req->iv, AES_BLOCK_SIZE);
	}

	return lc_aes_xts_slowpath(req, crypt_func);
}

static int lc_aes_xts_encrypt(struct skcipher_request *req)
{
	return lc_aes_xts_common(req, lc_sym_encrypt_iv);
}

static int lc_aes_xts_decrypt(struct skcipher_request *req)
{
	return lc_aes_xts_common(req, lc_sym_decrypt_iv);
}

static int lc_aes_xts_init(struct crypto_skcipher *tfm)
{
	struct lc_sym_ctx *ctx = crypto_skcipher_ctx(tfm);

	LC_SYM_SET_CTX(ctx, lc_aes_xts);

	return 0;
}

/********************************* Interface  *********************************/

static struct skcipher_alg lc_aes_xts_skciphers[] = {
	{
		.base = {
			.cra_name = "xts(aes)",
			.cra_driver_name = "xts-aes-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_alignmask = LC_SYM_ALIGNMASK(lc_aes_xts),
			.cra_ctxsize = LC_SYM_CTX_SIZE_LEN(
					LC_AES_RISCV64_XTS_MAX_BLOCK_SIZE),
			.cra_module = THIS_MODULE,
		},
		.min_keysize = 2 * AES_MIN_KEY_SIZE,
		.max_keysize = 2 * AES_MAX_KEY_SIZE,
		.ivsize	 = AES_BLOCK_SIZE,
		.chunksize = 2 * AES_BLOCK_SIZE,
		.setkey = lc_aes_xts_setkey,
		.encrypt = lc_aes_xts_encrypt,
		.decrypt = lc_aes_xts_decrypt,
		.init = lc_aes_xts_init
	}
};

int __init lc_kernel_aes_xts_init(void)
{
	return crypto_register_skciphers(lc_aes_xts_skciphers,
					 ARRAY_SIZE(lc_aes_xts_skciphers));
}

void lc_kernel_aes_xts_exit(void)
{
	crypto_unregister_skciphers(lc_aes_xts_skciphers,
				    ARRAY_SIZE(lc_aes_xts_skciphers));
}
