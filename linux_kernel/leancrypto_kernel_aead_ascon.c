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

#include <crypto/internal/aead.h>
#include <crypto/scatterwalk.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>

#include "lc_ascon_keccak.h"
#include "lc_ascon_lightweight.h"

#include "leancrypto_kernel.h"

/* Re-implement lc_ascon_aad */
static void lc_aead_ascon_aad(struct aead_request *areq)
{
	struct scatter_walk src_walk;
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct lc_ascon_cryptor *ascon = ctx->aead_state;
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
	static const uint8_t pad_trail = 0x01;
	size_t nbytes = areq->assoclen, sponge_offset = 0;

	if (!areq->assoclen)
		return;

	scatterwalk_start(&src_walk, areq->src);

	/* Insert the associated data into the sponge */
	while (nbytes) {
		unsigned int todo =
			min_t(unsigned int, hash->sponge_rate - sponge_offset,
			      scatterwalk_clamp(&src_walk, nbytes));
		u8 *src_vaddr = scatterwalk_map(&src_walk);

		lc_sponge_add_bytes(hash, state_mem, src_vaddr, sponge_offset,
				    todo);
		scatterwalk_unmap(src_vaddr);

		scatterwalk_advance(&src_walk, todo);

		sponge_offset += todo;
		nbytes -= todo;
		scatterwalk_pagedone(&src_walk, 0, nbytes);

		if (sponge_offset == hash->sponge_rate) {
			lc_sponge(hash, state_mem, ascon->roundb);
			sponge_offset = 0;
		}
	}

	lc_ascon_add_padbyte(ascon, sponge_offset);

	lc_sponge(hash, state_mem, ascon->roundb);

	/* Add pad_trail bit */
	lc_sponge_add_bytes(hash, state_mem, &pad_trail, ascon->statesize - 1,
			    1);
}

static int lc_aead_ascon_update(struct aead_request *areq,
				int (*process)(struct lc_aead_ctx *ctx,
					       const uint8_t *in, uint8_t *out,
					       size_t datalen))
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct scatterlist sg_src[2], sg_dst[2];
	struct scatterlist *src, *dst;
	struct scatter_walk src_walk, dst_walk;
	unsigned int nbytes = areq->cryptlen;
	int ret;

	if (!areq->cryptlen)
		return 0;

	src = scatterwalk_ffwd(sg_src, areq->src, areq->assoclen);
	if (areq->src == areq->dst)
		dst = src;
	else
		dst = scatterwalk_ffwd(sg_dst, areq->dst, areq->assoclen);

	scatterwalk_start(&src_walk, src);
	scatterwalk_start(&dst_walk, dst);

	while (nbytes) {
		unsigned int todo =
			min_t(unsigned int, scatterwalk_pagelen(&src_walk),
			      scatterwalk_pagelen(&dst_walk));
		u8 *src_vaddr, *dst_vaddr;

		todo = min_t(unsigned int, nbytes, todo);

		src_vaddr = scatterwalk_map(&src_walk);
		dst_vaddr = scatterwalk_map(&dst_walk);
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
	}

	return ret;
}

static int lc_aead_ascon_enc_final(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	/* Maximum tag size */
	u8 tag[64];
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

static int lc_aead_ascon_enc(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	int ret;

	/* NULL-key implies loading the key set with lc_ascon_load_key */
	ret = lc_aead_setkey(ctx, NULL, 0, areq->iv, crypto_aead_ivsize(aead));
	if (ret)
		return ret;

	lc_aead_ascon_aad(areq);

	ret = lc_aead_ascon_update(areq, lc_aead_enc_update);
	if (ret)
		return ret;

	return lc_aead_ascon_enc_final(areq);
}

static int lc_aead_ascon_dec_final(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	/* Maximum tag size */
	u8 tag[64];

	WARN_ON(sizeof(tag) < crypto_aead_maxauthsize(aead));

	scatterwalk_map_and_copy(tag, areq->src,
				 areq->assoclen + areq->cryptlen,
				 crypto_aead_authsize(aead), 0);

	return lc_aead_dec_final(ctx, tag, crypto_aead_authsize(aead));
}

static int lc_aead_ascon_dec(struct aead_request *areq)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	int ret;

	/* NULL-key implies loading the key set with lc_ascon_load_key */
	ret = lc_aead_setkey(ctx, NULL, 0, areq->iv, crypto_aead_ivsize(aead));
	if (ret)
		return ret;

	lc_aead_ascon_aad(areq);

	ret = lc_aead_ascon_update(areq, lc_aead_dec_update);
	if (ret)
		return ret;

	return lc_aead_ascon_dec_final(areq);
}

static int lc_aead_ascon_setkey(struct crypto_aead *aead, const u8 *key,
				unsigned int keylen)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct lc_ascon_cryptor *ascon = ctx->aead_state;

	/*
	 * Only load the key, but do not initialize the Ascon state yet. It
	 * will be initialized at the time the actual cipher operation will
	 * be performed. The goal is to allow the setting of the authsize (i.e.
	 * the tag length) after the setkey API is called.
	 */
	return lc_ascon_load_key(ascon, key, keylen);
}

static int lc_aead_setauthsize(struct crypto_aead *aead, unsigned int authsize)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct lc_ascon_cryptor *ascon = ctx->aead_state;

	if (authsize < 16)
		return -EINVAL;

	ascon->taglen = authsize;

	return 0;
}

#ifdef LC_ASCON
static int lc_aead_init_ascon128(struct crypto_aead *aead)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct lc_ascon_cryptor *ascon_crypto;

	LC_ASCON_SET_CTX(ctx, lc_ascon_128a);
	ascon_crypto = ctx->aead_state;
	ascon_crypto->statesize = LC_ASCON_HASH_STATE_SIZE;
	ascon_crypto->taglen = crypto_aead_maxauthsize(aead);

	return 0;
}

#endif

#ifdef LC_ASCON_KECCAK
static int lc_aead_init_ascon_keccak256(struct crypto_aead *aead)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct lc_ascon_cryptor *ascon_crypto;

	LC_ASCON_SET_CTX(ctx, lc_sha3_256);
	ascon_crypto = ctx->aead_state;
	ascon_crypto->statesize = LC_SHA3_STATE_SIZE;
	ascon_crypto->taglen = crypto_aead_maxauthsize(aead);

	return 0;
}

static int lc_aead_init_ascon_keccak512(struct crypto_aead *aead)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	struct lc_ascon_cryptor *ascon_crypto;

	LC_ASCON_SET_CTX(ctx, lc_sha3_512);
	ascon_crypto = ctx->aead_state;
	ascon_crypto->statesize = LC_SHA3_STATE_SIZE;
	ascon_crypto->taglen = crypto_aead_maxauthsize(aead);

	return 0;
}
#endif

static void lc_aead_exit(struct crypto_aead *aead)
{
}

static struct aead_alg lc_aead_algs[] = {
#ifdef LC_ASCON
	{
		.base = {
			.cra_name = "ascon-aead-128",
			.cra_driver_name = "ascon-aead-128-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = LC_AL_CTX_SIZE,
			.cra_alignmask = LC_ASCON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_aead_ascon_setkey,
		.setauthsize = lc_aead_setauthsize,
		.encrypt = lc_aead_ascon_enc,
		.decrypt = lc_aead_ascon_dec,
		.init = lc_aead_init_ascon128,
		.exit = lc_aead_exit,
		.ivsize = 16,
		.maxauthsize = 16,
	},
#endif
#ifdef LC_ASCON_KECCAK
	{
		.base = {
			.cra_name = "ascon-aead-keccak256",
			.cra_driver_name = "ascon-aead-keccak256-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = LC_AK_CTX_SIZE(lc_sha3_256),
			.cra_alignmask = LC_ASCON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_aead_ascon_setkey,
		.setauthsize = lc_aead_setauthsize,
		.encrypt = lc_aead_ascon_enc,
		.decrypt = lc_aead_ascon_dec,
		.init = lc_aead_init_ascon_keccak256,
		.exit = lc_aead_exit,
		.ivsize = 16,
		.maxauthsize = 32,
	}, {
		.base = {
			.cra_name = "ascon-aead-keccak512",
			.cra_driver_name = "ascon-aead-keccak512-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = LC_AK_CTX_SIZE(lc_sha3_512),
			.cra_alignmask = LC_ASCON_ALIGNMENT - 1,
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_aead_ascon_setkey,
		.setauthsize = lc_aead_setauthsize,
		.encrypt = lc_aead_ascon_enc,
		.decrypt = lc_aead_ascon_dec,
		.init = lc_aead_init_ascon_keccak512,
		.exit = lc_aead_exit,
		.ivsize = 16,
		.maxauthsize = 64,
	}
#endif
};

int __init lc_kernel_aead_ascon_init(void)
{
	return crypto_register_aeads(lc_aead_algs, ARRAY_SIZE(lc_aead_algs));
}

void lc_kernel_aead_ascon_exit(void)
{
	crypto_unregister_aeads(lc_aead_algs, ARRAY_SIZE(lc_aead_algs));
}
