// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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
#include "leancrypto_kernel_aead_helper.h"

/* Re-implement lc_ascon_aad */
static void lc_aead_ascon_aad(struct aead_request *areq,
			      struct lc_aead_ctx *vola_ctx)
{
	struct scatter_walk src_walk;
	struct lc_ascon_cryptor *ascon = vola_ctx->aead_state;
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
	static const uint8_t pad_trail = 0x80;
	size_t nbytes = areq->assoclen, sponge_offset = 0;

	if (!nbytes)
		return;

	scatterwalk_start(&src_walk, areq->src);

	/* Insert the associated data into the sponge */
	while (nbytes) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
		unsigned int todo =
			min_t(unsigned int, hash->sponge_rate - sponge_offset,
			      scatterwalk_next(&src_walk, nbytes));

		u8 *src_vaddr = src_walk.addr;
#else
		unsigned int todo =
			min_t(unsigned int, hash->sponge_rate - sponge_offset,
			      scatterwalk_clamp(&src_walk, nbytes));
		u8 *src_vaddr = scatterwalk_map(&src_walk);
#endif

		lc_sponge_add_bytes(hash, state_mem, src_vaddr, sponge_offset,
				    todo);

		sponge_offset += todo;
		nbytes -= todo;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
		scatterwalk_done_src(&src_walk, todo);
#else
		scatterwalk_unmap(src_vaddr);

		scatterwalk_advance(&src_walk, todo);
		scatterwalk_pagedone(&src_walk, 0, nbytes);
#endif

		if (sponge_offset == hash->sponge_rate) {
			lc_sponge(hash, state_mem, ascon->roundb);
			sponge_offset = 0;
		}
	}

	lc_ascon_add_padbyte(ascon, sponge_offset);

	lc_sponge(hash, state_mem, ascon->roundb);

	/* Add pad_trail bit */
	lc_sponge_add_bytes(hash, state_mem, &pad_trail, ascon->statesize - 1,
			    sizeof(pad_trail));
}

static int lc_aead_ascon_enc_final(struct aead_request *areq,
				   struct lc_aead_ctx *vola_ctx)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	/* Maximum tag size */
	u8 tag[64];
	int ret;

	WARN_ON(sizeof(tag) < crypto_aead_maxauthsize(aead));

	ret = lc_aead_enc_final(vola_ctx, tag, crypto_aead_authsize(aead));
	if (ret)
		return ret;

	scatterwalk_map_and_copy(tag, areq->dst,
				 areq->assoclen + areq->cryptlen,
				 crypto_aead_authsize(aead), 1);

	return 0;
}

static int lc_aead_ascon_enc(struct aead_request *areq,
			     struct lc_aead_ctx *vola_ctx)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	int ret;

	ret = lc_aead_setkey_from_ctx(vola_ctx, ctx, areq->iv,
				      crypto_aead_ivsize(aead));
	if (ret)
		return ret;

	lc_aead_ascon_aad(areq, vola_ctx);

	ret = lc_kernel_aead_update(areq, vola_ctx, 1, lc_aead_enc_update);
	if (ret)
		return ret;

	return lc_aead_ascon_enc_final(areq, vola_ctx);
}

static int lc_aead_ascon_dec_final(struct aead_request *areq,
				   struct lc_aead_ctx *vola_ctx)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	unsigned int authsize = crypto_aead_authsize(aead);
	unsigned int cryptlen = areq->cryptlen - authsize;
	/* Maximum tag size */
	u8 tag[64];

	WARN_ON(sizeof(tag) < crypto_aead_maxauthsize(aead));

	scatterwalk_map_and_copy(tag, areq->src, areq->assoclen + cryptlen,
				 authsize, 0);

	return lc_aead_dec_final(vola_ctx, tag, authsize);
}

static int lc_aead_ascon_dec(struct aead_request *areq,
			     struct lc_aead_ctx *vola_ctx)
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);
	int ret;

	if (areq->cryptlen < crypto_aead_authsize(aead))
		return -EBADMSG;

	ret = lc_aead_setkey_from_ctx(vola_ctx, ctx, areq->iv,
				      crypto_aead_ivsize(aead));
	if (ret)
		return ret;

	lc_aead_ascon_aad(areq, vola_ctx);

	ret = lc_kernel_aead_update(areq, vola_ctx, 0, lc_aead_dec_update);
	if (ret)
		return ret;

	return lc_aead_ascon_dec_final(areq, vola_ctx);
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

	LC_AEAD_CTX_NO_STATE(ctx, lc_ascon_aead);

	return 0;
}

static int lc_aead_ascon_call_ascon128(
	struct aead_request *areq,
	int (*encdec)(struct aead_request *areq, struct lc_aead_ctx *vola_ctx))
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_ascon_cryptor *ascon_crypto;
	struct lc_aead_ctx *vola_ctx;
	int ret;

	vola_ctx = kzalloc(LC_AL_CTX_SIZE, GFP_KERNEL);
	if (!vola_ctx)
		return -ENOMEM;

	/*
	 * Note, lc_ascon_128a is used as it provides the proper round counts
	 * for the sponge operation for Ascon-AEAD128. It is not used for
	 * hashing.
	 */
	LC_ASCON_SET_CTX(vola_ctx, lc_ascon_128a, lc_ascon_aead);
	ascon_crypto = vola_ctx->aead_state;
	ascon_crypto->statesize = LC_ASCON_HASH_STATE_SIZE;
	ascon_crypto->taglen = crypto_aead_maxauthsize(aead);

	ret = encdec(areq, vola_ctx);

	lc_aead_zero(vola_ctx);
	kfree(vola_ctx);
	return ret;
}

static int lc_aead_ascon_enc_ascon128(struct aead_request *areq)
{
	return lc_aead_ascon_call_ascon128(areq, lc_aead_ascon_enc);
}

static int lc_aead_ascon_dec_ascon128(struct aead_request *areq)
{
	return lc_aead_ascon_call_ascon128(areq, lc_aead_ascon_dec);
}

#endif

#ifdef LC_ASCON_KECCAK

static int lc_aead_init_ascon_keccak256(struct crypto_aead *aead)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);

	LC_AEAD_CTX_NO_STATE(ctx, lc_ascon_keccak_aead);

	return 0;
}

static int lc_aead_ascon_call_keccak256(
	struct aead_request *areq,
	int (*encdec)(struct aead_request *areq, struct lc_aead_ctx *vola_ctx))
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_ascon_cryptor *ascon_crypto;
	struct lc_aead_ctx *vola_ctx;
	int ret;

	vola_ctx = kzalloc(LC_AK_CTX_SIZE, GFP_KERNEL);
	if (!vola_ctx)
		return -ENOMEM;

	LC_ASCON_SET_CTX(vola_ctx, lc_sha3_256, lc_ascon_keccak_aead);
	ascon_crypto = vola_ctx->aead_state;
	ascon_crypto->statesize = LC_SHA3_STATE_SIZE;
	ascon_crypto->taglen = crypto_aead_maxauthsize(aead);

	ret = encdec(areq, vola_ctx);

	lc_aead_zero(vola_ctx);
	kfree(vola_ctx);
	return ret;
}

static int lc_aead_ascon_enc_keccak256(struct aead_request *areq)
{
	return lc_aead_ascon_call_keccak256(areq, lc_aead_ascon_enc);
}

static int lc_aead_ascon_dec_keccak256(struct aead_request *areq)
{
	return lc_aead_ascon_call_keccak256(areq, lc_aead_ascon_dec);
}

static int lc_aead_init_ascon_keccak512(struct crypto_aead *aead)
{
	struct lc_aead_ctx *ctx = crypto_aead_ctx(aead);

	LC_AEAD_CTX_NO_STATE(ctx, lc_ascon_keccak_aead);

	return 0;
}

static int lc_aead_ascon_call_keccak512(
	struct aead_request *areq,
	int (*encdec)(struct aead_request *areq, struct lc_aead_ctx *vola_ctx))
{
	struct crypto_aead *aead = crypto_aead_reqtfm(areq);
	struct lc_ascon_cryptor *ascon_crypto;
	struct lc_aead_ctx *vola_ctx;
	int ret;

	vola_ctx = kzalloc(LC_AK_CTX_SIZE, GFP_KERNEL);
	if (!vola_ctx)
		return -ENOMEM;

	LC_ASCON_SET_CTX(vola_ctx, lc_sha3_512, lc_ascon_keccak_aead);
	ascon_crypto = vola_ctx->aead_state;
	ascon_crypto->statesize = LC_SHA3_STATE_SIZE;
	ascon_crypto->taglen = crypto_aead_maxauthsize(aead);

	ret = encdec(areq, vola_ctx);

	lc_aead_zero(vola_ctx);
	kfree(vola_ctx);
	return ret;
}

static int lc_aead_ascon_enc_keccak512(struct aead_request *areq)
{
	return lc_aead_ascon_call_keccak512(areq, lc_aead_ascon_enc);
}

static int lc_aead_ascon_dec_keccak512(struct aead_request *areq)
{
	return lc_aead_ascon_call_keccak512(areq, lc_aead_ascon_dec);
}

#endif

static void lc_aead_exit(struct crypto_aead *aead)
{
}

static struct aead_alg lc_aead_algs[] = {
#ifdef LC_ASCON
	{
		.base = {
			.cra_name = "ascon-aead128",
			.cra_driver_name = "ascon-aead128-leancrypto",
			.cra_priority = LC_KERNEL_DEFAULT_PRIO,
			.cra_blocksize = 1,
			.cra_ctxsize = sizeof(struct lc_aead_ctx),
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_aead_ascon_setkey,
		.setauthsize = lc_aead_setauthsize,
		.encrypt = lc_aead_ascon_enc_ascon128,
		.decrypt = lc_aead_ascon_dec_ascon128,
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
			.cra_ctxsize = sizeof(struct lc_aead_ctx),
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_aead_ascon_setkey,
		.setauthsize = lc_aead_setauthsize,
		.encrypt = lc_aead_ascon_enc_keccak256,
		.decrypt = lc_aead_ascon_dec_keccak256,
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
			.cra_ctxsize = sizeof(struct lc_aead_ctx),
			.cra_module = THIS_MODULE,
		},
		.setkey = lc_aead_ascon_setkey,
		.setauthsize = lc_aead_setauthsize,
		.encrypt = lc_aead_ascon_enc_keccak512,
		.decrypt = lc_aead_ascon_dec_keccak512,
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
