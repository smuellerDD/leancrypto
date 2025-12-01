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

#include <crypto/internal/kpp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#include "hqc_internal.h"
#include "lc_memset_secure.h"

#include "leancrypto_kernel.h"

struct lc_kernel_hqc_ctx {
	struct lc_hqc_sk sk;
	struct lc_hqc_ss ss;
	struct lc_hqc_ct ct;
	bool ss_set;
};

static int lc_kernel_hqc_set_secret(struct crypto_kpp *tfm, const void *buffer,
				    unsigned int len)
{
	struct lc_kernel_hqc_ctx *ctx = kpp_tfm_ctx(tfm);

	if (!buffer || !len) {
		struct lc_hqc_pk *pk;
		int ret;

		pk = kmalloc(sizeof(struct lc_hqc_pk), GFP_KERNEL);
		if (!pk)
			return -ENOMEM;

		/* We do not need the pk at this point */
		ret = lc_hqc_keypair(pk, &ctx->sk, lc_seeded_rng);

		free_zero(pk);
		return ret;
	}

	if (len != sizeof(struct lc_hqc_sk))
		return -EINVAL;

	memcpy(&ctx->sk, buffer, sizeof(struct lc_hqc_sk));

	return 0;
}

/*
 * The kernel crypto API interface is defined as follows for the different
 * operation types.
 *
 * Initiator:
 *
 * 1. Generate new keypair: crypto_kpp_set_secret(tfm, NULL, 0);
 *
 * 2. Get public key:
 * 	crypto_kpp_generate_public_key(req->src = NULL, req->dst = PK)
 *
 * 3. Send the PK to remote and get the CT.
 *
 * 4. Calculate shared secret:
 *	crypto_kpp_compute_shared_secret(req->src = CT, req->dst = SS)
 *
 * Responder:
 *
 * 1. Generate new keypair: crypto_kpp_set_secret(tfm, NULL, 0);
 *
 * 2. Get the remote PK to generate the CT and shared secret:
 *	crypto_kpp_generate_public_key(req->src = PK, req->dst = CT)
 *
 * 3. Send CT to the peer
 *
 * 4. Get the shared secret:
 * 	crypto_kpp_compute_shared_secret(req->src = NULL, req->dst = SS)
 */

static int lc_kernel_hqc_gen_ct(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_hqc_ctx *ctx = kpp_tfm_ctx(tfm);
	struct lc_hqc_pk *rpk = NULL;
	size_t nbytes, copied;
	int ret = 0;

	/*
	 * req->src contains the remote public key to generate the local
	 * HQC CT - this is optional
	 * req->dst is filled with either the local HQC PK (if req->src is
	 * NULL), or with the HQC CT as a result of the encapsulation
	 */
	if (req->src_len != sizeof(struct lc_hqc_pk)) {
		/* See hqc_secret_key_to_string: sk contains pk */
		u8 *lpk = ctx->sk.sk + LC_HQC_SEED_BYTES +
			  LC_HQC_VEC_K_SIZE_BYTES;

		/* Copy out the public key */
		copied = sg_copy_from_buffer(
			req->dst,
			sg_nents_for_len(req->dst, LC_HQC_PUBLIC_KEY_BYTES),
			lpk, LC_HQC_PUBLIC_KEY_BYTES);
		if (copied != LC_HQC_PUBLIC_KEY_BYTES)
			return -EINVAL;
		return 0;
	}

	rpk = kmalloc(sizeof(struct lc_hqc_pk), GFP_KERNEL);
	if (!rpk)
		return -ENOMEM;

	copied = sg_copy_to_buffer(req->src,
				   sg_nents_for_len(req->src, req->src_len),
				   rpk, sizeof(struct lc_hqc_pk));
	if (copied != sizeof(struct lc_hqc_pk)) {
		ret = -EINVAL;
		goto out;
	}

	ret = lc_hqc_enc(&ctx->ct, &ctx->ss, rpk);
	if (ret)
		goto out;

	ctx->ss_set = true;

	/*
	 * Now we copy out the HQC CT
	 */
	nbytes = min_t(size_t, sizeof(struct lc_hqc_ct), req->dst_len);
	copied = sg_copy_from_buffer(
		req->dst, sg_nents_for_len(req->dst, nbytes), &ctx->ct, nbytes);
	if (copied != nbytes)
		ret = -EINVAL;

out:
	if (rpk)
		free_zero(rpk);
	return ret;
}

static int lc_kernel_hqc_ss_local(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_hqc_ctx *ctx = kpp_tfm_ctx(tfm);
	u8 *shared_secret = NULL, *outbuf;
	size_t copied;
	int ret = 0;

	/* lc_kernel_hqc_gen_ct must have been called before */
	if (!ctx->ss_set)
		return -EOPNOTSUPP;

	/*
	 * If the requested shared secret size is exactly the HQC SS size
	 * then perform a HQC operation without the KDF. Otherwise invoke
	 * HQC with KDF.
	 */

	if (req->dst_len == LC_HQC_SHARED_SECRET_BYTES) {
		outbuf = ctx->ss.ss;
	} else {
#if 0
		shared_secret = kmalloc(req->dst_len, GFP_KERNEL);
		if (!shared_secret)
			return -ENOMEM;

		/*
		 * NOTE: This function call implies that this code is not
		 * converted to the common HQC API, but uses the
		 * API specific to levels 256/192/128.
		 */
		hqc_ss_kdf(shared_secret, req->dst_len, &ctx->ct, ctx->ss.ss);

		outbuf = shared_secret;
#else
		return -EINVAL;
#endif
	}

	copied = sg_copy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     outbuf, req->dst_len);
	if (copied != req->dst_len)
		ret = -EINVAL;

	if (shared_secret)
		free_zero(shared_secret);

	/*
	 * The SS is allowed to be only used once - if the caller wants
	 * another SS, he has to call ->generate_public_key again.
	 */
	lc_memset_secure(&ctx->ss, 0, sizeof(ctx->ss));
	lc_memset_secure(&ctx->ct, 0, sizeof(ctx->ct));
	ctx->ss_set = false;

	return ret;
}

static int lc_kernel_hqc_ss(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_hqc_ctx *ctx = kpp_tfm_ctx(tfm);
	struct lc_hqc_ct *ct = NULL;
	struct lc_hqc_ss ss;
	u8 *shared_secret = NULL, *outbuf;
	size_t copied;
	int ret;

	/*
	 * req->src contains HQC ciphertext of peer - if this is NULL,
	 * extract the local shared secret
	 * req->dst will receive shared secret
	 */

	/*
	 * Set an arbitrary limit for the shared secret to avoid allocating
	 * too much memory. The value allows 2 AES keys + 2 IVs + 2 MAC keys.
	 */
	if (req->dst_len > (2 * 32 + 2 * 16 + 2 * 32))
		return -EOVERFLOW;

	if (!req->dst_len)
		return -EINVAL;

	/* Extract the local SS */
	if (!req->src_len)
		return lc_kernel_hqc_ss_local(req);

	if (req->src_len != sizeof(struct lc_hqc_ct))
		return -EINVAL;

	ct = kmalloc(sizeof(struct lc_hqc_ct), GFP_KERNEL);
	if (!ct)
		return -ENOMEM;

	copied = sg_copy_to_buffer(req->src,
				   sg_nents_for_len(req->src, req->src_len), ct,
				   sizeof(struct lc_hqc_ct));
	if (copied != sizeof(struct lc_hqc_ct))
		return -EINVAL;

	/*
	 * If the requested shared secret size is exactly the HQC SS size
	 * then perform a HQC operation without the KDF. Otherwise invoke
	 * HQC with KDF.
	 */
	if (req->dst_len == LC_HQC_SHARED_SECRET_BYTES) {
		ret = lc_hqc_dec(&ss, ct, &ctx->sk);

		outbuf = ss.ss;
	} else {
#if 0
		shared_secret = kmalloc(req->dst_len, GFP_KERNEL);
		if (!shared_secret)
			return -ENOMEM;

		ret = lc_hqc_dec_kdf(shared_secret, req->dst_len, ct,
				      &ctx->sk);

		outbuf = shared_secret;
#else
		ret = -EINVAL;
		goto out;
#endif
	}

	if (ret)
		goto out;

	copied = sg_copy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     outbuf, req->dst_len);
	if (copied != req->dst_len)
		ret = -EINVAL;

out:
	if (ct)
		free_zero(ct);
	if (shared_secret)
		free_zero(shared_secret);
	else
		lc_memset_secure(&ss, 0, sizeof(ss));

	return ret;
}

static unsigned int lc_kernel_hqc_max_size(struct crypto_kpp *tfm)
{
	return sizeof(struct lc_hqc_ct);
}

static struct kpp_alg lc_kernel_hqc = {
	.set_secret = lc_kernel_hqc_set_secret,
	.generate_public_key = lc_kernel_hqc_gen_ct,
	.compute_shared_secret = lc_kernel_hqc_ss,
	.max_size = lc_kernel_hqc_max_size,
#ifdef LC_HQC_TYPE_128
	.base.cra_name = "hqc128",
	.base.cra_driver_name = "hqc128-leancrypto",
#elif defined(LC_HQC_TYPE_192)
	.base.cra_name = "hqc192",
	.base.cra_driver_name = "hqc192-leancrypto",
#else
	.base.cra_name = "hqc256",
	.base.cra_driver_name = "hqc256-leancrypto",
#endif
	.base.cra_ctxsize = sizeof(struct lc_kernel_hqc_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

#ifdef LC_HQC_TYPE_128
int __init lc_kernel_hqc_128_init(void)
{
	return crypto_register_kpp(&lc_kernel_hqc);
}

void lc_kernel_hqc_128_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_hqc);
}

#elif defined(LC_HQC_TYPE_192)
int __init lc_kernel_hqc_192_init(void)
{
	return crypto_register_kpp(&lc_kernel_hqc);
}

void lc_kernel_hqc_192_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_hqc);
}

#else
int __init lc_kernel_hqc_init(void)
{
	return crypto_register_kpp(&lc_kernel_hqc);
}

void lc_kernel_hqc_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_hqc);
}

#endif
