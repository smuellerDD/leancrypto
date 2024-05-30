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

#include <crypto/internal/kpp.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#include "kyber_kdf.h"
#include "kyber_type.h"
#include "kyber_internal.h"
#include "lc_memset_secure.h"

#include "leancrypto_kernel.h"

struct lc_kernel_kyber_ctx {
	struct lc_kyber_sk sk;
	struct lc_kyber_ss ss;
	struct lc_kyber_ct ct;
	bool ss_set;
};

static int lc_kernel_kyber_set_secret(struct crypto_kpp *tfm,
				      const void *buffer, unsigned int len)
{
	struct lc_kernel_kyber_ctx *ctx = kpp_tfm_ctx(tfm);

	if (!buffer || !len) {
		struct lc_kyber_pk pk;

		/* We do not need the pk at this point */
		return lc_kyber_keypair(&pk, &ctx->sk, lc_seeded_rng);
	}

	if (len != LC_KYBER_SECRETKEYBYTES)
		return -EINVAL;

	memcpy(ctx->sk.sk, buffer, LC_KYBER_SECRETKEYBYTES);

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

static int lc_kernel_kyber_gen_ct(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_kyber_ctx *ctx = kpp_tfm_ctx(tfm);
	struct lc_kyber_pk rpk;
	size_t nbytes, copied;
	int ret;

	/*
	 * req->src contains the remote public key to generate the local
	 * Kyber CT - this is optional
	 * req->dst is filled with either the local Kyber PK (if req->src is
	 * NULL), or with the Kyber CT as a result of the encapsulation
	 */
	if (req->src_len != LC_KYBER_PUBLICKEYBYTES) {
		/* See _lc_kyber_keypair: sk contains pk */
		u8 *lpk = &ctx->sk.sk[LC_KYBER_INDCPA_SECRETKEYBYTES];

		/* Copy out the public key */
		copied = sg_copy_from_buffer(
			req->dst,
			sg_nents_for_len(req->dst, LC_KYBER_PUBLICKEYBYTES),
			lpk, LC_KYBER_PUBLICKEYBYTES);
		if (copied != LC_KYBER_PUBLICKEYBYTES)
			return -EINVAL;
		return 0;
	}

	copied = sg_copy_to_buffer(req->src,
				   sg_nents_for_len(req->src, req->src_len),
				   rpk.pk, LC_KYBER_PUBLICKEYBYTES);
	if (copied != LC_KYBER_PUBLICKEYBYTES)
		return -EINVAL;

	ret = lc_kyber_enc(&ctx->ct, &ctx->ss, &rpk);
	if (ret)
		return ret;

	ctx->ss_set = true;

	/*
	 * Now we copy out the Kyber CT
	 */
	nbytes = min_t(size_t, LC_CRYPTO_CIPHERTEXTBYTES, req->dst_len);
	copied = sg_copy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, nbytes),
				     ctx->ct.ct, nbytes);
	if (copied != nbytes)
		ret = -EINVAL;

	return 0;
}

static int lc_kernel_kyber_ss_local(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_kyber_ctx *ctx = kpp_tfm_ctx(tfm);
	u8 *shared_secret = NULL, *outbuf;
	size_t copied;
	int ret = 0;

	/* lc_kernel_kyber_gen_ct must have been called before */
	if (!ctx->ss_set)
		return -EOPNOTSUPP;

	/*
	 * If the requested shared secret size is exactly the Kyber SS size
	 * then perform a Kyber operation without the KDF. Otherwise invoke
	 * Kyber with KDF.
	 */

	if (req->dst_len == LC_KYBER_SSBYTES) {
		outbuf = ctx->ss.ss;
	} else {
		shared_secret = kmalloc(req->dst_len, GFP_KERNEL);
		if (!shared_secret)
			return -ENOMEM;

		kyber_ss_kdf(shared_secret, req->dst_len, &ctx->ct, ctx->ss.ss);

		outbuf = shared_secret;
	}

	copied = sg_copy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     outbuf, req->dst_len);
	if (copied != req->dst_len)
		ret = -EINVAL;

	if (shared_secret)
		kfree_sensitive(shared_secret);

	/*
	 * The SS is allowed to be only used once - if the caller wants
	 * another SS, he has to call ->generate_public_key again.
	 */
	lc_memset_secure(&ctx->ss, 0, sizeof(ctx->ss));
	lc_memset_secure(&ctx->ct, 0, sizeof(ctx->ct));
	ctx->ss_set = false;

	return ret;
}

static int lc_kernel_kyber_ss(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_kyber_ctx *ctx = kpp_tfm_ctx(tfm);
	struct lc_kyber_ct ct;
	struct lc_kyber_ss ss;
	u8 *shared_secret = NULL, *outbuf;
	size_t copied;
	int ret;

	/*
	 * req->src contains Kyber ciphertext of peer - if this is NULL,
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
		return lc_kernel_kyber_ss_local(req);

	if (req->src_len != LC_CRYPTO_CIPHERTEXTBYTES)
		return -EINVAL;

	copied = sg_copy_to_buffer(req->src,
				   sg_nents_for_len(req->src, req->src_len),
				   ct.ct, LC_CRYPTO_CIPHERTEXTBYTES);
	if (copied != LC_CRYPTO_CIPHERTEXTBYTES)
		return -EINVAL;

	/*
	 * If the requested shared secret size is exactly the Kyber SS size
	 * then perform a Kyber operation without the KDF. Otherwise invoke
	 * Kyber with KDF.
	 */
	if (req->dst_len == LC_KYBER_SSBYTES) {
		ret = lc_kyber_dec(&ss, &ct, &ctx->sk);

		outbuf = ss.ss;
	} else {
		shared_secret = kmalloc(req->dst_len, GFP_KERNEL);
		if (!shared_secret)
			return -ENOMEM;

		ret = lc_kyber_dec_kdf(shared_secret, req->dst_len, &ct,
				       &ctx->sk);

		outbuf = shared_secret;
	}

	if (ret)
		goto out;

	copied = sg_copy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     outbuf, req->dst_len);
	if (copied != req->dst_len)
		ret = -EINVAL;

out:
	if (shared_secret)
		kfree_sensitive(shared_secret);
	else
		lc_memset_secure(&ss, 0, sizeof(ss));

	return ret;
}

static unsigned int lc_kernel_kyber_max_size(struct crypto_kpp *tfm)
{
	return LC_CRYPTO_CIPHERTEXTBYTES;
}

static struct kpp_alg lc_kernel_kyber = {
	.set_secret = lc_kernel_kyber_set_secret,
	.generate_public_key = lc_kernel_kyber_gen_ct,
	.compute_shared_secret = lc_kernel_kyber_ss,
	.max_size = lc_kernel_kyber_max_size,
#ifdef LC_KYBER_TYPE_512
	.base.cra_name = "kyber512",
	.base.cra_driver_name = "kyber512-leancrypto",
#elif defined(LC_KYBER_TYPE_768)
	.base.cra_name = "kyber768",
	.base.cra_driver_name = "kyber768-leancrypto",
#else
	.base.cra_name = "kyber1024",
	.base.cra_driver_name = "kyber1024-leancrypto",
#endif
	.base.cra_ctxsize = sizeof(struct lc_kernel_kyber_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

#ifdef LC_KYBER_TYPE_512
int __init lc_kernel_kyber_512_init(void)
{
	return crypto_register_kpp(&lc_kernel_kyber);
}

void lc_kernel_kyber_512_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_kyber);
}

EXPORT_SYMBOL(lc_kyber_512_enc_internal);
EXPORT_SYMBOL(lc_kyber_512_enc_kdf_internal);
EXPORT_SYMBOL(lc_kex_512_ake_responder_ss_internal);
EXPORT_SYMBOL(lc_kex_512_uake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_512_ake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_512_uake_responder_ss_internal);
EXPORT_SYMBOL(lc_kyber_512_ies_enc_internal);
EXPORT_SYMBOL(lc_kyber_512_ies_enc_init_internal);

#elif defined(LC_KYBER_TYPE_768)
int __init lc_kernel_kyber_768_init(void)
{
	return crypto_register_kpp(&lc_kernel_kyber);
}

void lc_kernel_kyber_768_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_kyber);
}

EXPORT_SYMBOL(lc_kyber_768_enc_internal);
EXPORT_SYMBOL(lc_kyber_768_enc_kdf_internal);
EXPORT_SYMBOL(lc_kex_768_ake_responder_ss_internal);
EXPORT_SYMBOL(lc_kex_768_uake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_768_ake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_768_uake_responder_ss_internal);
EXPORT_SYMBOL(lc_kyber_768_ies_enc_internal);
EXPORT_SYMBOL(lc_kyber_768_ies_enc_init_internal);

#else
int __init lc_kernel_kyber_init(void)
{
	return crypto_register_kpp(&lc_kernel_kyber);
}

void lc_kernel_kyber_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_kyber);
}

EXPORT_SYMBOL(lc_kyber_enc_internal);
EXPORT_SYMBOL(lc_kyber_enc_kdf_internal);
EXPORT_SYMBOL(lc_kex_ake_responder_ss_internal);
EXPORT_SYMBOL(lc_kex_uake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_ake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_uake_responder_ss_internal);
EXPORT_SYMBOL(lc_kyber_ies_enc_internal);
EXPORT_SYMBOL(lc_kyber_ies_enc_init_internal);

#endif
