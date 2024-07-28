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
#include <crypto/scatterwalk.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#include "kyber_type.h"
#include "kyber_x25519_internal.h"
#include "lc_memset_secure.h"
#include "x25519_scalarmult.h"

#include "leancrypto_kernel.h"

/*
 * Set an arbitrary limit for the shared secret to avoid allocating
 * too much memory. The value allows 2 AES keys + 2 IVs + 2 MAC keys.
 */
#define LC_KYBER_X25519_MAX_SS (2 * 32 + 2 * 16 + 2 * 32)

struct lc_kernel_kyber_x25519_ctx {
	struct lc_kyber_x25519_sk sk;
	struct lc_kyber_x25519_pk pk;
	struct lc_kyber_x25519_ct ct;
	u8 ss[LC_KYBER_X25519_MAX_SS];
	bool ss_set;
	bool pubkey_present;
};

static int lc_kernel_kyber_x25519_set_secret(struct crypto_kpp *tfm,
					     const void *buffer,
					     unsigned int len)
{
	struct lc_kernel_kyber_x25519_ctx *ctx = kpp_tfm_ctx(tfm);

	ctx->pubkey_present = 0;

	if (!buffer || !len) {
		/* We do not need the pk at this point */
		int ret = lc_kyber_x25519_keypair(&ctx->pk, &ctx->sk,
						  lc_seeded_rng);

		if (!ret)
			ctx->pubkey_present = 1;
		return ret;
	}

	if (len != sizeof(struct lc_kyber_x25519_sk))
		return -EINVAL;

	memcpy(&ctx->sk, buffer, sizeof(struct lc_kyber_x25519_sk));

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
 *
 * Note, the caller must provide or expect all data to be a concatenation of
 * the Kyber data followed by the X25519 data.
 */

static int lc_kernel_kyber_x25519_gen_ct(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct scatterlist x25519_sg[2];
	struct lc_kyber_x25519_pk rpk;
	struct scatterlist *x25519;
	struct lc_kernel_kyber_x25519_ctx *ctx = kpp_tfm_ctx(tfm);
	size_t copied;
	int ret;

	/*
	 * req->src contains the remote public keys to generate the local
	 * Kyber CT - this is optional
	 * req->dst is filled with either the local Kyber PK (if req->src is
	 * NULL), or with the Kyber CT as a result of the encapsulation
	 */
	if (req->src_len !=
	    LC_KYBER_PUBLICKEYBYTES + LC_X25519_PUBLICKEYBYTES) {
		struct lc_kyber_x25519_pk *lpk = &ctx->pk;

		if (!ctx->pubkey_present)
			return -EOPNOTSUPP;

		/* Copy out the Kyber public key */
		copied = sg_copy_from_buffer(
			req->dst,
			sg_nents_for_len(req->dst, LC_KYBER_PUBLICKEYBYTES),
			lpk->pk.pk, LC_KYBER_PUBLICKEYBYTES);
		if (copied != LC_KYBER_PUBLICKEYBYTES)
			return -EINVAL;

		/* Copy out the X25519 public key */
		x25519 = scatterwalk_ffwd(x25519_sg, req->dst,
					  LC_KYBER_PUBLICKEYBYTES);
		copied = sg_pcopy_from_buffer(
			x25519, sg_nents_for_len(x25519,
						 LC_X25519_PUBLICKEYBYTES),
			lpk->pk_x25519.pk, LC_X25519_PUBLICKEYBYTES, 0);
		if (copied != LC_X25519_PUBLICKEYBYTES)
			return -EINVAL;

		return 0;
	}

	/* Require the caller to provide sufficient buffer for the CT data */
	if (req->dst_len < LC_CRYPTO_CIPHERTEXTBYTES + LC_X25519_PUBLICKEYBYTES)
		return -EOVERFLOW;

	/* Copy in the Kyber public key */
	copied = sg_copy_to_buffer(req->src,
				   sg_nents_for_len(req->src, req->src_len),
				   rpk.pk.pk, LC_KYBER_PUBLICKEYBYTES);
	if (copied != LC_KYBER_PUBLICKEYBYTES)
		return -EINVAL;

	/* Copy in the X25519 public key */
	x25519 = scatterwalk_ffwd(x25519_sg, req->src,
				  LC_KYBER_PUBLICKEYBYTES);
	copied = sg_copy_to_buffer(x25519,
				   sg_nents_for_len(x25519, req->src_len),
				   rpk.pk_x25519.pk, LC_X25519_PUBLICKEYBYTES);
	if (copied != LC_X25519_PUBLICKEYBYTES)
		return -EINVAL;

	ret = lc_kyber_x25519_enc_kdf(&ctx->ct, ctx->ss,
				      LC_KYBER_X25519_MAX_SS, &rpk);
	if (ret)
		return ret;

	ctx->ss_set = true;

	/* Now we copy out the Kyber CT */
	copied = sg_copy_from_buffer(
		req->dst, sg_nents_for_len(req->dst, LC_CRYPTO_CIPHERTEXTBYTES),
		ctx->ct.ct.ct, LC_CRYPTO_CIPHERTEXTBYTES);
	if (copied != LC_CRYPTO_CIPHERTEXTBYTES)
		ret = -EINVAL;

	/* .. and copy out the X25519 PK */
	x25519 = scatterwalk_ffwd(x25519_sg, req->dst,
				  LC_CRYPTO_CIPHERTEXTBYTES);

	copied = sg_copy_from_buffer(
		x25519, sg_nents_for_len(x25519, LC_X25519_PUBLICKEYBYTES),
		ctx->ct.pk_x25519.pk, LC_X25519_PUBLICKEYBYTES);
	if (copied != LC_X25519_PUBLICKEYBYTES)
		ret = -EINVAL;

	return 0;
}

static int lc_kernel_kyber_x25519_ss_local(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_kyber_x25519_ctx *ctx = kpp_tfm_ctx(tfm);
	size_t copied;
	int ret = 0;

	/* lc_kernel_kyber_x25519_gen_ct must have been called before */
	if (!ctx->ss_set)
		return -EOPNOTSUPP;

	/*
	 * Copy out the requested SS size up to the maximum available data.
	 * The chosen KDF works such that when truncating the existing data, the
	 * same data is obtained as if the KDF is invoked with the already
	 * reduced length.
	 */
	copied = sg_copy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     ctx->ss, req->dst_len);
	if (copied != req->dst_len)
		ret = -EINVAL;

	/*
	 * The SS is allowed to be only used once - if the caller wants
	 * another SS, he has to call ->generate_public_key again.
	 */
	lc_memset_secure(&ctx->ss, 0, req->dst_len);
	lc_memset_secure(&ctx->ct, 0, sizeof(ctx->ct));
	ctx->ss_set = false;

	return ret;
}

static int lc_kernel_kyber_x25519_ss(struct kpp_request *req)
{
	u8 ss[LC_KYBER_X25519_MAX_SS];
	struct scatterlist x25519_sg[2];
	struct scatterlist *x25519;
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_kyber_x25519_ctx *ctx = kpp_tfm_ctx(tfm);
	struct lc_kyber_x25519_ct *ct;
	size_t copied;
	int ret;

	/*
	 * req->src contains Kyber ciphertext of peer - if this is NULL,
	 * extract the local shared secret
	 * req->dst will receive shared secret
	 */

	if (req->dst_len > LC_KYBER_X25519_MAX_SS)
		return -EOVERFLOW;

	if (!req->dst_len)
		return -EINVAL;

	/* Extract the local SS */
	if (!req->src_len)
		return lc_kernel_kyber_x25519_ss_local(req);

	if (req->src_len !=
	    LC_CRYPTO_CIPHERTEXTBYTES + LC_X25519_PUBLICKEYBYTES)
		return -EINVAL;

	ct = kmalloc(sizeof(struct lc_kyber_x25519_ct), GFP_KERNEL);
	if (!ct)
		return -ENOMEM;

	/* Copy in the remote Kyber CT */
	copied = sg_copy_to_buffer(
		req->src, sg_nents_for_len(req->src, LC_CRYPTO_CIPHERTEXTBYTES),
		ct->ct.ct, LC_CRYPTO_CIPHERTEXTBYTES);
	if (copied != LC_CRYPTO_CIPHERTEXTBYTES) {
		ret = -EINVAL;
		goto out;
	}

	/* Copy in the remote X25519 PK */
	x25519 = scatterwalk_ffwd(x25519_sg, req->src,
				  LC_CRYPTO_CIPHERTEXTBYTES);
	copied = sg_copy_to_buffer(
		x25519, sg_nents_for_len(x25519, LC_X25519_PUBLICKEYBYTES),
		ct->pk_x25519.pk, LC_X25519_PUBLICKEYBYTES);
	if (copied != LC_X25519_PUBLICKEYBYTES) {
		ret = -EINVAL;
		goto out;
	}

	ret = lc_kyber_x25519_dec_kdf(ss, sizeof(ss), ct, &ctx->sk);
	if (ret)
		goto out;

	copied = sg_copy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     ss, req->dst_len);
	if (copied != req->dst_len)
		ret = -EINVAL;

out:
	lc_memset_secure(&ss, 0, req->dst_len);
	kfree_sensitive(ct);
	return ret;
}

static unsigned int lc_kernel_kyber_x25519_max_size(struct crypto_kpp *tfm)
{
	return LC_CRYPTO_CIPHERTEXTBYTES + LC_X25519_PUBLICKEYBYTES;
}

static struct kpp_alg lc_kernel_kyber = {
	.set_secret = lc_kernel_kyber_x25519_set_secret,
	.generate_public_key = lc_kernel_kyber_x25519_gen_ct,
	.compute_shared_secret = lc_kernel_kyber_x25519_ss,
	.max_size = lc_kernel_kyber_x25519_max_size,
#if LC_KYBER_K == 2
	.base.cra_name = "kyber512-x25519",
	.base.cra_driver_name = "kyber512-x25519-leancrypto",
#elif LC_KYBER_K == 3
	.base.cra_name = "kyber768-x25519",
	.base.cra_driver_name = "kyber768-x25519-leancrypto",
#else
	.base.cra_name = "kyber1024-x25519",
	.base.cra_driver_name = "kyber1024-x25519-leancrypto",
#endif
	.base.cra_ctxsize = sizeof(struct lc_kernel_kyber_x25519_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

#ifdef LC_KYBER_TYPE_512
int __init lc_kernel_kyber_x25519_512_init(void)
{
	return crypto_register_kpp(&lc_kernel_kyber);
}

void lc_kernel_kyber_x25519_512_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_kyber);
}

EXPORT_SYMBOL(lc_kyber_512_x25519_enc_kdf_internal);
EXPORT_SYMBOL(lc_kyber_512_x25519_ies_enc_internal);
EXPORT_SYMBOL(lc_kyber_512_x25519_ies_enc_init_internal);
EXPORT_SYMBOL(lc_kex_512_x25519_ake_responder_ss_internal);
EXPORT_SYMBOL(lc_kex_512_x25519_uake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_512_x25519_ake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_512_x25519_uake_responder_ss_internal);

#elif defined(LC_KYBER_TYPE_768)
int __init lc_kernel_kyber_x25519_768_init(void)
{
	return crypto_register_kpp(&lc_kernel_kyber);
}

void lc_kernel_kyber_x25519_768_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_kyber);
}

EXPORT_SYMBOL(lc_kyber_768_x25519_enc_kdf_internal);
EXPORT_SYMBOL(lc_kyber_768_x25519_ies_enc_internal);
EXPORT_SYMBOL(lc_kyber_768_x25519_ies_enc_init_internal);
EXPORT_SYMBOL(lc_kex_768_x25519_ake_responder_ss_internal);
EXPORT_SYMBOL(lc_kex_768_x25519_uake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_768_x25519_ake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_768_x25519_uake_responder_ss_internal);

#else

int __init lc_kernel_kyber_x25519_init(void)
{
	return crypto_register_kpp(&lc_kernel_kyber);
}

void lc_kernel_kyber_x25519_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_kyber);
}

EXPORT_SYMBOL(lc_kyber_x25519_enc_kdf_internal);
EXPORT_SYMBOL(lc_kyber_x25519_ies_enc_internal);
EXPORT_SYMBOL(lc_kyber_x25519_ies_enc_init_internal);
EXPORT_SYMBOL(lc_kex_x25519_ake_responder_ss_internal);
EXPORT_SYMBOL(lc_kex_x25519_uake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_x25519_ake_initiator_init_internal);
EXPORT_SYMBOL(lc_kex_x25519_uake_responder_ss_internal);
#endif
