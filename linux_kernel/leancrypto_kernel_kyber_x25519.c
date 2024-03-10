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

#include "lc_kyber.h"
#include "lc_memset_secure.h"
#include "x25519_scalarmult.h"

#include "leancrypto_kernel.h"

struct lc_kernel_kyber_x25519_ctx {
	struct lc_kyber_x25519_sk sk;
};

static int lc_kernel_kyber_x25519_set_secret(struct crypto_kpp *tfm,
					     const void *buffer,
					     unsigned int len)
{
	struct lc_kernel_kyber_x25519_ctx *ctx = kpp_tfm_ctx(tfm);

	if (len != sizeof(struct lc_kyber_x25519_sk))
		return -EINVAL;

	memcpy(&ctx->sk, buffer, sizeof(struct lc_kyber_x25519_sk));

	return 0;
}

static int lc_kernel_kyber_x25519_gen_pubkey(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_kyber_x25519_ctx *ctx = kpp_tfm_ctx(tfm);
	struct lc_kyber_x25519_pk pk;
	struct lc_kyber_sk *kyber_sk;
	struct lc_kyber_pk *kyber_pk;
	struct lc_x25519_pk *x25519_pk;
	struct lc_x25519_sk *x25519_sk;
	size_t nbytes, copied;
	int ret;

	kyber_sk = &ctx->sk.sk;
	kyber_pk = &pk.pk;
	x25519_sk = &ctx->sk.sk_x25519;
	x25519_pk = &pk.pk_x25519;

	/* See _lc_kyber_x25519_keypair: sk contains pk */
	memcpy(kyber_pk->pk, &kyber_sk->sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
	       LC_KYBER_PUBLICKEYBYTES);

	ret = crypto_scalarmult_curve25519_base(x25519_pk->pk, x25519_sk->sk);
	if (ret)
		return ret;

	nbytes = min_t(size_t, sizeof(pk), req->dst_len);
	copied = sg_copy_from_buffer(
		req->dst, sg_nents_for_len(req->dst, nbytes), &pk, nbytes);
	if (copied != nbytes)
		ret = -EINVAL;

	return ret;
}

static int lc_kernel_kyber_x25519_ss(struct kpp_request *req)
{
	struct crypto_kpp *tfm = crypto_kpp_reqtfm(req);
	struct lc_kernel_kyber_x25519_ctx *ctx = kpp_tfm_ctx(tfm);
	struct lc_kyber_x25519_ct ct;
	u8 *shared_secret = NULL;
	size_t copied;
	int ret;

	/*
	 * req->src contains Kyber ciphertext of peer
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

	if (req->src_len != sizeof(ct))
		return -EINVAL;

	copied = sg_copy_to_buffer(req->src,
				   sg_nents_for_len(req->src, req->src_len),
				   &ct, sizeof(ct));
	if (copied != sizeof(ct))
		return -EINVAL;

	shared_secret = kmalloc(req->dst_len, GFP_KERNEL);
	if (!shared_secret)
		return -ENOMEM;

	ret = lc_kyber_x25519_dec_kdf(shared_secret, req->dst_len, &ct,
				      &ctx->sk);
	if (ret)
		goto out;

	copied = sg_copy_from_buffer(req->dst,
				     sg_nents_for_len(req->dst, req->dst_len),
				     shared_secret, req->dst_len);
	if (copied != req->dst_len)
		ret = -EINVAL;

out:
	kfree_sensitive(shared_secret);
	return ret;
}

static unsigned int lc_kernel_kyber_x25519_max_size(struct crypto_kpp *tfm)
{
	return sizeof(struct lc_kyber_x25519_pk);
}

static struct kpp_alg lc_kernel_kyber = {
	.set_secret = lc_kernel_kyber_x25519_set_secret,
	.generate_public_key = lc_kernel_kyber_x25519_gen_pubkey,
	.compute_shared_secret = lc_kernel_kyber_x25519_ss,
	.max_size = lc_kernel_kyber_x25519_max_size,
#if LC_KYBER_K == 2
	.base.cra_name = "kyber-x25519-512",
	.base.cra_driver_name = "kyber-x25519-512-leancrypto",
#elif LC_KYBER_K == 3
	.base.cra_name = "kyber-x25519-768",
	.base.cra_driver_name = "kyber-x25519-768-leancrypto",
#else
	.base.cra_name = "kyber-x25519-1024",
	.base.cra_driver_name = "kyber-x25519-1024-leancrypto",
#endif
	.base.cra_ctxsize = sizeof(struct lc_kernel_kyber_x25519_ctx),
	.base.cra_module = THIS_MODULE,
	.base.cra_priority = LC_KERNEL_DEFAULT_PRIO,
};

int __init lc_kernel_kyber_x25519_init(void)
{
	return crypto_register_kpp(&lc_kernel_kyber);
}

void lc_kernel_kyber_x25519_exit(void)
{
	crypto_unregister_kpp(&lc_kernel_kyber);
}
