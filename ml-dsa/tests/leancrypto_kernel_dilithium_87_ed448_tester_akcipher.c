// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/akcipher.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

#include "lc_dilithium.h"
#include "leancrypto_kernel.h"

#ifdef LC_DILITHIUM_TYPE_65
#define DILITHIUM_TYPE LC_DILITHIUM_65
#define LC_DILITHIUM_IMPL_NAME "dilithium65-ed448-leancrypto"
#elif defined LC_DILITHIUM_TYPE_44
#define DILITHIUM_TYPE LC_DILITHIUM_44
#define LC_DILITHIUM_IMPL_NAME "dilithium44-ed448-leancrypto"
#else
#define DILITHIUM_TYPE LC_DILITHIUM_87
#define LC_DILITHIUM_IMPL_NAME "dilithium87-ed448-leancrypto"
#endif

struct lc_tcrypt_res {
	struct completion completion;
	int err;
};

/* tie all data structures together */
struct lc_akcipher_def {
	struct crypto_akcipher *tfm;
	struct akcipher_request *req;
	struct lc_tcrypt_res result;
};

static void lc_akcipher_wait(struct lc_akcipher_def *akcipher, int rc)
{
	init_completion(&akcipher->result.completion);

	switch (rc) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&akcipher->result.completion);
		rc = akcipher->result.err;
		if (!akcipher->result.err) {
			reinit_completion(&akcipher->result.completion);
		}
		break;
	default:
		pr_info("akcipher cipher operation returned with %d result"
			" %d\n",
			rc, akcipher->result.err);
		break;
	}
}

static int lc_test_sigver(const char *algname, struct lc_dilithium_ed448_pk *pk,
			  uint8_t *sig, uint8_t *msg, size_t msglen)
{
	struct crypto_akcipher *tfm = NULL;
	struct lc_akcipher_def akcipher;
	struct akcipher_request *req = NULL;
	struct scatterlist src[2];
	uint8_t *dilithium_ptr, *ed448_ptr;
	size_t dilithium_len, ed448_len;
	int err = -ENOMEM;

	tfm = crypto_alloc_akcipher(algname, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate akcipher handle for %s %ld\n",
			algname, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto err;

	err = lc_dilithium_ed448_pk_ptr(&dilithium_ptr, &dilithium_len,
					&ed448_ptr, &ed448_len, pk);
	if (err)
		goto err;

	if (dilithium_len + ed448_len !=
	    lc_dilithium_ed448_pk_size(DILITHIUM_TYPE)) {
		pr_info("Unexpected public key length: %zu %u\n",
			dilithium_len + ed448_len,
			lc_dilithium_ed448_pk_size(DILITHIUM_TYPE));
		err = -EFAULT;
		goto err;
	}

	/*
	 * NOTE: This only works because dilithium_ptr and ed448_ptr
	 * are concatenated in a linear buffer.
	 */
	err = crypto_akcipher_set_pub_key(tfm, dilithium_ptr,
					  dilithium_len + ed448_len);
	if (err)
		goto err;

	pr_info("input datasize: %u\n", crypto_akcipher_maxsize(tfm));

	akcipher.tfm = tfm;
	akcipher.req = req;

	/*
	 * NOTE: This only works because dilithium_sk_ptr and ed448_sk_ptr
	 * are concatenated in a linear buffer.
	 */

	sg_init_table(src, 2);
	sg_set_buf(&src[0], sig, lc_dilithium_ed448_sig_size(DILITHIUM_TYPE));
	sg_set_buf(&src[1], msg, msglen);

	akcipher_request_set_crypt(
		req, src, NULL,
		lc_dilithium_ed448_sig_size(DILITHIUM_TYPE) + msglen, 0);

	err = crypto_akcipher_verify(req);

	lc_akcipher_wait(&akcipher, err);

	pr_info("Signature verification result %d\n", err);

err:
	if (req)
		akcipher_request_free(req);
	if (tfm)
		crypto_free_akcipher(tfm);
	return err;
}

static int lc_test_siggen(const char *algname, struct lc_dilithium_ed448_sk *sk,
			  uint8_t *sig, uint8_t *msg, size_t msglen)
{
	struct crypto_akcipher *tfm = NULL;
	struct lc_akcipher_def akcipher;
	struct akcipher_request *req = NULL;
	struct scatterlist src, dst;
	uint8_t *dilithium_ptr, *ed448_ptr;
	size_t dilithium_len, ed448_len;
	int err = -ENOMEM;

	tfm = crypto_alloc_akcipher(algname, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate akcipher handle for %s %ld\n",
			algname, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req)
		goto err;

	err = lc_dilithium_ed448_sk_ptr(&dilithium_ptr, &dilithium_len,
					&ed448_ptr, &ed448_len, sk);
	if (err)
		goto err;

	if (dilithium_len + ed448_len !=
	    lc_dilithium_ed448_sk_size(DILITHIUM_TYPE)) {
		pr_info("Unexpected private key length: %zu %u\n",
			dilithium_len + ed448_len,
			lc_dilithium_ed448_sk_size(DILITHIUM_TYPE));
		err = -EFAULT;
		goto err;
	}

	/*
	 * NOTE: This only works because dilithium_sk_ptr and ed448_sk_ptr
	 * are concatenated in a linear buffer.
	 */
	err = crypto_akcipher_set_priv_key(tfm, dilithium_ptr,
					   dilithium_len + ed448_len);
	if (err)
		goto err;

	pr_info("output datasize: %u\n", crypto_akcipher_maxsize(tfm));

	akcipher.tfm = tfm;
	akcipher.req = req;

	sg_init_one(&src, msg, msglen);
	sg_init_one(&dst, sig, lc_dilithium_ed448_sig_size(DILITHIUM_TYPE));
	akcipher_request_set_crypt(req, &src, &dst, msglen,
				   lc_dilithium_ed448_sig_size(DILITHIUM_TYPE));

	err = crypto_akcipher_sign(req);
	lc_akcipher_wait(&akcipher, err);

	pr_info("Dilithium signature generation result %d\n", err);

#if 0
	{
		char hex[10000];

		memset(hex, 0, sizeof(hex));
		bin2hex(hex, dilithium_ptr, dilithium_len);
		pr_err("Siggen - Dilithium sig: %s\n", hex);

		memset(hex, 0, sizeof(hex));
		bin2hex(hex, ed448_ptr, ed448_len);
		pr_err("Sigget - ED448 sig: %s\n", hex);
	}
#endif

err:
	if (req)
		akcipher_request_free(req);
	if (tfm)
		crypto_free_akcipher(tfm);
	return err;
}

static int lc_dilithium_tester(void)
{
	struct workspace {
		struct lc_dilithium_ed448_pk pk;
		struct lc_dilithium_ed448_sk sk;
		uint8_t msg[10];
		uint8_t sig[];
	};
	struct workspace *ws;
	int ret;

	ws = kzalloc(sizeof(struct workspace) +
			     lc_dilithium_ed448_sig_size(DILITHIUM_TYPE),
		     GFP_KERNEL);
	if (!ws)
		return -ENOMEM;

	ret = lc_dilithium_ed448_keypair(&ws->pk, &ws->sk, lc_seeded_rng,
					 DILITHIUM_TYPE);
	if (ret)
		goto out;

	ret = lc_test_siggen(LC_DILITHIUM_IMPL_NAME, &ws->sk, ws->sig, ws->msg,
			     sizeof(ws->msg));
	if (ret)
		goto out;

	ret = lc_test_sigver(LC_DILITHIUM_IMPL_NAME, &ws->pk, ws->sig, ws->msg,
			     sizeof(ws->msg));
	if (ret)
		goto out;

	pr_info("Dilithium " LC_DILITHIUM_IMPL_NAME
		" invocation via kernel crypto API succeeded\n");

out:
	free_zero(ws);
	return ret;
}

static int __init leancrypto_kernel_dilithium_test_init(void)
{
	return lc_dilithium_tester();
}

static void __exit leancrypto_kernel_dilithium_test_exit(void)
{
}

module_init(leancrypto_kernel_dilithium_test_init);
module_exit(leancrypto_kernel_dilithium_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION(
	"Kernel module leancrypto_kernel_dilithium_test for implementation " LC_DILITHIUM_IMPL_NAME);
