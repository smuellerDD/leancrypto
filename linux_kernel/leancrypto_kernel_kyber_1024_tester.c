// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include <linux/version.h>
#include <crypto/kpp.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

#ifdef LC_KYBER_TYPE_768
#include "../ml-kem/tests/kyber_kem_tester_vectors_768.h"
#define LC_KYBER_IMPL_NAME "kyber768-leancrypto"
#elif defined LC_KYBER_TYPE_512
#include "../ml-kem/tests/kyber_kem_tester_vectors_512.h"
#define LC_KYBER_IMPL_NAME "kyber512-leancrypto"
#else
#include "../ml-kem/tests/kyber_kem_tester_vectors_1024.h"
#define LC_KYBER_IMPL_NAME "kyber1024-leancrypto"
#endif

struct lc_tcrypt_res {
	struct completion completion;
	int err;
};

/* tie all data structures together */
struct lc_kpp_def {
	struct crypto_kpp *tfm;
	struct kpp_request *req;
	struct lc_tcrypt_res result;
};

/* Callback function */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6,3,0)
static void lc_kpp_cb(struct crypto_async_request *req, int error)
{
#else
static void lc_kpp_cb(void *data, int error)
{
        struct crypto_async_request *req = data;
#endif
	struct lc_tcrypt_res *result = req->data;

	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
	pr_info("Kyber operation finished successfully\n");
}

/* Perform KPP operation */
static unsigned int lc_kpp_op(struct lc_kpp_def *kpp, int gen_ss)
{
	int rc = 0;

	init_completion(&kpp->result.completion);

	if (gen_ss)
		rc = crypto_kpp_compute_shared_secret(kpp->req);
	else
		rc = crypto_kpp_generate_public_key(kpp->req);

	switch (rc) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&kpp->result.completion);
		rc = kpp->result.err;
		if (!kpp->result.err) {
			reinit_completion(&kpp->result.completion);
		}
		break;
	default:
		pr_err("kpp cipher operation returned with %d result"
		       " %d\n",
		       rc, kpp->result.err);
		break;
	}

	return rc;
}

static int lc_kyber_ss(const char *algname)
{
	struct lc_kpp_def kpp;
	struct crypto_kpp *tfm = NULL;
	struct kpp_request *req = NULL;
	struct scatterlist src, dst;
	struct lc_kyber_ct *ct = NULL;
	struct lc_kyber_pk *pk = NULL;
	u8 *ss1, *ss2;
	int err = -ENOMEM;

	tfm = crypto_alloc_kpp(algname, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate kpp handle for %s %ld\n", algname,
			PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	if (crypto_kpp_maxsize(tfm) != LC_CRYPTO_CIPHERTEXTBYTES) {
		pr_err("crypto_kpp_maxsize returns wrong size: %u vs %u\n",
		       crypto_kpp_maxsize(tfm), LC_CRYPTO_CIPHERTEXTBYTES);
		err = -EINVAL;
		goto out;
	}

	ct = kmalloc(sizeof(struct lc_kyber_ct), GFP_KERNEL);
	if (!ct) {
		err = -ENOMEM;
		pr_err("Cannot allocate Kyber CT\n");
		goto out;
	}

	pk = kmalloc(sizeof(struct lc_kyber_pk), GFP_KERNEL);
	if (!pk) {
		err = -ENOMEM;
		pr_err("Cannot allocate Kyber PK\n");
		goto out;
	}

	req = kpp_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		pr_err("Cannot allocate request\n");
		goto out;
	}

	ss1 = kmalloc(LC_KYBER_SSBYTES, GFP_KERNEL);
	if (!ss1) {
		err = -ENOMEM;
		pr_err("Cannot allocate BIKE PK\n");
		goto out;
	}

	ss2 = kmalloc(LC_KYBER_SSBYTES, GFP_KERNEL);
	if (!ss2) {
		err = -ENOMEM;
		pr_err("Cannot allocate BIKE PK\n");
		goto out;
	}


	kpp.tfm = tfm;
	kpp.req = req;

	/* Generate a new local key pair */
	err = crypto_kpp_set_secret(tfm, NULL, 0);
	if (err)
		goto out;

	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, lc_kpp_cb,
				 &kpp.result);

	/* Initiator: Obtain the PK */
	sg_init_one(&dst, pk->pk, sizeof(struct lc_kyber_pk));
	kpp_request_set_input(req, NULL, 0);
	kpp_request_set_output(req, &dst, sizeof(struct lc_kyber_pk));
	err = lc_kpp_op(&kpp, 0);
	pr_info("Initiator: Kyber PK extracted %d\n", err);
	if (err)
		goto out;

	/* Respopnder: Generate our local shared secret and obtain the CT */
	sg_init_one(&src, pk->pk, sizeof(struct lc_kyber_pk));
	sg_init_one(&dst, ct->ct, sizeof(struct lc_kyber_ct));
	kpp_request_set_input(req, &src, sizeof(struct lc_kyber_pk));
	kpp_request_set_output(req, &dst, sizeof(struct lc_kyber_ct));
	err = lc_kpp_op(&kpp, 0);
	pr_info("Responder: Kyber SS / CT generation and CT gathering result %d\n",
		err);
	if (err)
		goto out;

	/* Responder: Obtain the local shared secret */
	sg_init_one(&dst, ss1, LC_KYBER_SSBYTES);
	kpp_request_set_input(req, NULL, 0);
	kpp_request_set_output(req, &dst, LC_KYBER_SSBYTES);
	err = lc_kpp_op(&kpp, 1);
	pr_info("Responder: Kyber SS gathering result %d\n", err);
	if (err)
		goto out;

	/* Initiator: Generate the SS. */
	sg_init_one(&src, ct->ct, crypto_kpp_maxsize(tfm));
	sg_init_one(&dst, ss2, LC_KYBER_SSBYTES);
	kpp_request_set_input(req, &src, crypto_kpp_maxsize(tfm));
	kpp_request_set_output(req, &dst, LC_KYBER_SSBYTES);
	kpp_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, lc_kpp_cb,
				 &kpp.result);

	err = lc_kpp_op(&kpp, 1);
	pr_info("Initiator: Kyber shared secret generation result %d\n", err);
	if (err)
		goto out;

	/* Check that both shared secrets are identical */
	if (memcmp(ss1, ss2, LC_KYBER_SSBYTES)) {
		pr_err("Shared secrets mismatch\n");
		err = -EFAULT;
		goto out;
	}

	pr_info("Kyber SS generation test successful\n");

out:
	if (ss1)
		kfree(ss1);
	if (ss2)
		kfree(ss2);
	if (ct)
		kfree(ct);
	if (pk)
		kfree(pk);
	if (tfm)
		crypto_free_kpp(tfm);
	if (req)
		kpp_request_free(req);

	return err;
}

static int __init leancrypto_kernel_kyber_test_init(void)
{
	return lc_kyber_ss(LC_KYBER_IMPL_NAME);
}

static void __exit leancrypto_kernel_kyber_test_exit(void)
{
}

module_init(leancrypto_kernel_kyber_test_init);
module_exit(leancrypto_kernel_kyber_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION(
	"Kernel module leancrypto_kernel_kyber_test for implementation " LC_KYBER_IMPL_NAME);
