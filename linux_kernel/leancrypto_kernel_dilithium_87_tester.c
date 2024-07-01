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

#include <crypto/akcipher.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

#ifdef LC_DILITHIUM_TYPE_65
#include "../signature/tests/dilithium_tester_vectors_65.h"
#define LC_DILITHIUM_IMPL_NAME "dilithium65-leancrypto"
#elif defined LC_DILITHIUM_TYPE_44
#include "../signature/tests/dilithium_tester_vectors_44.h"
#define LC_DILITHIUM_IMPL_NAME "dilithium44-leancrypto"
#else
#include "../signature/tests/dilithium_tester_vectors_87.h"
#define LC_DILITHIUM_IMPL_NAME "dilithium87-leancrypto"
#endif

/*
 * kzfree was renamed to kfree_sensitive in 5.9
 */
#undef free_zero
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#define free_zero(x) kfree_sensitive(x)
#else
#define free_zero(x) kzfree(x)
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

static int lc_test_sigver(const char *algname,
			  const struct dilithium_testvector *vector)
{
	struct crypto_akcipher *tfm = NULL;
	struct lc_akcipher_def akcipher;
	struct akcipher_request *req = NULL;
	struct scatterlist src, dst;
	u8 *msg = NULL, *sig = NULL;
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

	err = crypto_akcipher_set_pub_key(tfm, vector->pk, sizeof(vector->pk));
	if (err)
		goto err;

	pr_info("input datasize: %u\n", crypto_akcipher_maxsize(tfm));

	akcipher.tfm = tfm;
	akcipher.req = req;

	/*
	 * Copy the message from the r/o buffer as otherwise it cannot be mapped
	 * by the SG-handling logic.
	 */
	sig = kmalloc(sizeof(vector->sig), GFP_KERNEL);
	if (!sig) {
		err = -ENOMEM;
		goto err;
	}
	memcpy(sig, vector->sig, sizeof(vector->sig));
	sg_init_one(&src, sig, sizeof(vector->sig));

	/*
	 * Copy the message from the r/o buffer as otherwise it cannot be mapped
	 * by the SG-handling logic.
	 */
	msg = kmalloc(sizeof(vector->m), GFP_KERNEL);
	if (!msg) {
		err = -ENOMEM;
		goto err;
	}
	memcpy(msg, vector->m, sizeof(vector->m));
	sg_init_one(&dst, msg, sizeof(vector->m));

	akcipher_request_set_crypt(req, &src, &dst, sizeof(vector->sig),
				   sizeof(vector->m));

	err = crypto_akcipher_verify(req);

	lc_akcipher_wait(&akcipher, err);

	pr_info("Signature verification result %d\n", err);

err:
	free_zero(msg);
	free_zero(sig);
	if (req)
		akcipher_request_free(req);
	if (tfm)
		crypto_free_akcipher(tfm);
	return err;
}

static int lc_test_siggen(const char *algname,
			  const struct dilithium_testvector *vector, u8 *sig,
			  size_t siglen)
{
	struct crypto_akcipher *tfm = NULL;
	struct lc_akcipher_def akcipher;
	struct akcipher_request *req = NULL;
	struct scatterlist src, dst;
	u8 *msg = NULL;
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

	err = crypto_akcipher_set_priv_key(tfm, vector->sk, sizeof(vector->sk));
	if (err)
		goto err;

	pr_info("output datasize: %u\n", crypto_akcipher_maxsize(tfm));
	if (siglen < crypto_akcipher_maxsize(tfm)) {
		err = -EOVERFLOW;
		goto err;
	}

	akcipher.tfm = tfm;
	akcipher.req = req;

	/*
	 * Copy the message from the r/o buffer as otherwise it cannot be mapped
	 * by the SG-handling logic.
	 */
	msg = kmalloc(sizeof(vector->m), GFP_KERNEL);
	if (!msg) {
		err = -ENOMEM;
		goto err;
	}
	memcpy(msg, vector->m, sizeof(vector->m));
	sg_init_one(&src, msg, sizeof(vector->m));

	sg_init_one(&dst, sig, crypto_akcipher_maxsize(tfm));
	akcipher_request_set_crypt(req, &src, &dst, sizeof(vector->m),
				   crypto_akcipher_maxsize(tfm));

	err = crypto_akcipher_sign(req);
	lc_akcipher_wait(&akcipher, err);

	pr_info("Dilithium signature generation result %d\n", err);

err:
	free_zero(msg);
	if (req)
		akcipher_request_free(req);
	if (tfm)
		crypto_free_akcipher(tfm);
	return err;
}

static int lc_dilithium_tester(void)
{
	static const struct dilithium_testvector *vector =
		&dilithium_testvectors[0];
	size_t siglen = sizeof(vector->sig);
	u8 *sig;
	int ret;

	sig = kmalloc(siglen, GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	ret = lc_test_siggen(LC_DILITHIUM_IMPL_NAME, vector, sig, siglen);
	if (ret)
		goto out;

	/*
	 * memcmp is not possible as we use lc_seeded_rng causing a different
	 * signature for each invocation. When using NULL as the RNG context
	 * in sig gen, this can be enabled.
	 */
#if 0
	if (memcmp(sig, vector->sig, siglen)) {
		char hex[2 * siglen];

		pr_err("Calculated signature does not match expected signature\n");

		memset(hex, 0, sizeof(hex));
		bin2hex(hex, sig, siglen);
		pr_err("hex string: %s\n", hex);

		ret = -EINVAL;
		goto out;
	}
#endif

	ret = lc_test_sigver(LC_DILITHIUM_IMPL_NAME, vector);
	if (ret)
		goto out;

	pr_info("Dilithium " LC_DILITHIUM_IMPL_NAME
		" invocation via kernel crypto API succeeded\n");

out:
	free_zero(sig);
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
