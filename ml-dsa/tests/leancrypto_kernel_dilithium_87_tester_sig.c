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

#include <crypto/sig.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/version.h>

#ifdef LC_DILITHIUM_TYPE_65
#include "../ml-dsa/tests/dilithium_tester_vectors_65.h"
#define LC_DILITHIUM_IMPL_NAME "dilithium65-leancrypto"
#elif defined LC_DILITHIUM_TYPE_44
#include "../ml-dsa/tests/dilithium_tester_vectors_44.h"
#define LC_DILITHIUM_IMPL_NAME "dilithium44-leancrypto"
#else
#include "../ml-dsa/tests/dilithium_tester_vectors_87.h"
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

static int lc_test_sigver(const char *algname,
			  const struct dilithium_testvector *vector)
{
	struct crypto_sig *tfm = NULL;
	int err = -ENOMEM;

	tfm = crypto_alloc_sig(algname, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate sig handle for %s %ld\n", algname,
			PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = crypto_sig_set_pubkey(tfm, vector->pk, sizeof(vector->pk));
	if (err)
		goto err;

	err = crypto_sig_verify(tfm, vector->sig, sizeof(vector->sig),
				vector->m, sizeof(vector->m));

	pr_info("Signature verification result %d\n", err);

err:
	if (tfm)
		crypto_free_sig(tfm);
	return err;
}

static int lc_test_siggen(const char *algname,
			  struct dilithium_testvector *vector)
{
	struct crypto_sig *tfm = NULL;
	int err = -ENOMEM;

	tfm = crypto_alloc_sig(algname, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate sig handle for %s %ld\n", algname,
			PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = crypto_sig_set_privkey(tfm, vector->sk, sizeof(vector->sk));
	if (err)
		goto err;

	err = crypto_sig_sign(tfm, vector->m, sizeof(vector->m), vector->sig,
			      sizeof(vector->sig));

	pr_info("Dilithium signature generation result %d\n", err);

err:
	if (tfm)
		crypto_free_sig(tfm);
	return err;
}

static int lc_dilithium_tester(void)
{
	static const struct dilithium_testvector *vector =
		&dilithium_testvectors[0];
	struct dilithium_testvector *v = NULL;
	int ret;

	v = kmalloc(sizeof(*v), GFP_KERNEL);
	if (!v) {
		ret = -ENOMEM;
		goto out;
	}
	/*
	 * Copy the data from the r/o buffer as otherwise it cannot be mapped
	 * by the SG-handling logic.
	 */
	memcpy(v->m, vector->m, sizeof(v->m));
	memcpy(v->pk, vector->pk, sizeof(v->pk));
	memcpy(v->sk, vector->sk, sizeof(v->sk));

	ret = lc_test_siggen(LC_DILITHIUM_IMPL_NAME, v);
	if (ret) {
		pr_err("Generation of signature failed\n");
		goto out;
	}

	ret = lc_test_sigver(LC_DILITHIUM_IMPL_NAME, v);
	if (ret) {
		pr_err("Verification of generated signature failed\n");
		goto out;
	}

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

	pr_info("Dilithium " LC_DILITHIUM_IMPL_NAME
		" invocation via kernel crypto API succeeded\n");

out:
	if (v)
		free_zero(v);
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
