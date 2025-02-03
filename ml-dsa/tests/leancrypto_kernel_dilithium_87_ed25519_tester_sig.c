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

#include "lc_dilithium.h"
#include "leancrypto_kernel.h"

#ifdef LC_DILITHIUM_TYPE_65
#define DILITHIUM_TYPE LC_DILITHIUM_65
#define LC_DILITHIUM_IMPL_NAME "dilithium65-ed25519-leancrypto"
#elif defined LC_DILITHIUM_TYPE_44
#define DILITHIUM_TYPE LC_DILITHIUM_44
#define LC_DILITHIUM_IMPL_NAME "dilithium44-ed25519-leancrypto"
#else
#define DILITHIUM_TYPE LC_DILITHIUM_87
#define LC_DILITHIUM_IMPL_NAME "dilithium87-ed25519-leancrypto"
#endif

static int lc_test_sigver(const char *algname,
			  struct lc_dilithium_ed25519_pk *pk, uint8_t *sig,
			  uint8_t *msg, size_t msglen)
{
	struct crypto_sig *tfm = NULL;
	uint8_t *dilithium_ptr, *ed25519_ptr;
	size_t dilithium_len, ed25519_len;
	int err = -ENOMEM;

	tfm = crypto_alloc_sig(algname, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate sig handle for %s %ld\n",
			algname, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = lc_dilithium_ed25519_pk_ptr(&dilithium_ptr, &dilithium_len,
					  &ed25519_ptr, &ed25519_len, pk);
	if (err)
		goto err;

	if (dilithium_len + ed25519_len !=
	    lc_dilithium_ed25519_pk_size(DILITHIUM_TYPE)) {
		pr_info("Unexpected public key length: %zu %u\n",
			dilithium_len + ed25519_len,
			lc_dilithium_ed25519_pk_size(DILITHIUM_TYPE));
		err = -EFAULT;
		goto err;
	}

	/*
	 * NOTE: This only works because dilithium_ptr and ed25519_ptr
	 * are concatenated in a linear buffer.
	 */
	err = crypto_sig_set_pubkey(tfm, dilithium_ptr,
				    dilithium_len + ed25519_len);
	if (err)
		goto err;

	err = crypto_sig_verify(tfm, sig,
				lc_dilithium_ed25519_sig_size(DILITHIUM_TYPE),
				msg, msglen);

	pr_info("Signature verification result %d\n", err);

err:
	if (tfm)
		crypto_free_sig(tfm);
	return err;
}

static int lc_test_siggen(const char *algname,
			  struct lc_dilithium_ed25519_sk *sk, uint8_t *sig,
			  uint8_t *msg, size_t msglen)
{
	struct crypto_sig *tfm = NULL;
	uint8_t *dilithium_ptr, *ed25519_ptr;
	size_t dilithium_len, ed25519_len;
	int err = -ENOMEM;

	tfm = crypto_alloc_sig(algname, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate sig handle for %s %ld\n",
			algname, PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	err = lc_dilithium_ed25519_sk_ptr(&dilithium_ptr, &dilithium_len,
					  &ed25519_ptr, &ed25519_len, sk);
	if (err)
		goto err;

	if (dilithium_len + ed25519_len !=
	    lc_dilithium_ed25519_sk_size(DILITHIUM_TYPE)) {
		pr_info("Unexpected private key length: %zu %u\n",
			dilithium_len + ed25519_len,
			lc_dilithium_ed25519_sk_size(DILITHIUM_TYPE));
		err = -EFAULT;
		goto err;
	}

	/*
	 * NOTE: This only works because dilithium_sk_ptr and ed25519_sk_ptr
	 * are concatenated in a linear buffer.
	 */
	err = crypto_sig_set_privkey(tfm, dilithium_ptr,
				     dilithium_len + ed25519_len);
	if (err)
		goto err;

	err = crypto_sig_sign(tfm, msg, msglen, sig,
			      lc_dilithium_ed25519_sig_size(DILITHIUM_TYPE));

	pr_info("Dilithium signature generation result %d\n", err);

err:
	if (tfm)
		crypto_free_sig(tfm);
	return err;
}

static int lc_dilithium_tester(void)
{
	struct workspace {
		struct lc_dilithium_ed25519_pk pk;
		struct lc_dilithium_ed25519_sk sk;
		uint8_t msg[10];
		uint8_t sig[];
	};
	struct workspace *ws;
	int ret;

	ws = kzalloc(sizeof(struct workspace) +
			     lc_dilithium_ed25519_sig_size(DILITHIUM_TYPE),
		     GFP_KERNEL);
	if (!ws)
		return -ENOMEM;

	ret = lc_dilithium_ed25519_keypair(&ws->pk, &ws->sk, lc_seeded_rng,
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
