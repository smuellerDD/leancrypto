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

#include <crypto/rng.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/version.h>

static int lc_rng_test(void)
{
	struct crypto_rng *rng;
	u8 outbuf[50], hex[2 * sizeof(outbuf) + 1];
	int ret;

	rng = crypto_alloc_rng("xdrbg256-leancrypto", 0, 0);
	if (IS_ERR(rng)) {
		pr_err("DRNG xdrbg256-leancrypto cannot be allocated\n");
		ret = PTR_ERR(rng);
		goto free;
	}

	ret = crypto_rng_reset(rng, NULL, crypto_rng_seedsize(rng));
	if (ret)
		goto free;

	ret = crypto_rng_get_bytes(rng, outbuf, sizeof(outbuf));
	if (ret)
		goto free;

	memset(hex, 0, sizeof(hex));
	bin2hex(hex, outbuf, sizeof(outbuf));
	printk("generated rng data: %s\n", hex);

	pr_info("XDRBG invocation via kernel crypto API succeeded\n");

free:
	crypto_free_rng(rng);
	return ret;
}

static int __init leancrypto_kernel_rng_test_init(void)
{
	return lc_rng_test();
}

static void __exit leancrypto_kernel_rng_test_exit(void)
{

}

module_init(leancrypto_kernel_rng_test_init);
module_exit(leancrypto_kernel_rng_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_sha3_test");

