// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include <linux/module.h>

#include "testfunctions.h"

#define LC_EXEC_ONE_TEST(function)					       \
	ret += leancrypto_tester_one(function, #function)

static int __init leancrypto_tester_one(int (*func)(void), const char *name)
{
	int ret;

	pr_info("Executing test case %s\n", name);
	ret = func();
	if (ret)
		pr_err("Test case %s failed\n", name);
	else
		pr_info("Test case %s succeeded\n", name);

	return ret;
}

static int __init leancrypto_tester_init(void)
{
	int ret = 0;

	LC_EXEC_ONE_TEST(cc_tester_cshake_validate);
	LC_EXEC_ONE_TEST(cc_tester_cshake);
	LC_EXEC_ONE_TEST(hc_tester_sha512);
	LC_EXEC_ONE_TEST(kc_tester_kmac_validate);
	LC_EXEC_ONE_TEST(kc_tester_kmac);
	LC_EXEC_ONE_TEST(sh_nonaligned);
	LC_EXEC_ONE_TEST(sh_tester);
	LC_EXEC_ONE_TEST(kmac_128_tester);
	LC_EXEC_ONE_TEST(kmac_tester);
	LC_EXEC_ONE_TEST(kmac_xof_more_tester);
	LC_EXEC_ONE_TEST(kmac_xof_tester);
	LC_EXEC_ONE_TEST(chacha20_enc_selftest);
	LC_EXEC_ONE_TEST(chacha20_block_selftest);
	LC_EXEC_ONE_TEST(test_kw);
	LC_EXEC_ONE_TEST(test_encrypt_all);
	LC_EXEC_ONE_TEST(test_decrypt);
	LC_EXEC_ONE_TEST(test_ctr);
	LC_EXEC_ONE_TEST(test_encrypt_cbc);
	LC_EXEC_ONE_TEST(test_decrypt_cbc);
	LC_EXEC_ONE_TEST(hkdf_tester);
	LC_EXEC_ONE_TEST(kdf_ctr_tester);
	LC_EXEC_ONE_TEST(kdf_dpi_tester);
	LC_EXEC_ONE_TEST(kdf_fb_tester);
	LC_EXEC_ONE_TEST(pbkdf2_tester);
	LC_EXEC_ONE_TEST(hmac_sha2_256_tester);
	LC_EXEC_ONE_TEST(hmac_sha2_512_tester);
	LC_EXEC_ONE_TEST(sha3_hmac_tester);
	LC_EXEC_ONE_TEST(cshake256_tester);
	LC_EXEC_ONE_TEST(cshake128_tester);
	LC_EXEC_ONE_TEST(shake128_tester);
	LC_EXEC_ONE_TEST(shake256_tester);
	LC_EXEC_ONE_TEST(sha512_tester);
	LC_EXEC_ONE_TEST(sha3_512_tester);
	LC_EXEC_ONE_TEST(sha3_256_tester);
	LC_EXEC_ONE_TEST(sha3_224_tester);
	LC_EXEC_ONE_TEST(sha256_tester);
	LC_EXEC_ONE_TEST(shake_sqeeze_more_tester);
	LC_EXEC_ONE_TEST(chacha20_tester);
	LC_EXEC_ONE_TEST(kmac_test);
	LC_EXEC_ONE_TEST(hmac_drbg_tester);
	LC_EXEC_ONE_TEST(hash_drbg_tester);
	LC_EXEC_ONE_TEST(cshake_drng_test);
	LC_EXEC_ONE_TEST(dilitium_tester);
	LC_EXEC_ONE_TEST(dilithium_invalid);
	LC_EXEC_ONE_TEST(kyber_kem_tester);
	LC_EXEC_ONE_TEST(kyber_kex_tester);
	LC_EXEC_ONE_TEST(kyber_ies_tester);
	LC_EXEC_ONE_TEST(kyber_invalid);
	LC_EXEC_ONE_TEST(status_tester);

	if (ret) {
		pr_err("leancrypto tests failed: total of %d tests failed\n",
		       ret);
		return -EFAULT;
	}

	pr_info("all leancrypto tests passed\n");
	return 0;
}

static void __exit leancrypto_tester_exit(void)
{

}

module_init(leancrypto_tester_init);
module_exit(leancrypto_tester_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto");

