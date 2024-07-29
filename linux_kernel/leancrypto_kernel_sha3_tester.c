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

#include <crypto/hash.h>
#include <linux/module.h>

#include "leancrypto_kernel.h"

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct sdesc *lc_init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc)
		return ERR_PTR(-ENOMEM);
	sdesc->shash.tfm = alg;
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
	sdesc->shash.flags = 0x0;
#endif
	return sdesc;
}

static int lc_test_hash(const char *algname, const u8 *msg, size_t msglen,
			const u8 *key, u8 keylen, u8 *digest, size_t digestlen)
{
	int ret;
	struct crypto_shash *tfm;
	struct sdesc *sdesc = NULL;

	/*
	 * We explicitly do not check the input buffer as we allow
	 * an empty string.
	 */

	/* allocate synchronous hash */
	tfm = crypto_alloc_shash(algname, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate digest TFM handle for %s\n",
			algname);
		return PTR_ERR(tfm);
	}

	if (digestlen < crypto_shash_digestsize(tfm))
		return -EOVERFLOW;

	/* make room for scratch memory */
	sdesc = lc_init_sdesc(tfm);
	if (!sdesc) {
		goto out;
	}

	if (keylen) {
		pr_err("set key for MAC\n");
		ret = crypto_shash_setkey(tfm, key, keylen);
		if (ret < 0)
			goto out;
	}

	ret = crypto_shash_init(&sdesc->shash);
	if (ret)
		goto out;

	ret = crypto_shash_update(&sdesc->shash, msg, msglen);
	if (ret)
		goto out;

	ret = crypto_shash_final(&sdesc->shash, digest);

out:
	free_zero(sdesc);
	crypto_free_shash(tfm);
	return ret;
}

static int lc_hash_sha3(void)
{
	static const u8 msg_512[] = { 0x82, 0xD9, 0x19 };
	static const u8 exp_512[] = {
		0x76, 0x75, 0x52, 0x82, 0xA9, 0xC5, 0x0A, 0x67, 0xFE, 0x69,
		0xBD, 0x3F, 0xCE, 0xFE, 0x12, 0xE7, 0x1D, 0xE0, 0x4F, 0xA2,
		0x51, 0xC6, 0x7E, 0x9C, 0xC8, 0x5C, 0x7F, 0xAB, 0xC6, 0xCC,
		0x89, 0xCA, 0x9B, 0x28, 0x88, 0x3B, 0x2A, 0xDB, 0x22, 0x84,
		0x69, 0x5D, 0xD0, 0x43, 0x77, 0x55, 0x32, 0x19, 0xC8, 0xFD,
		0x07, 0xA9, 0x4C, 0x29, 0xD7, 0x46, 0xCC, 0xEF, 0xB1, 0x09,
		0x6E, 0xDE, 0x42, 0x91
	};
	u8 digest[sizeof(exp_512)];
	int ret;

	ret = lc_test_hash("sha3-512-leancrypto", msg_512, sizeof(msg_512),
			   NULL, 0, digest, sizeof(digest));
	if (ret)
		return ret;

	if (memcmp(digest, exp_512, sizeof(exp_512)))
		return -EINVAL;

	pr_info("SHA-3 invocation via kernel crypto API succeeded\n");

	return 0;
}

static int __init leancrypto_kernel_sha3_test_init(void)
{
	return lc_hash_sha3();
}

static void __exit leancrypto_kernel_sha3_test_exit(void)
{
}

module_init(leancrypto_kernel_sha3_test_init);
module_exit(leancrypto_kernel_sha3_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_sha3_test");
