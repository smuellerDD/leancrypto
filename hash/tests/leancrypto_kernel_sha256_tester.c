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

static int lc_hash_sha256(void)
{
	static const uint8_t msg_256[] = { 0x06, 0x3A, 0x53 };
	static const uint8_t exp_256[] = { 0x8b, 0x05, 0x65, 0x59, 0x60, 0x71,
					   0xc7, 0x6e, 0x35, 0xe1, 0xea, 0x54,
					   0x48, 0x39, 0xe6, 0x47, 0x27, 0xdf,
					   0x89, 0xb4, 0xde, 0x27, 0x74, 0x44,
					   0xa7, 0x7f, 0x77, 0xcb, 0x97, 0x89,
					   0x6f, 0xf4 };
	u8 digest[sizeof(exp_256)];
	int ret;

	ret = lc_test_hash("sha256-leancrypto", msg_256, sizeof(msg_256), NULL,
			   0, digest, sizeof(digest));
	if (ret)
		return ret;

	if (memcmp(digest, exp_256, sizeof(exp_256)))
		return -EINVAL;

	pr_info("SHA-256 invocation via kernel crypto API succeeded\n");

	return 0;
}

static int __init leancrypto_kernel_sha256_test_init(void)
{
	return lc_hash_sha256();
}

static void __exit leancrypto_kernel_sha256_test_exit(void)
{
}

module_init(leancrypto_kernel_sha256_test_init);
module_exit(leancrypto_kernel_sha256_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_sha256_test");
