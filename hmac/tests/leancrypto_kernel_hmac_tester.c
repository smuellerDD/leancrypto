// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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
		pr_info("set key for MAC\n");
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

static int lc_hash_kmac(void)
{
	static const uint8_t msg_256[] = { 0xF2, 0xAA, 0xAA, 0x3A, 0x63, 0xD6,
					   0xE8, 0x10, 0xE7, 0xD1, 0x13, 0x57,
					   0xA0, 0x1E, 0xE7, 0xA6 };
	static const uint8_t key_256[] = {
		0x19, 0xC4, 0xAB, 0x40, 0xE3, 0x76, 0x3E, 0xF1, 0x24, 0x3F,
		0x77, 0xB3, 0xDB, 0x06, 0x0A, 0x86, 0xEF, 0xF0, 0xD5, 0x12,
		0x23, 0x00, 0xED, 0x7D, 0x8B, 0x25, 0x97, 0xC3, 0x18, 0x5C,
		0xE4, 0x23, 0x43, 0x4B, 0x91, 0xC3, 0x73, 0x3C, 0x2A, 0xC7,
		0xBC, 0xCE, 0x3A, 0x50, 0x54, 0x74, 0x36, 0x7F, 0x94, 0x2C,
		0xB3, 0x85, 0x42, 0x2A, 0xF1, 0xAA, 0x87, 0x1F, 0x7D, 0x0E,
		0x3E, 0xFA, 0xBF, 0x5E
	};
	static const uint8_t exp_256[] = { 0x69, 0xe3, 0x08, 0xca, 0x4a, 0x24,
					   0xac, 0xbe, 0xdf, 0x73, 0xd1, 0xb4,
					   0x67, 0x58, 0x70, 0x34, 0xe9, 0x49,
					   0x38, 0x33, 0x1b, 0xe8, 0xc2, 0x24,
					   0x02, 0x6c, 0x87, 0x8b, 0xae, 0x41,
					   0xb4, 0xcd };
	u8 digest[sizeof(exp_256)];
	int ret;

	ret = lc_test_hash("hmac-sha256-leancrypto", msg_256, sizeof(msg_256),
			   key_256, sizeof(key_256), digest, sizeof(digest));
	if (ret)
		return ret;

	if (memcmp(digest, exp_256, sizeof(exp_256)))
		return -EINVAL;

	pr_info("KMAC invocation via kernel crypto API succeeded\n");

	return 0;
}

static int __init leancrypto_kernel_kmac_test_init(void)
{
	return lc_hash_kmac();
}

static void __exit leancrypto_kernel_kmac_test_exit(void)
{
}

module_init(leancrypto_kernel_kmac_test_init);
module_exit(leancrypto_kernel_kmac_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_kmac_test");
