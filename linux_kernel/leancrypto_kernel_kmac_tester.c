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
#include <linux/version.h>

/*
 * kzfree was renamed to kfree_sensitive in 5.9
 */
#undef free_zero
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
#define free_zero(x) kfree_sensitive(x)
#else
#define free_zero(x) kzfree(x)
#endif

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
	static const u8 msg1[] = { 0x6F, 0x50, 0xA7, 0xC3, 0x48, 0xCE, 0xA5,
				   0x10, 0x6A, 0xBE, 0x32, 0xE4, 0xF0, 0x9E,
				   0x7B, 0xC6, 0x0E, 0x5F, 0x8F, 0xE1, 0x17,
				   0xF9, 0x41, 0x29, 0x73, 0xC2, 0xAC, 0x0E,
				   0xD6, 0x87, 0xCD, 0x41, 0x99, 0xB7, 0xCD,
				   0x5B, 0x89, 0xA4, 0x02, 0x82, 0xD8, 0x54,
				   0x51 };
	static const u8 key1[] = {
		0x04, 0xBB, 0xB3, 0xF4, 0x84, 0x74, 0x25, 0x97, 0x72, 0xD8,
		0xF0, 0x78, 0x3C, 0xAC, 0x31, 0x67, 0x4B, 0x50, 0x7D, 0x64,
		0xBB, 0xC3, 0xED, 0x98, 0xE4, 0x23, 0xEF, 0xEC, 0xA6, 0xD1,
		0x68, 0xD1, 0x8F, 0x36, 0xED, 0x5A, 0xDB, 0x0E, 0xFD, 0x8C,
		0x3A, 0x43, 0x91, 0x2F, 0x32, 0x9C, 0xF0, 0x4B, 0x75, 0x4A,
		0xD3, 0xEA, 0xAA, 0xE4, 0x88, 0xF2, 0x15, 0x8F, 0x02, 0x82,
		0x01, 0x60, 0xDB, 0x03, 0x08, 0x23, 0x14, 0x2D, 0xF7, 0xA6,
		0xB2, 0x1F, 0x3B, 0x28, 0x48, 0x44, 0xB5, 0x03, 0x28, 0xE6,
		0xA5, 0xF1, 0x4C, 0x81, 0xD4, 0x70, 0xF5, 0xA4, 0x64, 0xE4,
		0x00, 0x8D, 0x2D, 0x38, 0xB4, 0x83, 0x87
	};
	static const u8 exp1[] = {
		0xa3, 0x45, 0xa5, 0x37, 0xdf, 0xc0, 0x19, 0xef, 0x63, 0xda,
		0x33, 0x65, 0x73, 0xe8, 0xcf, 0x33, 0xdf, 0x3d, 0xe3, 0xca,
		0x14, 0x7f, 0x7d, 0xf6, 0x9c, 0x16, 0x78, 0x8a, 0xb7, 0x5d,
		0x59, 0x1e, 0xd8, 0x4c, 0x06, 0x70, 0xa9, 0x38, 0xc8, 0xa3,
		0xa9, 0xee, 0xf2, 0xd6, 0xb1, 0xa7, 0x1d, 0x69, 0x8b, 0x49,
		0x2a, 0xd0, 0x89, 0x38, 0xef, 0x0f, 0x62, 0xba, 0x25, 0x3a,
		0x01, 0xe9, 0x4b, 0xca
	};
	u8 digest[sizeof(exp1)];
	int ret;

	ret = lc_test_hash("kmac256xof-512-leancrypto", msg1, sizeof(msg1),
			   key1, sizeof(key1), digest, sizeof(digest));
	if (ret)
		return ret;

	if (memcmp(digest, exp1, sizeof(exp1)))
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
