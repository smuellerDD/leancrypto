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

static int lc_hash_ascon_128(void)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = { 0x80, 0x13, 0xEA, 0xAA, 0x19, 0x51, 0x58,
				       0x0A, 0x7B, 0xEF, 0x7D, 0x29, 0xBA, 0xC3,
				       0x23, 0x37, 0x7E, 0x64, 0xF2, 0x79, 0xEA,
				       0x73, 0xE6, 0x88, 0x1B, 0x8A, 0xED, 0x69,
				       0x85, 0x5E, 0xF7, 0x64 };
	u8 digest[sizeof(exp)];
	int ret;

	ret = lc_test_hash("ascon-128-leancrypto", msg, sizeof(msg), NULL, 0,
			   digest, sizeof(digest));
	if (ret)
		return ret;

	if (memcmp(digest, exp, sizeof(exp)))
		return -EINVAL;

	pr_info("Ascon 128 invocation via kernel crypto API succeeded\n");

	return 0;
}

static int lc_hash_ascon_128a(void)
{
	static const uint8_t msg[] = { 0x00, 0x01, 0x02, 0x03 };
	static const uint8_t exp[] = { 0x7B, 0x4B, 0xD4, 0xD5, 0x73, 0x19, 0x66,
				       0x01, 0x0E, 0xA4, 0xF5, 0xF3, 0x6C, 0x74,
				       0x36, 0x11, 0x0C, 0x64, 0x19, 0x07, 0xD1,
				       0x2A, 0x1F, 0x12, 0x16, 0x92, 0x2D, 0xEB,
				       0xD6, 0x1B, 0x13, 0xFE };
	u8 digest[sizeof(exp)];
	int ret;

	ret = lc_test_hash("ascon-128a-leancrypto", msg, sizeof(msg), NULL, 0,
			   digest, sizeof(digest));
	if (ret)
		return ret;

	if (memcmp(digest, exp, sizeof(exp)))
		return -EINVAL;

	pr_info("Ascon 128a invocation via kernel crypto API succeeded\n");

	return 0;
}

static int __init leancrypto_kernel_ascon_test_init(void)
{
	int ret = lc_hash_ascon_128();

	if (ret)
		return ret;

	return lc_hash_ascon_128a();
}

static void __exit leancrypto_kernel_ascon_test_exit(void)
{
}

module_init(leancrypto_kernel_ascon_test_init);
module_exit(leancrypto_kernel_ascon_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_ascon_test");
