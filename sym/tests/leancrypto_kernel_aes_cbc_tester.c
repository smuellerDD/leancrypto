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

#include <linux/version.h>
#include <crypto/skcipher.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

struct lc_aes_cbc_test_res {
	struct completion completion;
	int err;
};

/* tie all data structures together */
struct lc_aes_cbc_test_def {
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	struct lc_aes_cbc_test_res result;
};

/* Callback function */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
static void lc_aes_cbc_test_cb(struct crypto_async_request *req, int error)
{
#else
static void lc_aes_cbc_test_cb(void *data, int error)
{
	struct crypto_async_request *req = data;
#endif
	struct lc_aes_cbc_test_res *result = req->data;

	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
	pr_info("Encryption finished successfully\n");
}

/* Perform encryption or decryption */
static unsigned int lc_aes_cbc_test_encdec(struct lc_aes_cbc_test_def *aes_cbc,
					   int enc)
{
	int rc = 0;

	init_completion(&aes_cbc->result.completion);

	if (enc)
		rc = crypto_skcipher_encrypt(aes_cbc->req);
	else
		rc = crypto_skcipher_decrypt(aes_cbc->req);

	switch (rc) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&aes_cbc->result.completion);
		rc = aes_cbc->result.err;
		if (!aes_cbc->result.err)
			reinit_completion(&aes_cbc->result.completion);
		break;
	default:
		pr_info("skcipher cipher operation returned with %d result"
			" %d\n",
			rc, aes_cbc->result.err);
		break;
	}

	return rc;
}

/*
 * Skcipher operation
 * input: type
 * input: name
 * input: plaintext / ciphertext
 * input: key
 * input: IV
 * output: ciphertext / plaintext
 *
 * Note: for decryption, the data->data will contain deadbeef if the
 *	 authentication failed.
 */
static int lc_aes_cbc_test(const char *name, const uint8_t *data, size_t inlen,
			   const uint8_t *in_iv, size_t ivlen,
			   const uint8_t *key, size_t keylen,
			   const uint8_t *exp_ct)
{
	int ret = -EFAULT;
	struct lc_aes_cbc_test_def aes_cbc;
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg_in[5], sg_out[6];
	u8 *out_enc = NULL, *out_dec = NULL, *in = NULL, *iv = NULL;

	in = kmalloc(inlen, GFP_KERNEL);
	if (!in) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(in, data, inlen);

	iv = kmalloc(ivlen, GFP_KERNEL);
	if (!in) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(iv, in_iv, ivlen);

	tfm = crypto_alloc_skcipher(name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate skcipher handle for %s %ld\n", name,
			PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}

	out_enc = kzalloc(inlen, GFP_KERNEL);
	if (IS_ERR(out_enc)) {
		pr_info("could not allocate out_enc\n");
		ret = PTR_ERR(out_enc);
		goto out;
	}

	out_dec = kzalloc(inlen, GFP_KERNEL);
	if (IS_ERR(out_dec)) {
		pr_info("could not allocate out_dec\n");
		ret = PTR_ERR(out_dec);
		goto out;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (IS_ERR(req)) {
		pr_info("could not allocate request queue\n");
		ret = PTR_ERR(req);
		goto out;
	}

	ret = crypto_skcipher_setkey(tfm, key, keylen);
	if (ret) {
		pr_info("key could not be set %d\n", ret);
		goto out;
	}

	aes_cbc.tfm = tfm;
	aes_cbc.req = req;

	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      lc_aes_cbc_test_cb, &aes_cbc.result);

	if (!virt_addr_valid(in)) {
		printk("Invalid virtual address for in\n");
		ret = -EINVAL;
		goto out;
	}
	if (!virt_addr_valid(out_enc)) {
		printk("Invalid virtual address for out_enc\n");
		ret = -EINVAL;
		goto out;
	}

	/* Encrypt */
	sg_init_table(sg_in, 1);
	sg_set_buf(&sg_in[0], in, inlen);

	sg_init_table(sg_out, 1);
	sg_set_buf(&sg_out[0], out_enc, inlen);

	skcipher_request_set_crypt(req, sg_in, sg_out, inlen, iv);

	ret = lc_aes_cbc_test_encdec(&aes_cbc, 1);
	if (0 > ret) {
		pr_info("skcipher encryption failed: %d\n", ret);
		goto out;
	}

	if (memcmp(out_enc, exp_ct, inlen)) {
		pr_info("Enc: ciphertext mismatch\n");
		ret = -EFAULT;
		goto out;
	}

	/* Decrypt */
	sg_init_table(sg_in, 1);
	sg_set_buf(&sg_in[0], out_enc, inlen);

	sg_init_table(sg_out, 1);
	sg_set_buf(&sg_out[0], out_dec, inlen);

	skcipher_request_set_crypt(req, sg_in, sg_out, inlen, iv);

	ret = lc_aes_cbc_test_encdec(&aes_cbc, 0);
	if (0 > ret) {
		pr_info("AEAD decryption failed: %d\n", ret);
		goto out;
	}

	if (memcmp(out_dec, in, inlen)) {
		pr_info("Dec: plaintext mismatch\n");
		ret = -EFAULT;
		goto out;
	}

	ret = 0;
	pr_info("Testing successful\n");

out:
	if (iv)
		kfree(iv);
	if (in)
		kfree(in);
	if (out_enc)
		kfree(out_enc);
	if (out_dec)
		kfree(out_dec);
	if (tfm)
		crypto_free_skcipher(tfm);
	if (req)
		skcipher_request_free(req);
	return ret;
}

static int aes_cbc_tester(void)
{
	static const uint8_t key256[] = {
		0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71,
		0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
		0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b,
		0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
		0x09, 0x14, 0xdf, 0xf4
	};
	static uint8_t pt256[] = {
		0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
		0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
		0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
		0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
		0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
		0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
		0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
		0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
	};
	static const uint8_t ct256[] = {
		0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab,
		0xfb, 0x5f, 0x7b, 0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb,
		0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d, 0x39,
		0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63,
		0x04, 0x23, 0x14, 0x61, 0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9,
		0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
	};
	static const uint8_t iv256[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f
	};

	pr_info("AES CBC 256 crypt\n");
	return lc_aes_cbc_test("cbc-aes-leancrypto", pt256, sizeof(pt256),
			       iv256, sizeof(iv256), key256, sizeof(key256),
			       ct256);
}

static int __init leancrypto_kernel_aes_cbc_test_init(void)
{
	return aes_cbc_tester();
}

static void __exit leancrypto_kernel_aes_cbc_test_exit(void)
{
}

module_init(leancrypto_kernel_aes_cbc_test_init);
module_exit(leancrypto_kernel_aes_cbc_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_aes_cbc_test");
