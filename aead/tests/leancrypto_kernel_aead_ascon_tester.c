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

#include <linux/version.h>
#include <crypto/aead.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/scatterlist.h>

struct lc_aead_test_res {
	struct completion completion;
	int err;
};

/* tie all data structures together */
struct lc_aead_test_def {
	struct crypto_aead *tfm;
	struct aead_request *req;
	struct lc_aead_test_res result;
};

/* Callback function */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
static void lc_aead_test_cb(struct crypto_async_request *req, int error)
{
#else
static void lc_aead_test_cb(void *data, int error)
{
	struct crypto_async_request *req = data;
#endif
	struct lc_aead_test_res *result = req->data;

	if (error == -EINPROGRESS)
		return;
	result->err = error;
	complete(&result->completion);
	pr_info("Encryption finished successfully\n");
}

/* Perform encryption or decryption */
static unsigned int lc_aead_test_encdec(struct lc_aead_test_def *aead, int enc)
{
	int rc = 0;

	init_completion(&aead->result.completion);

	if (enc)
		rc = crypto_aead_encrypt(aead->req);
	else
		rc = crypto_aead_decrypt(aead->req);

	switch (rc) {
	case 0:
		break;
	case -EINPROGRESS:
	case -EBUSY:
		wait_for_completion(&aead->result.completion);
		rc = aead->result.err;
		if (!aead->result.err)
			reinit_completion(&aead->result.completion);
		break;
	default:
		pr_info("aead cipher operation returned with %d result"
			" %d\n",
			rc, aead->result.err);
		break;
	}

	return rc;
}

/*
 * AEAD operation
 * input: type
 * input: name
 * input: plaintext / ciphertext in kccavs_test->data
 * input: AuthTag is appended to ciphertext
 * input: Authsize
 * input: key in kccavs_test->key
 * input: IV in kccavs_test->iv
 * input: associated data in kccavs_test->aead_assoc
 * output: ciphertext / plaintext in kccavs_test->data
 *
 * Note: for decryption, the data->data will contain deadbeef if the
 *	 authentication failed.
 */
static int lc_aead_test(const char *name, const uint8_t *data, size_t inlen,
			uint8_t *nonce, size_t noncelen, const uint8_t *aad_in,
			size_t aadlen, const uint8_t *key, size_t keylen,
			const uint8_t *exp_ct, const uint8_t *exp_tag,
			size_t exp_tag_len)
{
	int ret = -EFAULT;
	struct lc_aead_test_def aead;
	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg_in[5], sg_out[5];
	u8 *out_enc = NULL, *out_dec = NULL, *aad = NULL, *in = NULL,
	   *tag = NULL;

	if (noncelen != 16)
		return -EINVAL;

	aad = kmalloc(aadlen, GFP_KERNEL);
	if (!aad)
		return -ENOMEM;
	memcpy(aad, aad_in, aadlen);

	in = kmalloc(inlen, GFP_KERNEL);
	if (!in) {
		ret = -ENOMEM;
		goto out;
	}
	memcpy(in, data, inlen);

	tag = kmalloc(exp_tag_len, GFP_KERNEL);
	if (!tag) {
		ret = -ENOMEM;
		goto out;
	}

	tfm = crypto_alloc_aead(name, 0, 0);
	if (IS_ERR(tfm)) {
		pr_info("could not allocate aead handle for %s %ld\n", name,
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

	req = aead_request_alloc(tfm, GFP_KERNEL);
	if (IS_ERR(req)) {
		pr_info("could not allocate request queue\n");
		ret = PTR_ERR(req);
		goto out;
	}

	ret = crypto_aead_setkey(tfm, key, keylen);
	if (ret) {
		pr_info("key could not be set %d\n", ret);
		goto out;
	}

	ret = crypto_aead_setauthsize(tfm, exp_tag_len);
	if (ret) {
		pr_info("authsize %zu could not be set %d\n", exp_tag_len, ret);
		ret = -EAGAIN;
		goto out;
	}

	aead.tfm = tfm;
	aead.req = req;

	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  lc_aead_test_cb, &aead.result);
	aead_request_set_ad(req, aadlen);

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
	if (!virt_addr_valid(tag)) {
		printk("Invalid virtual address for tag\n");
		ret = -EINVAL;
		goto out;
	}

	/* Encrypt */
	if (aadlen) {
		if (!virt_addr_valid(aad)) {
			printk("Invalid virtual address for aad\n");
			ret = -EINVAL;
			goto out;
		}

		if (aadlen < 4 || inlen < 6) {
			ret = -EFAULT;
			goto out;
		}

		/* Using strage SGL definitions for testing */
		sg_init_table(sg_in, 5);
		sg_set_buf(&sg_in[0], aad, 1);
		sg_set_buf(&sg_in[1], aad + 1, 3);
		sg_set_buf(&sg_in[2], aad + 4, aadlen - 4);
		sg_set_buf(&sg_in[3], in, 1);
		sg_set_buf(&sg_in[4], in + 1, inlen - 1);

		sg_init_table(sg_out, 5);
		sg_set_buf(&sg_out[0], aad, aadlen);
		sg_set_buf(&sg_out[1], out_enc, 1);
		sg_set_buf(&sg_out[2], out_enc + 1, 3);
		sg_set_buf(&sg_out[3], out_enc + 4, inlen - 4);
		sg_set_buf(&sg_out[4], tag, exp_tag_len);
	} else {
		sg_init_table(sg_in, 1);
		sg_set_buf(&sg_in[0], in, inlen);

		sg_init_table(sg_out, 2);
		sg_set_buf(&sg_out[0], out_enc, inlen);
		sg_set_buf(&sg_out[1], tag, exp_tag_len);
	}
	aead_request_set_crypt(req, sg_in, sg_out, inlen, nonce);

	ret = lc_aead_test_encdec(&aead, 1);
	if (0 > ret) {
		pr_info("AEAD encryption failed: %d\n", ret);
		goto out;
	}

	if (memcmp(out_enc, exp_ct, inlen)) {
		pr_info("Enc: ciphertext mismatch\n");
		ret = -EFAULT;
		goto out;
	}
	if (memcmp(tag, exp_tag, exp_tag_len)) {
		pr_info("Enc: tag mismatch\n");
		ret = -EFAULT;
		goto out;
	}

	/* Decrypt */
	if (aadlen) {
		sg_init_table(sg_in, 3);
		sg_set_buf(&sg_in[0], aad, aadlen);
		sg_set_buf(&sg_in[1], out_enc, inlen);
		sg_set_buf(&sg_in[2], tag, exp_tag_len);

		sg_init_table(sg_out, 2);
		sg_set_buf(&sg_out[0], aad, aadlen);
		sg_set_buf(&sg_out[1], out_dec, inlen);
	} else {
		sg_init_table(sg_in, 1);
		sg_set_buf(&sg_in[0], out_enc, inlen);
		sg_set_buf(&sg_in[1], tag, exp_tag_len);

		sg_init_table(sg_out, 1);
		sg_set_buf(&sg_out[0], out_dec, inlen);
	}
	aead_request_set_crypt(req, sg_in, sg_out, inlen, nonce);

	ret = lc_aead_test_encdec(&aead, 0);
	if (0 > ret) {
		pr_info("AEAD decryption failed: %d\n", ret);
		goto out;
	}

	if (memcmp(out_dec, in, inlen)) {
		pr_info("Dec: plaintext mismatch\n");
		ret = -EFAULT;
		goto out;
	}

	/* Mess up the ciphertext */
	out_enc[0] ^= 0x01;
	ret = lc_aead_test_encdec(&aead, 0);
	if (ret != -EBADMSG) {
		pr_info("AEAD decryption unexpected result (should be -EBADMSG): %d\n",
			ret);
		goto out;
	}

	ret = 0;
	pr_info("Testing successful\n");

out:
	if (tag)
		kfree(tag);
	if (aad)
		kfree(aad);
	if (in)
		kfree(in);
	if (out_enc)
		kfree(out_enc);
	if (out_dec)
		kfree(out_dec);
	if (tfm)
		crypto_free_aead(tfm);
	if (req)
		aead_request_free(req);
	return ret;
}

static int aascon_tester_128(void)
{
	/*
	 * Vector 1089 from genkat_crypto_aead_asconaead128_ref generated by
	 * code https://github.com/ascon/ascon-c
	 */
	static const uint8_t pt[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				      0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
				      0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
				      0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
				      0x1C, 0x1D, 0x1E, 0x1F };
	static const uint8_t aad[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				       0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
				       0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
				       0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
				       0x1C, 0x1D, 0x1E, 0x1F };
	static const uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
				       0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
				       0x0C, 0x0D, 0x0E, 0x0F };
	uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			    0x08, 0x09, 0x0A, 0x0B,
					 0x0C, 0x0D, 0x0E, 0x0F };
	static const uint8_t exp_ct[] = { 0x4C, 0x08, 0x6D, 0x27, 0xA3, 0xB5,
					  0x1A, 0x23, 0x33, 0xCF, 0xC7, 0xF2,
					  0x21, 0x72, 0xA9, 0xBC, 0xAD, 0x88,
					  0xB8, 0xD4, 0xD7, 0x7E, 0x50, 0x62,
					  0x2D, 0x78, 0x83, 0x45, 0xFA, 0x7B,
					  0xEE, 0x44 };
	static const uint8_t exp_tag[] = { 0x68, 0x91, 0x5D, 0x3F, 0x94, 0x22,
					   0x28, 0x9F, 0x23, 0x49, 0xD6, 0xA3,
					   0xB4, 0x16, 0x03, 0x97 };
	pr_info("Ascon lightweight 128 crypt\n");
	return lc_aead_test("ascon-aead-128-leancrypto", pt, sizeof(pt), nonce,
			    sizeof(nonce), aad, sizeof(aad), key, sizeof(key),
			    exp_ct, exp_tag, sizeof(exp_tag));
}

static int __init leancrypto_kernel_aead_test_init(void)
{
	return aascon_tester_128();
}

static void __exit leancrypto_kernel_aead_test_exit(void)
{
}

module_init(leancrypto_kernel_aead_test_init);
module_exit(leancrypto_kernel_aead_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_aead_test");
