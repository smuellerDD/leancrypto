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
			const uint8_t *nonce_in, size_t noncelen,
			const uint8_t *aad_in, size_t aadlen,
			const uint8_t *key, size_t keylen,
			const uint8_t *exp_ct, const uint8_t *exp_tag,
			size_t exp_tag_len, int rfc4106)
{
	int ret = -EFAULT;
	struct lc_aead_test_def aead;
	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg_in[5], sg_out[6];
	u8 *out_enc = NULL, *out_dec = NULL, *aad = NULL, *in = NULL,
	   *tag = NULL, *nonce = NULL;

	nonce = kmalloc(noncelen, GFP_KERNEL);
	if (!nonce)
		return -ENOMEM;
	memcpy(nonce, nonce_in, noncelen);

	aad = kmalloc(aadlen, GFP_KERNEL);
	if (!aad) {
		ret = -ENOMEM;
		goto out;
	}
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

	if (rfc4106)
		aead_request_set_ad(req, aadlen + noncelen);
	else
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
		//sg_init_table(sg_in, 5);
		//sg_set_buf(&sg_in[0], aad, 1);
		//sg_set_buf(&sg_in[1], aad + 1, 3);
		//sg_set_buf(&sg_in[2], aad + 4, aadlen - 4);

		if (rfc4106) {
			sg_init_table(sg_in, 4);
			sg_set_buf(&sg_in[0], aad, aadlen);
			sg_set_buf(&sg_in[1], nonce, noncelen);
			sg_set_buf(&sg_in[2], in, 1);
			sg_set_buf(&sg_in[3], in + 1, inlen - 1);

			sg_init_table(sg_out, 6);
			sg_set_buf(&sg_out[0], aad, aadlen);
			sg_set_buf(&sg_out[1], nonce, noncelen);
			sg_set_buf(&sg_out[2], out_enc, 1);
			sg_set_buf(&sg_out[3], out_enc + 1, 3);
			sg_set_buf(&sg_out[4], out_enc + 4, inlen - 4);
			sg_set_buf(&sg_out[5], tag, exp_tag_len);
		} else {
			sg_init_table(sg_in, 3);
			sg_set_buf(&sg_in[0], aad, aadlen);
			sg_set_buf(&sg_in[1], in, 1);
			sg_set_buf(&sg_in[2], in + 1, inlen - 1);

			sg_init_table(sg_out, 5);
			sg_set_buf(&sg_out[0], aad, aadlen);
			sg_set_buf(&sg_out[1], out_enc, 1);
			sg_set_buf(&sg_out[2], out_enc + 1, 3);
			sg_set_buf(&sg_out[3], out_enc + 4, inlen - 4);
			sg_set_buf(&sg_out[4], tag, exp_tag_len);
		}
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

	/* Reset the IV to the original IV */
	memcpy(nonce, nonce_in, noncelen);

	/* Decrypt */
	if (aadlen) {
		if (rfc4106) {
			sg_init_table(sg_in, 4);
			sg_set_buf(&sg_in[0], aad, aadlen);
			sg_set_buf(&sg_in[1], nonce, noncelen);
			sg_set_buf(&sg_in[2], out_enc, inlen);
			sg_set_buf(&sg_in[3], tag, exp_tag_len);

			sg_init_table(sg_out, 3);
			sg_set_buf(&sg_out[0], aad, aadlen);
			sg_set_buf(&sg_out[1], nonce, noncelen);
			sg_set_buf(&sg_out[2], out_dec, inlen);
		} else {
			sg_init_table(sg_in, 3);
			sg_set_buf(&sg_in[0], aad, aadlen);
			sg_set_buf(&sg_in[1], out_enc, inlen);
			sg_set_buf(&sg_in[2], tag, exp_tag_len);

			sg_init_table(sg_out, 2);
			sg_set_buf(&sg_out[0], aad, aadlen);
			sg_set_buf(&sg_out[1], out_dec, inlen);
		}
	} else {
		sg_init_table(sg_in, 2);
		sg_set_buf(&sg_in[0], out_enc, inlen);
		sg_set_buf(&sg_in[1], tag, exp_tag_len);

		sg_init_table(sg_out, 1);
		sg_set_buf(&sg_out[0], out_dec, inlen);
	}
	aead_request_set_crypt(req, sg_in, sg_out, inlen + exp_tag_len, nonce);

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

	/* Reset the IV to the original IV */
	memcpy(nonce, nonce_in, noncelen);

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
	if (nonce)
		kfree(nonce);
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

static int aes_gcm_tester_256(void)
{
	static const uint8_t pt[] = { 0xb7, 0x06, 0x19, 0x4b, 0xb0, 0xb1,
				      0x0c, 0x47, 0x4e, 0x1b, 0x2d, 0x7b,
				      0x22, 0x78, 0x22, 0x4c };
	static const uint8_t aad[] = { 0xff, 0x76, 0x28, 0xf6, 0x42, 0x7f,
				       0xbc, 0xef, 0x1f, 0x3b, 0x82, 0xb3,
				       0x74, 0x04, 0xe1, 0x16 };
	static const uint8_t key[] = { 0x7f, 0x71, 0x68, 0xa4, 0x06, 0xe7, 0xc1,
				       0xef, 0x0f, 0xd4, 0x7a, 0xc9, 0x22, 0xc5,
				       0xec, 0x5f, 0x65, 0x97, 0x65, 0xfb, 0x6a,
				       0xaa, 0x04, 0x8f, 0x70, 0x56, 0xf6, 0xc6,
				       0xb5, 0xd8, 0x51, 0x3d };
	uint8_t iv[] = { 0xb8, 0xb5, 0xe4, 0x07, 0xad, 0xc0,
			 0xe2, 0x93, 0xe3, 0xe7, 0xe9, 0x91 };
	static const uint8_t exp_ct[] = { 0x8f, 0xad, 0xa0, 0xb8, 0xe7, 0x77,
					  0xa8, 0x29, 0xca, 0x96, 0x80, 0xd3,
					  0xbf, 0x4f, 0x35, 0x74 };
	static const uint8_t exp_tag[] = { 0xda, 0xca, 0x35, 0x42, 0x77,
					   0xf6, 0x33, 0x5f, 0xc8, 0xbe,
					   0xc9, 0x08, 0x86, 0xda, 0x70 };
	pr_info("AES GCM 256 crypt\n");
	return lc_aead_test("gcm-aes-leancrypto", pt, sizeof(pt), iv,
			    sizeof(iv), aad, sizeof(aad), key, sizeof(key),
			    exp_ct, exp_tag, sizeof(exp_tag), 0);
}

/*
 * Identical data as the RFC4106 for verification
 */
static int rfc4106_comparison_aes_gcm_tester_256(void)
{
	static const uint8_t pt[] = { 0xb7, 0x06, 0x19, 0x4b, 0xb0, 0xb1,
				      0x0c, 0x47, 0x4e, 0x1b, 0x2d, 0x7b,
				      0x22, 0x78, 0x22, 0x4c };
	static const uint8_t aad[] = { 0xff, 0x76, 0x28, 0xf6,
				       0x42, 0x7f, 0xbc, 0xef };
	static const uint8_t key[] = { 0x7f, 0x71, 0x68, 0xa4, 0x06, 0xe7, 0xc1,
				       0xef, 0x0f, 0xd4, 0x7a, 0xc9, 0x22, 0xc5,
				       0xec, 0x5f, 0x65, 0x97, 0x65, 0xfb, 0x6a,
				       0xaa, 0x04, 0x8f, 0x70, 0x56, 0xf6, 0xc6,
				       0xb5, 0xd8, 0x51, 0x3d };
	static const uint8_t iv[] = { 0xb8, 0xb5, 0xe4, 0x07, 0xad, 0xc0,
				      0xe2, 0x93, 0xe3, 0xe7, 0xe9, 0x91 };
	static const uint8_t exp_ct[] = { 0x8f, 0xad, 0xa0, 0xb8, 0xe7, 0x77,
					  0xa8, 0x29, 0xca, 0x96, 0x80, 0xd3,
					  0xbf, 0x4f, 0x35, 0x74 };
	static const uint8_t exp_tag[] = { 0xbd, 0x08, 0x80, 0x82, 0x97, 0x53,
					   0x09, 0xbc, 0xc2, 0x5d, 0x5c, 0x0d,
					   0xaf, 0xe6, 0xaf, 0x47 };
	pr_info("AES GCM 256 crypt (comparision to RFC4106)\n");
	return lc_aead_test("gcm-aes-leancrypto", pt, sizeof(pt), iv,
			    sizeof(iv), aad, sizeof(aad), key, sizeof(key),
			    exp_ct, exp_tag, sizeof(exp_tag), 0);
}

static int rfc4106_aes_gcm_tester_256(void)
{
	static const uint8_t pt[] = { 0xb7, 0x06, 0x19, 0x4b, 0xb0, 0xb1,
				      0x0c, 0x47, 0x4e, 0x1b, 0x2d, 0x7b,
				      0x22, 0x78, 0x22, 0x4c };
	static const uint8_t aad[] = { 0xff, 0x76, 0x28, 0xf6,
				       0x42, 0x7f, 0xbc, 0xef };
	static const uint8_t key[] = { 0x7f, 0x71, 0x68, 0xa4, 0x06, 0xe7, 0xc1,
				       0xef, 0x0f, 0xd4, 0x7a, 0xc9, 0x22, 0xc5,
				       0xec, 0x5f, 0x65, 0x97, 0x65, 0xfb, 0x6a,
				       0xaa, 0x04, 0x8f, 0x70, 0x56, 0xf6, 0xc6,
				       0xb5, 0xd8, 0x51, 0x3d,
				       /* IV part */
				       0xb8, 0xb5, 0xe4, 0x07 };
	static const uint8_t iv[] = { /* 0xb8, 0xb5, 0xe4, 0x07,*/ 0xad,
					0xc0,
					0xe2,
					0x93,
					0xe3,
					0xe7,
					0xe9,
					0x91 };
	static const uint8_t exp_ct[] = { 0x8f, 0xad, 0xa0, 0xb8, 0xe7, 0x77,
					  0xa8, 0x29, 0xca, 0x96, 0x80, 0xd3,
					  0xbf, 0x4f, 0x35, 0x74 };
	static const uint8_t exp_tag[] = { 0xbd, 0x08, 0x80, 0x82, 0x97, 0x53,
					   0x09, 0xbc, 0xc2, 0x5d, 0x5c, 0x0d,
					   0xaf, 0xe6, 0xaf, 0x47 };
	pr_info("RFC4106 AES GCM 256 crypt\n");
	return lc_aead_test("rfc4106-gcm-aes-leancrypto", pt, sizeof(pt), iv,
			    sizeof(iv), aad, sizeof(aad), key, sizeof(key),
			    exp_ct, exp_tag, sizeof(exp_tag), 1);
}

static int __init leancrypto_kernel_aes_gcm_test_init(void)
{
	int ret = aes_gcm_tester_256();

	ret |= rfc4106_comparison_aes_gcm_tester_256();
	ret |= rfc4106_aes_gcm_tester_256();

	return ret;
}

static void __exit leancrypto_kernel_aes_gcm_test_exit(void)
{
}

module_init(leancrypto_kernel_aes_gcm_test_init);
module_exit(leancrypto_kernel_aes_gcm_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_aes_gcm_test");
