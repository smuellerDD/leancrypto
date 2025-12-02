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
 * input: plaintext / ciphertext
 * input: AuthTag is appended to ciphertext
 * input: Authsize
 * input: key
 * input: IV
 * input: associated data
 * output: ciphertext / plaintext
 */
static int lc_aead_test(const char *name, const uint8_t *data, size_t inlen,
			uint8_t *iv, size_t ivlen, const uint8_t *aad_in,
			size_t aadlen, const uint8_t *key, size_t keylen,
			const uint8_t *exp_ct, const uint8_t *exp_tag,
			size_t exp_tag_len, int esp)
{
	int ret = -EFAULT;
	struct lc_aead_test_def aead;
	struct crypto_aead *tfm = NULL;
	struct aead_request *req = NULL;
	struct scatterlist sg_in[5], sg_out[6];
	u8 *out_enc = NULL, *out_dec = NULL, *aad = NULL, *in = NULL,
	   *tag = NULL;

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

	if (esp)
		aead_request_set_ad(req, aadlen + ivlen);
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

		if (esp) {
			sg_init_table(sg_in, 4);
			sg_set_buf(&sg_in[0], aad, aadlen);
			sg_set_buf(&sg_in[1], iv, ivlen);
			sg_set_buf(&sg_in[2], in, 1);
			sg_set_buf(&sg_in[3], in + 1, inlen - 1);

			sg_init_table(sg_out, 6);
			sg_set_buf(&sg_out[0], aad, aadlen);
			sg_set_buf(&sg_out[1], iv, ivlen);
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
	aead_request_set_crypt(req, sg_in, sg_out, inlen, iv);

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
		if (esp) {
			sg_init_table(sg_in, 4);
			sg_set_buf(&sg_in[0], aad, aadlen);
			sg_set_buf(&sg_in[1], iv, ivlen);
			sg_set_buf(&sg_in[2], out_enc, inlen);
			sg_set_buf(&sg_in[3], tag, exp_tag_len);

			sg_init_table(sg_out, 3);
			sg_set_buf(&sg_out[0], aad, aadlen);
			sg_set_buf(&sg_out[1], iv, ivlen);
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
	aead_request_set_crypt(req, sg_in, sg_out, inlen + exp_tag_len, iv);

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

/*
 * Identical data as the ESP for verification
 */
static int rfc7539_cc20p1305_tester(void)
{
	static const uint8_t pt[] = {
		0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64,
		0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e,
		0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
		0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
		0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75,
		0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
		0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
		0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
		0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65,
		0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65,
		0x20, 0x69, 0x74, 0x2e
	};
	static const uint8_t aad[] = {
		0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
		0xc4, 0xc5, 0xc6, 0xc7
	};
	static const uint8_t key[] = {
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
		0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
		0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
		0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
		0x9c, 0x9d, 0x9e, 0x9f
	};
	uint8_t iv[] = {
		0x07, 0x00, 0x00, 0x00,
		0x40, 0x41, 0x42, 0x43,
		0x44, 0x45, 0x46, 0x47
	};
	static const uint8_t exp_ct[] = {
		0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86,
		0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51,
		0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
		0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
		0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71,
		0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
		0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
		0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
		0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
		0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0,
		0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce,
		0xc6, 0x4b, 0x61, 0x16
	};
	static const uint8_t exp_tag[] = {
		0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
		0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
	};
	pr_info("ChaCha20 Poly1305 crypt\n");
	return lc_aead_test("chacha20-rfc7539-poly1305-leancrypto", pt,
			    sizeof(pt), iv, sizeof(iv), aad, sizeof(aad), key,
			    sizeof(key), exp_ct, exp_tag, sizeof(exp_tag), 0);
}

static int rfc7539esp_cc20p1305_tester(void)
{
	static const uint8_t pt[] = {
		0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64,
		0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c, 0x65, 0x6d, 0x65, 0x6e,
		0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c,
		0x61, 0x73, 0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
		0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63, 0x6f, 0x75,
		0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79,
		0x6f, 0x75, 0x20, 0x6f, 0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e,
		0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
		0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65,
		0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73, 0x63, 0x72, 0x65, 0x65,
		0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65,
		0x20, 0x69, 0x74, 0x2e
	};
	static const uint8_t aad[] = {
		0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3,
		0xc4, 0xc5, 0xc6, 0xc7
	};
	static const uint8_t key[] = {
		0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
		0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d,
		0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94,
		0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
		0x9c, 0x9d, 0x9e, 0x9f,
		/* IV part */
		0x07, 0x00, 0x00, 0x00,
	};
	uint8_t iv[] = {
		/* 0x07, 0x00, 0x00, 0x00, */
		0x40, 0x41, 0x42, 0x43,
		0x44, 0x45, 0x46, 0x47
	};
	static const uint8_t exp_ct[] = {
		0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86,
		0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51,
		0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
		0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12,
		0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71,
		0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
		0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
		0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
		0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
		0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0,
		0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce,
		0xc6, 0x4b, 0x61, 0x16
	};
	static const uint8_t exp_tag[] = {
		0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
		0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91
	};
	pr_info("ESP ChaCha20 Poly1305 crypt\n");
	return lc_aead_test("chacha20-rfc7539esp-poly1305-leancrypto", pt,
			    sizeof(pt), iv, sizeof(iv), aad, sizeof(aad), key,
			    sizeof(key), exp_ct, exp_tag, sizeof(exp_tag), 1);
}

static int __init leancrypto_kernel_cc20p1305_test_init(void)
{
	int ret = rfc7539_cc20p1305_tester();

	ret |= rfc7539esp_cc20p1305_tester();

	return ret;
}

static void __exit leancrypto_kernel_cc20p1305_test_exit(void)
{
}

module_init(leancrypto_kernel_cc20p1305_test_init);
module_exit(leancrypto_kernel_cc20p1305_test_exit);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Stephan Mueller <smueller@chronox.de>");
MODULE_DESCRIPTION("Kernel module leancrypto_kernel_chacha20_poly1305_test");
