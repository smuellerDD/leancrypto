/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
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

#include "lc_aes.h"
#include "lc_aes_private.h"
#include "compare.h"
#include "ret_checkers.h"
#include "visibility.h"

static const uint8_t key128[] = {
	0x75, 0x75, 0xda, 0x3a, 0x93, 0x60, 0x7c, 0xc2,
	0xbf, 0xd8, 0xce, 0xc7, 0xaa, 0xdf, 0xd9, 0xa6
};
static const uint8_t pt128[] = {
	0x42, 0x13, 0x6d, 0x3c, 0x38, 0x4a, 0x3e, 0xea,
	0xc9, 0x5a, 0x06, 0x6f, 0xd2, 0x8f, 0xed, 0x3f
};
static const uint8_t ct128[] = {
	0xf6, 0x85, 0x94, 0x81, 0x6f, 0x64, 0xca, 0xa3,
	0xf5, 0x6f, 0xab, 0xea, 0x25, 0x48, 0xf5, 0xfb
};
static const uint8_t iv128[] = {
	0x03, 0x1f, 0x6b, 0xd7, 0xe6, 0x1e, 0x64, 0x3d
};

static const uint8_t key256[] = {
	0x80, 0xaa, 0x99, 0x73, 0x27, 0xa4, 0x80, 0x6b,
	0x6a, 0x7a, 0x41, 0xa5, 0x2b, 0x86, 0xc3, 0x71,
	0x03, 0x86, 0xf9, 0x32, 0x78, 0x6e, 0xf7, 0x96,
	0x76, 0xfa, 0xfb, 0x90, 0xb8, 0x26, 0x3c, 0x5f
};
static const uint8_t pt256[] = {
	0x0a, 0x25, 0x6b, 0xa7, 0x5c, 0xfa, 0x03, 0xaa,
	0xa0, 0x2b, 0xa9, 0x42, 0x03, 0xf1, 0x5b, 0xaa
};
static const uint8_t ct256[] = {
	0xd3, 0x3d, 0x3d, 0x97, 0x7b, 0xf0, 0xa9, 0x15,
	0x59, 0xf9, 0x9c, 0x8a, 0xcd, 0x29, 0x3d, 0x43
};
static const uint8_t iv256[] = {
	0x42, 0x3c, 0x96, 0x0d, 0x8a, 0x2a, 0xc4, 0xc1
};


static int test_encrypt_kw_one(struct lc_sym_ctx *ctx,
			       const uint8_t *key, size_t keylen,
			       const uint8_t *pt, size_t ptlen,
			       const uint8_t *ct, const uint8_t *iv)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wvla"
	uint8_t out[ptlen + 8], out2[ptlen];
#pragma GCC diagnostic pop
	uint8_t tag[8];
	int ret, rc;

	/* Encrypt */
	lc_sym_init(ctx);
	CKINT(lc_sym_setkey(ctx, key, keylen));
	lc_aes_kw_encrypt(ctx, pt, out, ptlen);
	ret = compare(out + 8, ct, ptlen, "AES-KW encrypt ciphertext");
	ret += compare(out, iv, sizeof(tag), "AES-KW encrypt tag");

	/* Decrypt */
	rc = lc_aes_kw_decrypt(ctx, out, out2, sizeof(out));
	if (rc) {
		ret++;
		printf("AES-KW Decryption error\n");
	}
	ret += compare(out2, pt, ptlen, "AES-KW decrypt plaintext");

	/* Decrypt with error */
	out[0] = (out[0] + 1) & 0xff;
	rc = lc_aes_kw_decrypt(ctx, out, out2, sizeof(out));
	if (rc != -EBADMSG) {
		ret++;
		printf("AES-KW Decryption error not caught\n");
	}

out:
	return ret;
}

static int test_kw(void)
{
	int ret;
	LC_SYM_CTX_ON_STACK(aes_kw, lc_aes_kw);

	ret = test_encrypt_kw_one(aes_kw,
				  key128, sizeof(key128),
				  pt128, sizeof(pt128), ct128, iv128);
	lc_sym_zero(aes_kw);

	ret += test_encrypt_kw_one(aes_kw,
				   key256, sizeof(key256),
				   pt256, sizeof(pt256), ct256, iv256);
	lc_sym_zero(aes_kw);

	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return test_kw();
}
