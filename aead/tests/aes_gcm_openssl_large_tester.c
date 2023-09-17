/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <stdlib.h>

#include <openssl/aes.h>
#include <openssl/evp.h>

#include "ret_checkers.h"

#define LC_OPENSSL_SIZE (1UL << 30)
static int aes_gcm_large(void)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *type = EVP_aes_256_gcm();
	uint8_t *pt;
	uint8_t tag[16];
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b };
	int ret;

	pt = calloc(1, LC_OPENSSL_SIZE);
	if (!pt)
		return 1;

	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	ret = EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 1);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv),
				  NULL);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_Cipher(ctx, pt, pt, LC_OPENSSL_SIZE);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_Cipher(ctx, NULL, NULL, 0);
	if (ret < 0) {
		ret = 1;
		goto out;
	}

	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag);
	if (!ret) {
		ret = 1;
		goto out;
	}

	EVP_CIPHER_CTX_free(ctx);

	/* Decrypt */
	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	ret = EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 0);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv),
				  NULL);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, sizeof(tag), tag);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_Cipher(ctx, pt, pt, LC_OPENSSL_SIZE);
	if (!ret) {
		ret = 1;
		goto out;
	}

	ret = EVP_Cipher(ctx, NULL, NULL, 0);
	if (ret < 0) {
		ret = 1;
		goto out;
	}
	ret = 0;

out:
	if (ctx)
		EVP_CIPHER_CTX_free(ctx);
	free(pt);
	return ret;
}

/*
 * Invoke plain C implementation:
 * export OPENSSL_ia32cap=~0x200020000000000:0x0
 */
int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return aes_gcm_large();
}
