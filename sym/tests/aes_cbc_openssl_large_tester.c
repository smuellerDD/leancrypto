/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include <openssl/aes.h>
#include <openssl/evp.h>

#include "test_helper.h"

static int aes_cbc_large(void)
{
	EVP_CIPHER_CTX *ctx = NULL;
	const EVP_CIPHER *type = EVP_aes_256_cbc();
	uint8_t *pt;
	int outl;
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	size_t len;
	int ret;

	CKINT(test_mem(&pt, &len));

	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	ret = EVP_EncryptInit_ex(ctx, type, NULL, key, iv);
	if (!ret) {
		ret = 1;
		goto out;
	}
	ret = EVP_CipherUpdate(ctx, pt, &outl, pt, len);
	if (!ret) {
		ret = 1;
		goto out;
	}
	ret = EVP_CipherFinal_ex(ctx, pt, &outl);
	if (!ret) {
		ret = 1;
		goto out;
	}

	EVP_CIPHER_CTX_free(ctx);
	ctx = EVP_CIPHER_CTX_new();
	CKNULL(ctx, -ENOMEM);

	ret = EVP_DecryptInit_ex(ctx, type, NULL, key, iv);
	if (!ret) {
		ret = 1;
		goto out;
	}
	ret = EVP_CipherUpdate(ctx, pt, &outl, pt, len);
	if (!ret) {
		ret = 1;
		goto out;
	}
	ret = EVP_CipherFinal_ex(ctx, pt, &outl);
	if (!ret) {
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
	return aes_cbc_large();
}
