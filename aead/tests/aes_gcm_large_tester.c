/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "aes_c.h"
#include "binhexbin.h"
#include "compare.h"
#include "cpufeatures.h"
#include "lc_aes_gcm.h"
#include "test_helper.h"

static int aes_gcm_tester_large(int argc)
{
	uint8_t tag[16];
	uint8_t *pt;
	uint8_t aad[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	uint8_t iv[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c
	};
	size_t len;
	int ret;
	LC_AES_GCM_CTX_ON_STACK(aes_gcm);

	if (argc >= 2) {
		struct lc_aes_gcm_cryptor *c = aes_gcm->aead_state;
		c->sym_ctx.sym = lc_aes_c;
	}

	CKINT(test_mem(&pt, &len));

	if (lc_aead_setkey(aes_gcm, key, sizeof(key), iv, sizeof(iv))) {
		ret = EFAULT;
		goto out;
	}
	lc_aead_encrypt(aes_gcm, pt, pt, len, aad, sizeof(aad), tag,
			sizeof(tag));
	lc_aead_zero(aes_gcm);

	if (lc_aead_setkey(aes_gcm, key, sizeof(key), iv, sizeof(iv))) {
		ret = EFAULT;
		goto out;
	}
	ret = lc_aead_decrypt(aes_gcm, pt, pt, len, aad, sizeof(aad), tag,
			      sizeof(tag));
	lc_aead_zero(aes_gcm);

out:
	free(pt);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = aes_gcm_tester_large(argc);

	return ret;
}
