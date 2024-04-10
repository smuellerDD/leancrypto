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
#include <stdlib.h>

#include "compare.h"
#include "binhexbin.h"
#include "lc_ascon_keccak.h"
#include "test_helper.h"

static int ak_256512_tester_large(void)
{
	LC_AK_CTX_ON_STACK(ak, lc_sha3_512);
	uint8_t tag[16];
	uint8_t *pt;
	uint8_t aad[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };
	uint8_t iv[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	};
	size_t len;
	int ret;

	CKINT(test_mem(&pt, &len));

	if (lc_aead_setkey(ak, key, sizeof(key), iv, sizeof(iv))) {
		ret = EFAULT;
		goto out;
	}
	lc_aead_encrypt(ak, pt, pt, len, aad, sizeof(aad), tag,
			sizeof(tag));
	lc_aead_zero(ak);

	if (lc_aead_setkey(ak, key, sizeof(key), iv, sizeof(iv))) {
		ret = EFAULT;
		goto out;
	}
	ret = lc_aead_decrypt(ak, pt, pt, len, aad, sizeof(aad), tag,
			      sizeof(tag));
	lc_aead_zero(ak);

out:
	free(pt);
	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return ak_256512_tester_large();
}
