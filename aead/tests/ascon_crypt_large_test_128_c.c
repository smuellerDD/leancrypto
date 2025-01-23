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

#include <errno.h>
#include <stdlib.h>

#include "ascon_c.h"
#include "compare.h"
#include "binhexbin.h"
#include "lc_ascon_lightweight.h"
#include "test_helper.h"

static int al_128_tester_large(void)
{
	LC_AL_CTX_ON_STACK(al);
	uint8_t tag[16];
	uint8_t *pt;
	size_t len;
	static const uint8_t aad[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				       0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
				       0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
				       0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
				       0x1C, 0x1D, 0x1E, 0x1F };
	static const uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
				       0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
				       0x0C, 0x0D, 0x0E, 0x0F };
	static const uint8_t nonce[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
					 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
					 0x0C, 0x0D, 0x0E, 0x0F };
	int ret;

	LC_ASCON_SET_CTX(al, lc_ascon_128a_c);

	CKINT(test_mem(&pt, &len));

	if (lc_aead_setkey(al, key, sizeof(key), nonce, sizeof(nonce))) {
		ret = EFAULT;
		goto out;
	}
	lc_aead_encrypt(al, pt, pt, len, aad, sizeof(aad), tag, sizeof(tag));
	lc_aead_zero(al);

	if (lc_aead_setkey(al, key, sizeof(key), nonce, sizeof(nonce))) {
		ret = EFAULT;
		goto out;
	}
	ret = lc_aead_decrypt(al, pt, pt, len, aad, sizeof(aad), tag,
			      sizeof(tag));
	lc_aead_zero(al);

out:
	free(pt);
	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return al_128_tester_large();
}
