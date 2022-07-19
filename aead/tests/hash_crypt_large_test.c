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

#include <errno.h>
#include <stdlib.h>

#include "compare.h"
#include "binhexbin.h"
#include "lc_hash_crypt.h"
#include "lc_sha256.h"

static int hc_tester_sha512_large(void)
{
	LC_HC_CTX_ON_STACK(hc, lc_sha512);
	uint8_t tag[16];
	uint8_t *pt;
	uint8_t aad[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};
	ssize_t ret;

	pt = calloc(1, 1UL<<30);
	if (!pt)
		return 1;

	lc_hc_setkey(hc, key, sizeof(key), NULL, 0);
	lc_hc_encrypt_oneshot(hc, pt, pt, 1UL<<30, aad, sizeof(aad),
			      tag, sizeof(tag));
	lc_hc_zero(hc);

	lc_hc_setkey(hc, key, sizeof(key), NULL, 0);
	ret = lc_hc_decrypt_oneshot(hc, pt, pt, 1UL<<30, aad, sizeof(aad),
				    tag, sizeof(tag));
	lc_hc_zero(hc);
	free(pt);
	if (ret < 0) {
		printf("Error return code %zd\n", ret);
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return hc_tester_sha512_large();
}
