/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
#include "lc_aes.h"
#include "lc_symkmac.h"
#include "ret_checkers.h"

static int symhmac_tester_large(void)
{
	LC_KH_CTX_ON_STACK(sh, lc_aes_cbc, lc_cshake256);
	uint8_t tag[64];
	uint8_t *pt;
	uint8_t aad[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	int ret;

	pt = calloc(1, 1UL << 30);
	if (!pt)
		return 77;

	CKINT(lc_aead_setkey(sh, key, sizeof(key), aad, sizeof(aad)));
	lc_aead_encrypt(sh, pt, pt, 1UL << 30, aad, sizeof(aad), tag,
			sizeof(tag));
	lc_aead_zero(sh);

	CKINT(lc_aead_setkey(sh, key, sizeof(key), aad, sizeof(aad)));
	ret = lc_aead_decrypt(sh, pt, pt, 1UL << 30, aad, sizeof(aad), tag,
			      sizeof(tag));

out:
	lc_aead_zero(sh);
	free(pt);
	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return symhmac_tester_large();
}
