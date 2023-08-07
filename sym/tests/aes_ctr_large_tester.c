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

#include "aes_internal.h"
#include "ext_headers.h"
#include "lc_aes.h"
#include "ret_checkers.h"

static int aes_ctr_large(void)
{
	LC_SYM_CTX_ON_STACK(aes_ctr, lc_aes_ctr);
	uint8_t *pt;
	uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	int ret;

	pt = calloc(1, 1UL << 30);
	if (!pt)
		return 1;

	lc_sym_init(aes_ctr);
	CKINT(lc_sym_setkey(aes_ctr, key, sizeof(key)));
	CKINT(lc_sym_setiv(aes_ctr, iv, sizeof(iv)));
	lc_sym_encrypt(aes_ctr, pt, pt, 1UL << 30);
	lc_sym_zero(aes_ctr);

	CKINT(lc_sym_setkey(aes_ctr, key, sizeof(key)));
	CKINT(lc_sym_setiv(aes_ctr, iv, sizeof(iv)));
	lc_sym_decrypt(aes_ctr, pt, pt, 1UL << 30);
	lc_sym_zero(aes_ctr);

out:
	free(pt);
	return ret;
}

int main(int argc, char *argv[])
{
	(void)argc;
	(void)argv;
	return aes_ctr_large();
}
