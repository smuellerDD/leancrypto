/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
#include "aes_aesni.h"
#include "aes_internal.h"
#include "ext_headers_internal.h"
#include "lc_aes.h"
#include "test_helper.h"

static int aes_xts_large(const struct lc_sym *sym)
{
	LC_SYM_CTX_ON_STACK(aes_xts, sym);
	uint8_t *pt;
	uint8_t key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01, 0x02, 0x03,
		0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
		0x0e, 0x0f, 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, 0x01,
		0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f,
	};
	uint8_t iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	size_t len;
	int ret;

	CKINT(test_mem(&pt, &len));

	CKINT(lc_sym_init(aes_xts));
	CKINT_LOG(lc_sym_setkey(aes_xts, key, sizeof(key)),
		  "Encrypt set key\n");
	CKINT_LOG(lc_sym_setiv(aes_xts, iv, sizeof(iv)), "Encrypt set IV\n");
	lc_sym_encrypt(aes_xts, pt, pt, len);
	lc_sym_zero(aes_xts);

	CKINT(lc_sym_init(aes_xts));
	CKINT_LOG(lc_sym_setkey(aes_xts, key, sizeof(key)),
		  "Decrypt set key\n");
	CKINT_LOG(lc_sym_setiv(aes_xts, iv, sizeof(iv)), "Decrypt set IV\n");
	lc_sym_decrypt(aes_xts, pt, pt, len);
	lc_sym_zero(aes_xts);

out:
	free(pt);
	return ret;
}

int main(int argc, char *argv[])
{
	const struct lc_sym *sym = lc_aes_xts;

	(void)argc;
	(void)argv;

	if (argc >= 2)
		sym = lc_aes_xts_c;

	return aes_xts_large(sym);
}
