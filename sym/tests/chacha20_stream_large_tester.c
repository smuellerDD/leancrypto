/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 *
 * License, 0x see LICENSE file in root directory
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

#include "conv_be_le.h"
#include "lc_chacha20.h"
#include "ret_checkers.h"
#include "test_helper.h"
#include "visibility.h"

static int chacha20_large_tester(void)
{
	/* Test vector according to RFC 7539 section 2.4.2 */
	static const uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				       0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				       0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				       0x1c, 0x1d, 0x1e, 0x1f };
	static const uint8_t iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
	uint8_t *pt = NULL;
	size_t len;
	int ret;
	LC_SYM_CTX_ON_STACK(chacha20, lc_chacha20);

	CKINT(test_mem(&pt, &len));

	/* Encrypt */
	lc_sym_init(chacha20);
	CKINT(lc_sym_setkey(chacha20, (uint8_t *)key, sizeof(key)));
	CKINT(lc_sym_setiv(chacha20, (uint8_t *)iv, sizeof(iv)));
	lc_sym_encrypt(chacha20, pt, pt, len);
	lc_sym_zero(chacha20);

	/* Decrypt */
	lc_sym_init(chacha20);
	CKINT(lc_sym_setkey(chacha20, (uint8_t *)key, sizeof(key)));
	CKINT(lc_sym_setiv(chacha20, (uint8_t *)iv, sizeof(iv)));
	lc_sym_decrypt(chacha20, pt, pt, len);
	lc_sym_zero(chacha20);

out:
	if (pt)
		free(pt);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return chacha20_large_tester();
}
