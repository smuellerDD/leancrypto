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

#include "alignment.h"
#include "conv_be_le.h"
#include "lc_chacha20.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "xor256.h"

static int chacha20_enc_selftest(void)
{
	/* Test vector according to RFC 7539 section 2.4.2 */
	static const uint8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				       0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				       0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				       0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				       0x1c, 0x1d, 0x1e, 0x1f };
	static const uint8_t iv[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0x4a, 0x00, 0x00, 0x00, 0x00 };
	static const char *string =
		"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
	static const uint8_t exp[] = {
		0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba,
		0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec,
		0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f,
		0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
		0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39,
		0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35,
		0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d,
		0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
		0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c,
		0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf,
		0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78,
		0x5e, 0x42, 0x87, 0x4d
	};
	uint8_t res[sizeof(exp)] __align(LC_XOR_ALIGNMENT(sizeof(uint64_t)));
	int ret;
	LC_SYM_CTX_ON_STACK(chacha20, lc_chacha20);

	printf("ChaCha20 ctx size: %" PRIu64 "\n", LC_SYM_CTX_SIZE(lc_chacha20));
	/* Encrypt */
	lc_sym_init(chacha20);
	CKINT(lc_sym_setkey(chacha20, (uint8_t *)key, sizeof(key)));
	CKINT(lc_sym_setiv(chacha20, (uint8_t *)iv, sizeof(iv)));
	lc_sym_encrypt(chacha20, (uint8_t *)string, res, strlen(string));
	ret = memcmp(res, exp, sizeof(exp));
	if (ret) {
		ret = -EINVAL;
		goto out;
	}
	lc_sym_zero(chacha20);

	/* Decrypt */
	lc_sym_init(chacha20);
	CKINT(lc_sym_setkey(chacha20, (uint8_t *)key, sizeof(key)));
	CKINT(lc_sym_setiv(chacha20, (uint8_t *)iv, sizeof(iv)));
	lc_sym_decrypt(chacha20, res, res, sizeof(res));
	ret = memcmp(res, string, sizeof(res));
	if (ret) {
		ret = -EINVAL;
		goto out;
	}

out:
	lc_sym_zero(chacha20);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return chacha20_enc_selftest();
}
