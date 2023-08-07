/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "compare.h"
#include "conv_be_le.h"
#include "lc_chacha20.h"
#include "ret_checkers.h"
#include "visibility.h"

static inline void chacha20_bswap32(uint32_t *ptr, uint32_t bytes)
{
	uint32_t i;

	/* Byte-swap data which is an LE representation */
	for (i = 0; i < bytes; i++) {
		*ptr = le_bswap32(*ptr);
		ptr++;
	}
}

static inline int chacha20_selftest_one(struct lc_sym_state *state,
					uint32_t *expected)
{
	uint32_t result[64 / sizeof(uint32_t)];

	cc20_block(state, result);

	return lc_compare((uint8_t *)result, (uint8_t *)expected,
			  sizeof(result), "ChaCha20 block");
}

static int chacha20_block_selftest(void)
{
	uint32_t expected[64 / sizeof(uint32_t)];
	int ret;
	uint32_t key[] = { 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
			   0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c };
	uint32_t iv[] = { 0x09000000, 0x4a000000, 0x00000000 };
	LC_SYM_CTX_ON_STACK(chacha20, lc_chacha20);

	/* Test vector according to RFC 7539 section 2.3.2 */
	chacha20_bswap32(key, sizeof(key) / sizeof(uint32_t));
	chacha20_bswap32(iv, sizeof(iv) / sizeof(uint32_t));
	lc_sym_init(chacha20);
	CKINT(lc_sym_setkey(chacha20, (uint8_t *)key, sizeof(key)));
	CKINT(lc_sym_setiv(chacha20, (uint8_t *)iv, sizeof(iv)));

	expected[0] = 0xe4e7f110;
	expected[1] = 0x15593bd1;
	expected[2] = 0x1fdd0f50;
	expected[3] = 0xc47120a3;
	expected[4] = 0xc7f4d1c7;
	expected[5] = 0x0368c033;
	expected[6] = 0x9aaa2204;
	expected[7] = 0x4e6cd4c3;
	expected[8] = 0x466482d2;
	expected[9] = 0x09aa9f07;
	expected[10] = 0x05d7c214;
	expected[11] = 0xa2028bd9;
	expected[12] = 0xd19c12b5;
	expected[13] = 0xb94e16de;
	expected[14] = 0xe883d0cb;
	expected[15] = 0x4e3c50a2;

	chacha20_bswap32(expected, sizeof(expected) / sizeof(uint32_t));

	ret = chacha20_selftest_one(chacha20->sym_state, &expected[0]);

out:
	lc_sym_zero(chacha20);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return chacha20_block_selftest();
}
