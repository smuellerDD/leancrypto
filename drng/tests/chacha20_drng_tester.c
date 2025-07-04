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

#include "alignment.h"
#include "compare.h"
#include "conv_be_le.h"
#include "lc_chacha20_drng.h"
#include "lc_chacha20_private.h"
#include "ret_checkers.h"
#include "visibility.h"

static inline void chacha20_bswap32(uint32_t *ptr, uint32_t words)
{
	uint32_t i;

	/* Byte-swap data which is an LE representation */
	for (i = 0; i < words; i++) {
		*ptr = le_bswap32(*ptr);
		ptr++;
	}
}

static int chacha20_drng_selftest(struct lc_chacha20_drng_ctx *cc20_ctx)
{
	struct lc_sym_ctx *sym_ctx = &cc20_ctx->cc20;
	struct lc_sym_state *chacha20_state = sym_ctx->sym_state;
	uint8_t outbuf[LC_CC20_KEY_SIZE * 2] __align(sizeof(uint32_t));
	union {
		uint8_t b[LC_CC20_KEY_SIZE * 2];
		uint32_t u[(LC_CC20_KEY_SIZE * 2) / sizeof(uint32_t)];
	} seed = { .b = {
			   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			   0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			   0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			   0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
			   0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			   0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
			   0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		   } };
	int ret = 0;

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * and pulling one ChaCha20 DRNG block.
	 */
	static const uint8_t expected_block[LC_CC20_KEY_SIZE] = {
		0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
		0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
		0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
		0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7
	};

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * followed by a reseed with
	 *	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	 *	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	 *	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	 *	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	 *	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	 *	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	 *	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	 *	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
	 * and pulling two ChaCha20 DRNG blocks.
	 */
	static const uint8_t expected_twoblocks[LC_CC20_KEY_SIZE * 2] = {
		0xe3, 0xb0, 0x8a, 0xcc, 0x34, 0xc3, 0x17, 0x0e, 0xc3, 0xd8,
		0xc3, 0x40, 0xe7, 0x73, 0xe9, 0x0d, 0xd1, 0x62, 0xa3, 0x5d,
		0x7d, 0xf2, 0xf1, 0x4a, 0x24, 0x42, 0xb7, 0x1e, 0xb0, 0x05,
		0x17, 0x07, 0xb9, 0x35, 0x10, 0x69, 0x8b, 0x46, 0xfb, 0x51,
		0xe9, 0x91, 0x3f, 0x46, 0xf2, 0x4d, 0xea, 0xd0, 0x81, 0xc1,
		0x1b, 0xa9, 0x5d, 0x52, 0x91, 0x5f, 0xcd, 0xdc, 0xc6, 0xd6,
		0xc3, 0x7c, 0x50, 0x23
	};

	/*
	 * Expected result when ChaCha20 DRNG state is zero:
	 *	* constants are set to "expand 32-byte k"
	 *	* remaining state is 0
	 * followed by a reseed with
	 *	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	 *	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	 *	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	 *	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	 *	0x20
	 * and pulling one ChaCha20 DRNG block plus four byte.
	 */
	static const uint8_t expected_block_nonaligned[LC_CC20_KEY_SIZE + 4] = {
		0x9c, 0xfc, 0x5e, 0x31, 0x21, 0x62, 0x11, 0x85, 0xd3,
		0x77, 0xd3, 0x69, 0x0f, 0xa8, 0x16, 0x55, 0xb4, 0x4c,
		0xf6, 0x52, 0xf3, 0xa8, 0x37, 0x99, 0x38, 0x76, 0xa0,
		0x66, 0xec, 0xbb, 0xce, 0xa9, 0x9c, 0x95, 0xa1, 0xfd
	};

	chacha20_bswap32(seed.u, sizeof(seed) / sizeof(uint32_t));

	/* Generate with zero state */
	chacha20_state->counter[0] = 0;

	lc_cc20_drng_generate(cc20_ctx, outbuf, sizeof(expected_block));
	ret += lc_compare(outbuf, expected_block, sizeof(expected_block),
			  "zero block");

	/* Clear state of DRNG */
	lc_cc20_drng_zero(cc20_ctx);

	/* Reseed with 2 blocks */
	chacha20_state->counter[0] = 0;
	lc_cc20_drng_seed(cc20_ctx, seed.b, sizeof(expected_twoblocks));
	lc_cc20_drng_generate(cc20_ctx, outbuf, sizeof(expected_twoblocks));
	ret += lc_compare(outbuf, expected_twoblocks,
			  sizeof(expected_twoblocks), "twoblocks");

	/* Clear state of DRNG */
	lc_cc20_drng_zero(cc20_ctx);

	/* Reseed with 1 block and one byte */
	chacha20_state->counter[0] = 0;
	lc_cc20_drng_seed(cc20_ctx, seed.b, sizeof(expected_block_nonaligned));
	lc_cc20_drng_generate(cc20_ctx, outbuf,
			      sizeof(expected_block_nonaligned));
	ret += lc_compare(outbuf, expected_block_nonaligned,
			  sizeof(expected_block_nonaligned),
			  "block nonaligned");

	return ret;
}

static int chacha20_tester(void)
{
	struct lc_chacha20_drng_ctx *cc20_ctx_heap = NULL;
	int ret;
	LC_CC20_DRNG_CTX_ON_STACK(cc20_ctx);

	CKINT_LOG(chacha20_drng_selftest(cc20_ctx),
		  "ChaCha20 DRNG self test failure: %d\n", ret);

	lc_cc20_drng_zero(cc20_ctx);

	CKINT_LOG(lc_cc20_drng_alloc(&cc20_ctx_heap),
		  "ChaCha20 DRNG heap allocation failure: %d\n", ret);

	ret = chacha20_drng_selftest(cc20_ctx_heap);

out:
	lc_cc20_drng_zero_free(cc20_ctx_heap);
	return ret;
}

LC_TEST_FUNC(int, main, int argc, char *argv[])
{
	(void)argc;
	(void)argv;

	return chacha20_tester();
}
