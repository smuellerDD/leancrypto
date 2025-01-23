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

#include "lc_chacha20_drng.h"
#include "lc_chacha20_private.h"

#define CC20_TEST_BLOCKSIZE LC_CC20_BLOCK_SIZE
//#define CC20_TEST_BLOCKSIZE	32

static int kmac_drng_selftest_large(struct lc_chacha20_drng_ctx *cc20_ctx)
{
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};
	uint8_t out[CC20_TEST_BLOCKSIZE];
	unsigned int i;

	lc_cc20_drng_seed(cc20_ctx, seed, sizeof(seed));

	for (i = 0; i < ((1U << 30) / CC20_TEST_BLOCKSIZE); i++)
		lc_cc20_drng_generate(cc20_ctx, out, CC20_TEST_BLOCKSIZE);
	lc_cc20_drng_zero(cc20_ctx);

	return 0;
}

int main(int argc, char *argv[])
{
	LC_CC20_DRNG_CTX_ON_STACK(cc20_ctx);
	int ret = kmac_drng_selftest_large(cc20_ctx);

	(void)argc;
	(void)argv;

	return ret;
}
