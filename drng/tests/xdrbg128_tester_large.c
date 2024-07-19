/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "lc_xdrbg.h"
#include "small_stack_support.h"

#define XDRBG128_TEST_BLOCKSIZE LC_XDRBG128_DRNG_MAX_CHUNK
//#define XDRBG128_TEST_BLOCKSIZE	32

static int xdrbg128_drng_selftest_large(struct lc_rng_ctx *xdrbg128_ctx)
{
	struct workspace {
		uint8_t out[XDRBG128_TEST_BLOCKSIZE];
	};
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};
	unsigned int i;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	lc_rng_seed(xdrbg128_ctx, seed, sizeof(seed), NULL, 0);

	for (i = 0; i < ((1U << 30) / XDRBG128_TEST_BLOCKSIZE); i++)
		lc_rng_generate(xdrbg128_ctx, NULL, 0, ws->out,
				XDRBG128_TEST_BLOCKSIZE);
	lc_rng_zero(xdrbg128_ctx);

	LC_RELEASE_MEM(ws);
	return 0;
}

int main(int argc, char *argv[])
{
	LC_XDRBG128_DRNG_CTX_ON_STACK(xdrbg128_ctx);
	int ret = xdrbg128_drng_selftest_large(xdrbg128_ctx);

	(void)argc;
	(void)argv;

	return ret;
}
