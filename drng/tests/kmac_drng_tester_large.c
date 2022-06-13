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

#include "lc_kmac256_drng.h"

#define KMAC256_TEST_BLOCKSIZE	LC_KMAC256_DRNG_MAX_CHUNK
//#define KMAC256_TEST_BLOCKSIZE	32
static int kmac_drng_selftest_large(struct lc_kmac256_drng_state *kmac_ctx)
{
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};
	uint8_t out[KMAC256_TEST_BLOCKSIZE];
	unsigned int i;

	lc_kmac256_drng_seed(kmac_ctx, seed, sizeof(seed));

	for (i = 0; i < ((1U<<30) / KMAC256_TEST_BLOCKSIZE); i++)
		lc_kmac256_drng_generate(kmac_ctx, NULL, 0, out,
					 KMAC256_TEST_BLOCKSIZE);
	lc_kmac256_drng_zero(kmac_ctx);

	return 0;
}


int main(int argc, char *argv[])
{
	LC_KMAC256_DRNG_CTX_ON_STACK(kmac_ctx);
	int ret = kmac_drng_selftest_large(kmac_ctx);

	(void)argc;
	(void)argv;

	return ret;
}
