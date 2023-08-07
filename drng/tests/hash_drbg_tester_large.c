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

#include "lc_hash_drbg.h"
#include "small_stack_support.h"

static int hash_drbg_selftest_large(struct lc_rng_ctx *drbg)
{
	struct workspace {
		uint8_t out[LC_DRBG_MAX_REQUEST_BYTES];
	};
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};
	unsigned int i;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (lc_rng_seed(drbg, seed, sizeof(seed), NULL, 0))
		goto out;

	for (i = 0; i < ((1U << 30) / LC_DRBG_MAX_REQUEST_BYTES); i++)
		lc_rng_generate(drbg, NULL, 0, ws->out, sizeof(ws->out));

out:
	lc_rng_zero(drbg);
	LC_RELEASE_MEM(ws);
	return ret;
}

int main(int argc, char *argv[])
{
#ifdef LC_MEM_ON_HEAP
	struct lc_rng_ctx *drbg;
	int ret = lc_drbg_hash_alloc(&drbg);
	if (ret)
		return ret;
#else
	LC_DRBG_HASH_CTX_ON_STACK(drbg);
	int ret;
#endif

	ret = hash_drbg_selftest_large(drbg);

	(void)argc;
	(void)argv;

#ifdef LC_MEM_ON_HEAP
	lc_rng_zero_free(drbg);
#else
	lc_rng_zero(drbg);
#endif
	return ret;
}
