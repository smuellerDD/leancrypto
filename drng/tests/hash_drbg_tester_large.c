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

#include "lc_hash_drbg.h"

static int hash_drbg_selftest_large(struct lc_rng_ctx *drbg)
{
	uint8_t seed[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
	};
	uint8_t out[LC_DRBG_MAX_REQUEST_BYTES];
	unsigned int i;
	int ret = 0;

	if (lc_rng_seed(drbg, seed, sizeof(seed), NULL, 0))
		goto out;

	for (i = 0; i < ((1U<<30) / LC_DRBG_MAX_REQUEST_BYTES); i++)
		lc_rng_generate(drbg, NULL, 0, out, sizeof(out));

out:
	lc_rng_zero(drbg);
	return ret;
}


int main(int argc, char *argv[])
{
	LC_DRBG_HASH_CTX_ON_STACK(drbg);
	int ret = hash_drbg_selftest_large(drbg);

	(void)argc;
	(void)argv;

	return ret;
}
