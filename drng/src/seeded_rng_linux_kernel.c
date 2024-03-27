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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <crypto/rng.h>
#include <linux/fips.h>
#include <linux/module.h>
#include <linux/random.h>

#include "seeded_rng.h"

static struct crypto_rng *jent = NULL;

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	int ret;

	if (IS_ERR_OR_NULL(jent)) {
		get_random_bytes(buffer, bufferlen);
		return (ssize_t)bufferlen;
	}

	/* Get data from random.c */
	get_random_bytes(buffer, bufferlen);

	/*
	 * Get data from Jitter RNG
	 *
	 * For this to work, we assume that the buffer is twice as large as
	 * defined by bufferlen.
	 */
	ret = crypto_rng_get_bytes(jent, buffer + bufferlen, bufferlen);
	if (fips_enabled && ret)
		return (ssize_t)ret;

	return (ssize_t)(bufferlen * 2);
}

void seeded_rng_noise_fini(void)
{
	if (!IS_ERR_OR_NULL(jent))
		crypto_free_rng(jent);
	jent = NULL;
}

int seeded_rng_noise_init(void)
{
	jent = crypto_alloc_rng("jitterentropy_rng", 0, 0);
	if (IS_ERR(jent)) {
		const int err = PTR_ERR(jent);

		jent = NULL;
		if (fips_enabled)
			return err;
		pr_info("DRBG: Continuing without Jitter RNG\n");
	}
	return 0;
}
