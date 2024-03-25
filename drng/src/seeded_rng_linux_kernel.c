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

#include "lc_hash.h"
#include "seeded_rng.h"

#ifdef CONFIG_LEANCRYPTO_SHA3
# include "lc_sha3.h"
# define LC_SEEDED_RNG_LINUX_KERNEL_HASH lc_sha3_256

#elif defined(CONFIG_LEANCRYPTO_SHA2_256)
# include "lc_sha256.h"
# define LC_SEEDED_RNG_LINUX_KERNEL_HASH lc_sha_256

#else
# error "Neither SHA3-256 nor SHA-256 present"
#endif

#define LC_SEEDED_RNG_LINUX_KERNEL_DIGESTSIZE 32

static struct crypto_rng *jent = NULL;

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	uint8_t seed[(256 / 8) * 2];

	/* This must not happen - seeded_rng.c consumes at most 256 bits */
	BUG_ON(sizeof(seed) / 2 < bufferlen);

	if (IS_ERR_OR_NULL(jent)) {
		get_random_bytes(buffer, bufferlen);
	} else {
		int ret;

		/* Get data from random.c */
		get_random_bytes(seed, bufferlen);

		/* Get data from Jitter RNG */
		ret = crypto_rng_get_bytes(jent, seed + bufferlen, bufferlen);
		if (fips_enabled && ret)
			return (ssize_t)ret;

		/* Compress the data using the given hash algo */
		if (bufferlen >= LC_SEEDED_RNG_LINUX_KERNEL_DIGESTSIZE) {
			WARN_ON(bufferlen >
				LC_SEEDED_RNG_LINUX_KERNEL_DIGESTSIZE);

			/* parts of seed may be uninitalized - we are ok */
			lc_hash(LC_SEEDED_RNG_LINUX_KERNEL_HASH, seed,
				sizeof(seed), buffer);
		} else {
			BUILD_BUG_ON(sizeof(seed) <
					    LC_SEEDED_RNG_LINUX_KERNEL_DIGESTSIZE);

			/* parts of seed may be uninitalized - we are ok */
			lc_hash(LC_SEEDED_RNG_LINUX_KERNEL_HASH, seed,
				sizeof(seed), seed);

			memcpy(buffer, seed, bufferlen);
		}
		memzero_explicit(seed, sizeof(seed));
	}

	return (ssize_t)bufferlen;
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
