/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "lc_sha3.h"
#include "math_helper.h"
#include "seeded_rng.h"
#include "es_cpu/cpu_random.h"

static uint32_t seeded_rng_cpu_data_multiplier = 0;

static ssize_t seeded_rng_cpu_data(uint8_t *buffer, size_t bufferlen)
{
	size_t origlen = bufferlen;
	unsigned long tmp;

	while (bufferlen) {
		size_t todo = min_size(bufferlen, sizeof(tmp));

		if (!cpu_es_get(&tmp))
			return 0;

		memcpy(buffer, &tmp, todo);
		buffer += todo;
		bufferlen -= todo;
	}

	return (ssize_t)origlen;
}

static ssize_t seeded_rng_cpu_data_compress(uint8_t *outbuf, size_t requested,
					    uint32_t multiplier)
{
	LC_HASH_CTX_ON_STACK(hash, lc_sha3_512);
	size_t digestsize, full_bytes;
	unsigned long tmp;
	ssize_t ret = (ssize_t)requested;

	digestsize = lc_hash_digestsize(hash);
	/* Cap to maximum entropy that can ever be generated with given hash */
	if (digestsize < requested)
		requested = digestsize;

	/*
	 * Calculate the number of bytes to fetch. As we use a hash conditioner,
	 * apply the oversampling as defined in SP800-90C for the conditioner.
	 */
	full_bytes = (requested + 64) * multiplier;

	lc_hash_init(hash);

	/* Hash all data from the CPU entropy source */
	while (full_bytes) {
		size_t todo = min_size(full_bytes, sizeof(tmp));

		if (!cpu_es_get(&tmp)) {
			ret = 0;
			goto out;
		}

		lc_hash_update(hash, (uint8_t *)&tmp, todo);
	}

	/* Generate the compressed data to be returned to the caller */
	if (requested < digestsize) {
		uint8_t digest[LC_SHA_MAX_SIZE_DIGEST];

		lc_hash_final(hash, digest);

		/* Truncate output data to requested size */
		memcpy(outbuf, digest, requested);
		lc_memset_secure(digest, 0, digestsize);
	} else {
		lc_hash_final(hash, outbuf);
	}

out:
	lc_hash_zero(hash);
	return ret;
}

/*
 * If CPU entropy source requires does not return full entropy, return the
 * multiplier of how much data shall be sampled from it.
 */
static uint32_t seeded_rng_cpu_multiplier(void)
{
	if (seeded_rng_cpu_data_multiplier > 0)
		return seeded_rng_cpu_data_multiplier;

	seeded_rng_cpu_data_multiplier = cpu_es_multiplier();
	if (!seeded_rng_cpu_data_multiplier)
		seeded_rng_cpu_data_multiplier = 1;

	return seeded_rng_cpu_data_multiplier;
}

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	uint32_t multiplier = seeded_rng_cpu_multiplier();

	if (multiplier <= 1)
		return seeded_rng_cpu_data(buffer, bufferlen);

	return seeded_rng_cpu_data_compress(buffer, bufferlen, multiplier);
}

void seeded_rng_noise_fini(void)
{
}

int seeded_rng_noise_init(void)
{
	seeded_rng_cpu_data_multiplier = 0;
	return 0;
}
