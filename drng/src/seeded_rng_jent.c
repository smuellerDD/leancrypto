/*
 * Fast Entropy Source: Jitter RNG
 *
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#include <jitterentropy.h>

#include "fips_mode.h"
#include "seeded_rng.h"
#include "seeded_rng_jent_config.h"
#include "ret_checkers.h"
#include "visibility.h"

static struct rand_data *esdm_jent_state = NULL;

void seeded_rng_noise_fini(void)
{
	if (!esdm_jent_state)
		return;

	jent_entropy_collector_free(esdm_jent_state);
	esdm_jent_state = NULL;
}

#if JENT_VERSION >= 3070000
static int seeded_rng_jent_ntg1()
{
        const int jent_secure_memory = jent_secure_memory_supported();
# ifdef LC_JENT_NTG1
        const int jent_ntg1 = 1;
# else
        const int jent_ntg1 = 0;
# endif

        return jent_secure_memory && jent_ntg1;
}
#endif /* JENT_VERSION */

int seeded_rng_noise_init(void)
{
	unsigned int flags = 0;
	int ret;

	/* Allow the init function to be called multiple times */
	seeded_rng_noise_fini();

	if (fips140_mode_enabled())
		flags |= JENT_FORCE_FIPS;

#if JENT_VERSION >= 3070000
	if (seeded_rng_jent_ntg1())
		flags |= JENT_NTG1;

#ifdef LC_JENT_ALL_CACHES
	flags |= JENT_CACHE_ALL;
#endif

	switch (LC_JENT_MAX_MEM) {
	case 1:
		flags |= JENT_MAX_MEMSIZE_1kB;
		break;
	case 2:
		flags |= JENT_MAX_MEMSIZE_2kB;
		break;
	case 3:
		flags |= JENT_MAX_MEMSIZE_4kB;
		break;
	case 4:
		flags |= JENT_MAX_MEMSIZE_8kB;
		break;
	case 5:
		flags |= JENT_MAX_MEMSIZE_16kB;
		break;
	case 6:
		flags |= JENT_MAX_MEMSIZE_32kB;
		break;
	case 7:
		flags |= JENT_MAX_MEMSIZE_64kB;
		break;
	case 8:
		flags |= JENT_MAX_MEMSIZE_128kB;
		break;
	case 9:
		flags |= JENT_MAX_MEMSIZE_256kB;
		break;
	case 10:
		flags |= JENT_MAX_MEMSIZE_512kB;
		break;
	case 11:
		flags |= JENT_MAX_MEMSIZE_1MB;
		break;
	case 12:
		flags |= JENT_MAX_MEMSIZE_2MB;
		break;
	case 13:
		flags |= JENT_MAX_MEMSIZE_4MB;
		break;
	case 14:
		flags |= JENT_MAX_MEMSIZE_8MB;
		break;
	case 15:
		flags |= JENT_MAX_MEMSIZE_16MB;
		break;
	case 16:
		flags |= JENT_MAX_MEMSIZE_32MB;
		break;
	case 17:
		flags |= JENT_MAX_MEMSIZE_64MB;
		break;
	case 18:
		flags |= JENT_MAX_MEMSIZE_128MB;
		break;
	case 19:
		flags |= JENT_MAX_MEMSIZE_256MB;
		break;
	case 20:
		flags |= JENT_MAX_MEMSIZE_512MB;
		break;
	}

	switch (LC_JENT_HASH_LOOP_COUNT) {
	case 0:
		flags |= JENT_HASHLOOP_1;
		break;
	case 1:
		flags |= JENT_HASHLOOP_2;
		break;
	case 2:
		flags |= JENT_HASHLOOP_4;
		break;
	case 3:
		flags |= JENT_HASHLOOP_8;
		break;
	case 4:
		flags |= JENT_HASHLOOP_16;
		break;
	case 5:
		flags |= JENT_HASHLOOP_32;
		break;
	case 6:
		flags |= JENT_HASHLOOP_64;
		break;
	case 7:
		flags |= JENT_HASHLOOP_128;
		break;
	}
#endif /* JENT_VERSION >= 3070000 */

	CKINT(jent_entropy_init_ex(LC_JENT_OSR, flags));

	esdm_jent_state = jent_entropy_collector_alloc(LC_JENT_OSR, flags);
	CKNULL(esdm_jent_state, -EFAULT);

out:
	return ret;
}

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	ssize_t ret;

	ret = jent_read_entropy_safe(&esdm_jent_state, (char *)buffer,
				     bufferlen);

	switch (ret) {
	case -1:
		ret = -EOPNOTSUPP;
		break;
	/* Temporary errors */
	case -2:
	case -3:
	case -5:
		ret = -ENODATA;
		break;
	/* Permanent errors */
	case -6:
	case -7:
	case -8:
	case -4:
		ret = -EFAULT;
		break;
	default:
		break;
	}

	return ret;
}
