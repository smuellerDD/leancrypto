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
#include "seeded_rng_linux.h"
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

int seeded_rng_noise_init(void)
{
	unsigned int flags = 0;
	int ret;

	/* Allow the init function to be called multiple times */
	seeded_rng_noise_fini();

	flags |= fips140_mode_enabled() ? JENT_FORCE_FIPS : 0;

	CKINT(jent_entropy_init_ex(0, flags));

	esdm_jent_state = jent_entropy_collector_alloc(0, flags);
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
