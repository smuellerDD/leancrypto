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

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "lc_memcmp_secure.h"
#include "lc_rng.h"
#include "ret_checkers.h"
#include "test_helper_common.h"

static int seeded_rng_selftest(void)
{
	uint8_t act1[64], act2[sizeof(act1)];
	int ret;

	memset(act1, 0, sizeof(act1));
	memset(act2, 0, sizeof(act2));
	CKINT_LOG(lc_rng_generate(lc_seeded_rng, NULL, 0, act1, sizeof(act1)),
		  "Cannot generate random numbers using seeded DRNG: %d\n",
		  ret);

	CKINT_LOG(lc_rng_set_seeded(lc_seeded_rng), "Cannot set seeded RNG\n");

	CKINT_LOG(lc_rng_generate(lc_seeded_rng, NULL, 0, act2, sizeof(act2)),
		  "Cannot generate random numbers using seeded DRNG: %d\n",
		  ret);
	if (!lc_memcmp_secure(act1, sizeof(act1), act2, sizeof(act2))) {
		printf("Seeded RNG produced identical data\n");
		return 1;
	}

out:
	return ret ? 1 : 0;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = seeded_rng_selftest();

#ifdef LC_DRNG_HASH_DRBG
	ret = test_validate_fips_status(ret,
					LC_ALG_STATUS_HASH_DRBG |
					LC_ALG_STATUS_TYPE_SEEDED_RNG, 1);
#endif
#ifdef LC_DRNG_HMAC_DRBG
	ret = test_validate_fips_status(ret,
					LC_ALG_STATUS_HMAC_DRBG |
					LC_ALG_STATUS_TYPE_SEEDED_RNG, 1);
#endif
#ifdef LC_DRNG_XDRBG128
	ret = test_validate_fips_status(ret,
					LC_ALG_STATUS_XDRBG128 |
					LC_ALG_STATUS_TYPE_SEEDED_RNG, 0);
#endif
#ifdef LC_DRNG_XDRBG256
	ret = test_validate_fips_status(ret,
					LC_ALG_STATUS_XDRBG256 |
					LC_ALG_STATUS_TYPE_SEEDED_RNG, 0);
	ret = test_validate_fips_status(ret,
					LC_ALG_STATUS_XDRBG512 |
					LC_ALG_STATUS_TYPE_SEEDED_RNG, 0);
#endif
#ifdef LC_DRNG_CSHAKE
	ret = test_validate_fips_status(ret,
					LC_ALG_STATUS_CSHAKE_DRBG |
					LC_ALG_STATUS_TYPE_SEEDED_RNG, 0);
#endif
#ifdef LC_DRNG_KMAC
	ret = test_validate_fips_status(ret,
					LC_ALG_STATUS_KMAC_DRBG |
					LC_ALG_STATUS_TYPE_SEEDED_RNG, 0);
#endif

	return ret;
}
