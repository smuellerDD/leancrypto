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

/*
 * Shall the GLIBC getrandom stub be used (requires GLIBC >= 2.25)
 */
#define USE_GLIBC_GETRANDOM

#ifdef USE_GLIBC_GETRANDOM
#include <sys/random.h>
#else
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#endif

#include <limits.h>
#include <time.h>

#include "lc_chacha20_drng.h"
#include "lc_cshake256_drng.h"
#include "lc_drng_config.h"
#include "lc_kmac256_drng.h"
#include "lc_hash_drbg.h"
#include "lc_hmac_drbg_sha512.h"
#include "lc_rng.h"
#include "ret_checkers.h"
#include "visibility.h"

/* Select the type of DRNG */

#ifdef LC_DRNG_CSHAKE
/* Use cSHAKE 256 */
# define LC_SEEDED_RNG_CTX_SIZE		LC_CSHAKE256_DRNG_CTX_SIZE
# define LC_SEEDED_RNG_CTX(name)	LC_CSHAKE256_RNG_CTX(name)

#elif defined(LC_DRNG_KMAC)
/* Use KMAC 256 */
# define LC_SEEDED_RNG_CTX_SIZE		LC_KMAC256_DRNG_CTX_SIZE
# define LC_SEEDED_RNG_CTX(name)	LC_KMAC256_RNG_CTX(name)

#elif defined(LC_DRNG_HASH_DRBG)
/* Use Hash DRBG SHA512 */
# define LC_SEEDED_RNG_CTX_SIZE		LC_DRBG_HASH_CTX_SIZE
# define LC_SEEDED_RNG_CTX(name)	LC_DRBG_HASH_RNG_CTX(name)

#elif defined(LC_DRNG_HMAC_DRBG)
/* Use HMAC DRBG SHA512 */
# define LC_SEEDED_RNG_CTX_SIZE		LC_DRBG_HMAC_CTX_SIZE(LC_DRBG_HMAC_CORE)
# define LC_SEEDED_RNG_CTX(name)	LC_DRBG_HMAC_RNG_CTX(name)

#else
# error "Undefined DRNG"
#endif

#define LC_SEEDED_RNG_PERS		"Seeded RNG"

struct lc_seeded_rng_ctx {
	struct lc_rng_ctx *rng_ctx;
#define LC_SEEDED_RNG_MAX_BYTES		(1<<10) /* Max bytes without reseed */
	size_t bytes;
#define LC_SEEDED_RNG_MAX_TIME		60 /* Max seconds without reseed */
	time_t last_seeded;
};

/* DRNG state */
static LC_ALIGNED_BUFFER(rng_ctx_buf, LC_SEEDED_RNG_CTX_SIZE,
			 LC_HASH_COMMON_ALIGNMENT);
static struct lc_seeded_rng_ctx seeded_rng = {
	.rng_ctx = (struct lc_rng_ctx *)rng_ctx_buf,

	/* Initialize the state such that a seed is forced */
	.bytes = LC_SEEDED_RNG_MAX_BYTES + 1,
	.last_seeded = 0
};

static inline ssize_t __getrandom(uint8_t *buffer, size_t bufferlen,
				  unsigned int flags)
{
	ssize_t ret, totallen = 0;

	if (bufferlen > INT_MAX)
		return -EINVAL;

	do {
#ifdef USE_GLIBC_GETRANDOM
		ret = getrandom(buffer, bufferlen, flags);
#else
		ret = syscall(__NR_getrandom, buffer, bufferlen, flags);
#endif
		if (ret > 0) {
			bufferlen -= (size_t)ret;
			buffer += ret;
			totallen += ret;
		}
	} while ((ret > 0 || errno == EINTR) && bufferlen);

	return ((ret < 0) ? -errno : totallen);
}

static inline ssize_t getrandom_random(uint8_t *buffer, size_t bufferlen)
{
	return __getrandom(buffer, bufferlen, GRND_RANDOM);
}

static int lc_seed_seeded_rng(struct lc_seeded_rng_ctx *rng, int init)
{
	uint8_t seed[256 / 8];
	int ret;

	if (!rng)
		return -EINVAL;

	/* Seed it with 256 bits of entropy */
	if (getrandom_random(seed, sizeof(seed)) != sizeof(seed))
		return -EFAULT;

	CKINT(lc_rng_seed(rng->rng_ctx, seed, sizeof(seed),
			  (uint8_t *)LC_SEEDED_RNG_PERS,
			  sizeof(LC_SEEDED_RNG_PERS) - 1));

	/* Insert 128 additional bits of entropy to the DRNG */
	if (init) {
		if (getrandom_random(seed, sizeof(seed) / 2) !=
		    sizeof(seed) / 2)
			return -EFAULT;

		CKINT(lc_rng_seed(rng->rng_ctx, seed, sizeof(seed) / 2,
				  NULL, 0));
	}

	rng->bytes = 0;
	rng->last_seeded = time(NULL);

out:
	memset_secure(seed, 0, sizeof(seed));
	return ret;
}

static void lc_seeded_rng_zero_state(void)
{
	struct lc_rng_ctx *rng;

	rng = seeded_rng.rng_ctx;
	if (!rng)
		return;
	seeded_rng.rng_ctx = NULL;
	lc_rng_zero(rng);
}

static int time_after(time_t curr, time_t base)
{
        if (curr == (time_t)-1)
                return 0;
        if (base == (time_t)-1)
                return 1;
        return (curr > base) ? 1 : 0;
}

static time_t time_after_now(time_t base)
{
        time_t curr = time(NULL);

        if (curr == (time_t)-1)
                return 0;
        return time_after(curr, base) ? (curr - base) : 0;
}

static int lc_seeded_rng_must_reseed(struct lc_seeded_rng_ctx *rng)
{
        return (rng->bytes > LC_SEEDED_RNG_MAX_BYTES ||
                time_after_now(rng->last_seeded + LC_SEEDED_RNG_MAX_TIME));
}

static int lc_get_seeded_rng(struct lc_seeded_rng_ctx **rng_ret)
{
	int ret = 0, init = 0;

	/* Initialize the DRNG state at the beginning */
	if (!seeded_rng.last_seeded) {
		LC_SEEDED_RNG_CTX(seeded_rng.rng_ctx);
		atexit(lc_seeded_rng_zero_state);
		init = 1;
	}

	/* Force reseed if needed */
	if (lc_seeded_rng_must_reseed(&seeded_rng))
		CKINT(lc_seed_seeded_rng(&seeded_rng, init));

	*rng_ret = &seeded_rng;

out:
	return ret;
}

/****************************** lc_rng Interface ******************************/
static int
lc_seeded_rng_generate(void *_state,
		       const uint8_t *addtl_input, size_t addtl_input_len,
		       uint8_t *out, size_t outlen)
{
	struct lc_seeded_rng_ctx *rng = NULL;
	int ret;

	if (_state)
		return -EINVAL;

	/* Get the DRNG state that is fully seeded */
	CKINT(lc_get_seeded_rng(&rng));
	/* Generate random numbers */
	CKINT(lc_rng_generate(rng->rng_ctx, addtl_input, addtl_input_len,
			      out, outlen));
	rng->bytes += outlen;

out:
	return ret;
}

static int
lc_seeded_rng_seed(void *_state,
		   const uint8_t *seed, size_t seedlen,
		   const uint8_t *persbuf, size_t perslen)
{
	struct lc_seeded_rng_ctx *rng;
	int ret;

	if (_state)
		return -EINVAL;

	CKINT(lc_get_seeded_rng(&rng));
	CKINT(lc_seed_seeded_rng(rng, 0));
	CKINT(lc_rng_seed(rng->rng_ctx, seed, seedlen, persbuf, perslen));

out:
	return ret;
}

static void lc_seeded_rng_zero(void *_state)
{
	(void)_state;

	/* Do nothing */
}

static const struct lc_rng _lc_seeded_rng = {
	.generate	= lc_seeded_rng_generate,
	.seed		= lc_seeded_rng_seed,
	.zero		= lc_seeded_rng_zero,
};

static struct lc_rng_ctx _lc_seeded_rng_ctx = { &_lc_seeded_rng, NULL };

LC_INTERFACE_SYMBOL(struct lc_rng_ctx *, lc_seeded_rng) = &_lc_seeded_rng_ctx;
