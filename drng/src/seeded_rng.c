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

#include "ext_headers.h"
#include "lc_chacha20_drng.h"
#include "lc_cshake256_drng.h"
#include "lc_kmac256_drng.h"
#include "lc_hash_drbg.h"
#include "lc_hmac_drbg_sha512.h"
#include "lc_rng.h"
#include "lc_xdrbg256.h"
#include "ret_checkers.h"
#include "seeded_rng.h"
#include "visibility.h"

/* Select the type of DRNG */

#ifdef LINUX_KERNEL
//TODO make this selectible based on KBUILD
#define CONFIG_LEANCRYPTO_XDRBG256_DRNG

#ifdef CONFIG_LEANCRYPTO_XDRBG256_DRNG
#define LC_DRNG_XDRBG_256
#endif
#ifdef CONFIG_LEANCRYPTO_KMAC_DRNG
#define LC_DRNG_KMAC
#endif
#ifdef CONFIG_LEANCRYPTO_CSHAKE_DRNG
#define LC_DRNG_CSHAKE
#endif
#ifdef CONFIG_LEANCRYPTO_HASH_DRBG
#define LC_DRNG_HASH_DRBG
#endif
#ifdef CONFIG_LEANCRYPTO_HMAC_DRBG
#define LC_DRNG_HMAC_DRBG
#endif
#else
#include "lc_drng_config.h"
#endif

#ifdef LC_DRNG_XDRBG_256
#define LC_SEEDED_RNG_CTX_SIZE LC_XDRBG256_DRNG_CTX_SIZE
#define LC_SEEDED_RNG_CTX(name) LC_XDRBG256_RNG_CTX(name)

#elif defined(LC_DRNG_CSHAKE)
/* Use cSHAKE 256 */
#define LC_SEEDED_RNG_CTX_SIZE LC_CSHAKE256_DRNG_CTX_SIZE
#define LC_SEEDED_RNG_CTX(name) LC_CSHAKE256_RNG_CTX(name)

#elif defined(LC_DRNG_KMAC)
/* Use KMAC 256 */
#define LC_SEEDED_RNG_CTX_SIZE LC_KMAC256_DRNG_CTX_SIZE
#define LC_SEEDED_RNG_CTX(name) LC_KMAC256_RNG_CTX(name)

#elif defined(LC_DRNG_HASH_DRBG)
/* Use Hash DRBG SHA512 */
#define LC_SEEDED_RNG_CTX_SIZE LC_DRBG_HASH_CTX_SIZE
#define LC_SEEDED_RNG_CTX(name) LC_DRBG_HASH_RNG_CTX(name)

#elif defined(LC_DRNG_HMAC_DRBG)
/* Use HMAC DRBG SHA512 */
#define LC_SEEDED_RNG_CTX_SIZE LC_DRBG_HMAC_CTX_SIZE(LC_DRBG_HMAC_CORE)
#define LC_SEEDED_RNG_CTX(name) LC_DRBG_HMAC_RNG_CTX(name)

#else
#error "Undefined DRNG"
#endif

#define LC_SEEDED_RNG_PERS "Seeded RNG"

struct lc_seeded_rng_ctx {
	struct lc_rng_ctx *rng_ctx;
#define LC_SEEDED_RNG_MAX_BYTES (1 << 10) /* Max bytes without reseed */
	size_t bytes;
#define LC_SEEDED_RNG_MAX_TIME 60 /* Max seconds without reseed */
	unsigned long last_seeded;
	pid_t pid; /* Detect a fork */
};

/* DRNG state */
static LC_ALIGNED_BUFFER(rng_ctx_buf, LC_SEEDED_RNG_CTX_SIZE,
			 LC_HASH_COMMON_ALIGNMENT);
static struct lc_seeded_rng_ctx seeded_rng = {
	.rng_ctx = (struct lc_rng_ctx *)rng_ctx_buf,

	/* Initialize the state such that a seed is forced */
	.bytes = LC_SEEDED_RNG_MAX_BYTES + 1,
	.last_seeded = 0,
	.pid = 0
};

#ifdef LINUX_KERNEL

static unsigned long get_time(void)
{
	return jiffies / HZ;
}

#else /* LINUX_KERNEL */

static int time_after(unsigned long curr, unsigned long base)
{
	if (curr == (unsigned long)-1)
		return 0;
	if (base == (unsigned long)-1)
		return 1;
	return (curr > base) ? 1 : 0;
}

static unsigned long get_time(void)
{
	time_t t = time(NULL);

	if (t == (time_t)-1)
		return 0;
	return (unsigned long)t;
}

#endif /* LINUX_KERNEL */

static int lc_seed_seeded_rng(struct lc_seeded_rng_ctx *rng, int init,
			      pid_t newpid)
{
	uint8_t seed[256 / 8];
	int ret;

	if (!rng)
		return -EINVAL;

	/* Seed it with 256 bits of entropy */
	if (get_full_entropy(seed, sizeof(seed)) != sizeof(seed))
		return -EFAULT;

	CKINT(lc_rng_seed(rng->rng_ctx, seed, sizeof(seed),
			  (uint8_t *)LC_SEEDED_RNG_PERS,
			  sizeof(LC_SEEDED_RNG_PERS) - 1));

	/* Insert 128 additional bits of entropy to the DRNG */
	if (init) {
		if (get_full_entropy(seed, sizeof(seed) / 2) !=
		    sizeof(seed) / 2)
			return -EFAULT;

		CKINT(lc_rng_seed(rng->rng_ctx, seed, sizeof(seed) / 2, NULL,
				  0));
	}

	rng->bytes = 0;
	rng->last_seeded = get_time();

	/* If we are given a new PID, apply it after a successful reseed */
	if (newpid)
		rng->pid = newpid;

out:
	lc_memset_secure(seed, 0, sizeof(seed));
	return ret;
}

static int lc_seeded_rng_init_state(void)
{
	LC_SEEDED_RNG_CTX(seeded_rng.rng_ctx);

	return seeded_rng_noise_init();
}

LC_DEFINE_DESTRUCTOR(lc_seeded_rng_zero_state);
void lc_seeded_rng_zero_state(void)
{
	struct lc_rng_ctx *rng;

	rng = seeded_rng.rng_ctx;
	if (!rng)
		return;
	seeded_rng.rng_ctx = NULL;

	if (seeded_rng.last_seeded)
		lc_rng_zero(rng);

	seeded_rng_noise_fini();
}

static unsigned long time_after_now(unsigned long base)
{
	unsigned long curr = get_time();

	return time_after(curr, base) ? (curr - base) : 0;
}

static int lc_seeded_rng_must_reseed(struct lc_seeded_rng_ctx *rng,
				     pid_t *newpid)
{
	pid_t pid;

	/* Reseed if ... */

	/* ... we generated too much data ... */
	if (rng->bytes > LC_SEEDED_RNG_MAX_BYTES)
		return 1;

	/* ... or our seeding was too long ago ... */
	if (time_after_now(rng->last_seeded + LC_SEEDED_RNG_MAX_TIME))
		return 1;

	/*
	 * ... or we detected a fork (do not set the pid here. It is only set if
	 * the reseed was successful).
	 */
	pid = getpid();
	if (rng->pid != pid) {
		*newpid = pid;
		return 1;
	}

	return 0;
}

static int lc_get_seeded_rng(struct lc_seeded_rng_ctx **rng_ret)
{
	pid_t newpid = 0;
	int ret = 0, init = 0;

	/* Initialize the DRNG state at the beginning */
	if (!seeded_rng.last_seeded) {
		CKINT(lc_seeded_rng_init_state());
		seeded_rng.pid = getpid();
		init = 1;
	}

	/* Force reseed if needed */
	if (lc_seeded_rng_must_reseed(&seeded_rng, &newpid))
		CKINT(lc_seed_seeded_rng(&seeded_rng, init, newpid));

	*rng_ret = &seeded_rng;

out:
	return ret;
}

/****************************** lc_rng Interface ******************************/
static int lc_seeded_rng_generate(void *_state, const uint8_t *addtl_input,
				  size_t addtl_input_len, uint8_t *out,
				  size_t outlen)
{
	struct lc_seeded_rng_ctx *rng = NULL;
	int ret;

	if (_state)
		return -EINVAL;

	/* Get the DRNG state that is fully seeded */
	CKINT(lc_get_seeded_rng(&rng));
	/* Generate random numbers */
	CKINT(lc_rng_generate(rng->rng_ctx, addtl_input, addtl_input_len, out,
			      outlen));
	rng->bytes += outlen;

out:
	return ret;
}

static int lc_seeded_rng_seed(void *_state, const uint8_t *seed, size_t seedlen,
			      const uint8_t *persbuf, size_t perslen)
{
	struct lc_seeded_rng_ctx *rng;
	int ret;

	if (_state)
		return -EINVAL;

	CKINT(lc_get_seeded_rng(&rng));
	CKINT(lc_seed_seeded_rng(rng, 0, 0));
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
	.generate = lc_seeded_rng_generate,
	.seed = lc_seeded_rng_seed,
	.zero = lc_seeded_rng_zero,
};

static struct lc_rng_ctx _lc_seeded_rng_ctx = { &_lc_seeded_rng, NULL };

LC_INTERFACE_SYMBOL(struct lc_rng_ctx *, lc_seeded_rng) = &_lc_seeded_rng_ctx;
