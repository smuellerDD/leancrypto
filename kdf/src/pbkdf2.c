/* PBKDF2 - SP800-132
 *
 * Copyright (C) 2016 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#include "alignment.h"
#include "compare.h"
#include "conv_be_le.h"
#include "ext_headers_internal.h"
#include "fips_mode.h"
#include "lc_hmac.h"
#include "lc_pbkdf2.h"
#include "lc_memset_secure.h"
#include "lc_sha256.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "xor.h"

#if 0
static inline uint64_t kcapi_get_time(void)
{
	struct timespec time;

	if (clock_gettime(CLOCK_REALTIME, &time) == 0)
		return (uint64_t)time.tv_nsec;

	return 0;
}

uint32_t kcapi_pbkdf_iteration_count(const char *hashname, uint64_t timeshresh)
{
#define LOW_ITERATION_COUNT (UINT32_C(1 << 16))
#define SAFE_ITERATION_COUNT (UINT32_C(1 << 18))
#define SAFE_ITERATION_TIME (UINT32_C(1 << 27)) /* more than 100,000,000 ns */
	uint32_t i = 1;
	uint32_t j;

	/* Safety measure */
	if (!kcapi_get_time())
		return (SAFE_ITERATION_COUNT);

	if (timeshresh == 0)
		timeshresh = SAFE_ITERATION_TIME;

	/* The outer loop catches rescheduling operations */
	for (j = 0; j < 2; j++) {
		for (; i < UINT_MAX; i<<=1) {
			uint64_t end, start = kcapi_get_time();
			uint8_t outbuf[16];
			ssize_t ret = kcapi_pbkdf(hashname,
						  (uint8_t *)"passwordpassword",
						  16, (uint8_t *)"salt", 4,
						  i, outbuf, sizeof(outbuf));

			end = kcapi_get_time();

			/* Safety measure */
			if (ret < 0)
				return (SAFE_ITERATION_COUNT);

			/* Take precautions if time runs backwards */
			if (end > start)
				end = end - start;
			else
				end = start - end;

			if (end > timeshresh)
				break;
			else
				j = 0;
		}
	}

	if (i < LOW_ITERATION_COUNT)
		i = LOW_ITERATION_COUNT;

	return i;
}
#endif

static int lc_pbkdf2_nocheck(const struct lc_hash *hash, const uint8_t *pw,
			     size_t pwlen, const uint8_t *salt, size_t saltlen,
			     const uint32_t count, uint8_t *key,size_t keylen)
{
	size_t h = 0;
	uint32_t i = 1;
#define MAX_DIGESTSIZE 64
	uint8_t u[LC_SHA_MAX_SIZE_DIGEST] __align(sizeof(uint64_t));
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);
	int ret;

	if (keylen > INT_MAX)
		return -EMSGSIZE;

	if (count == 0)
		return -EINVAL;

	CKINT(lc_hmac_init(hmac_ctx, pw, pwlen));
	h = lc_hmac_macsize(hmac_ctx);

	memset(key, 0, keylen);

	while (keylen) {
		uint32_t j;
		uint32_t ibe = be_bswap32(i);

		lc_hmac_update(hmac_ctx, salt, saltlen);
		lc_hmac_update(hmac_ctx, (uint8_t *)&ibe, sizeof(uint32_t));

		for (j = 0; j < count; j++) {
			if (j)
				lc_hmac_update(hmac_ctx, u, h);

			lc_hmac_final(hmac_ctx, u);
			lc_hmac_reinit(hmac_ctx);

			xor_64(key, u, keylen < h ? keylen : h);
		}

		if (keylen < h)
			goto out;
		else {
			keylen -= h;
			key += h;
			i++;
		}
	}

out:
	lc_memset_secure(u, 0, h);
	lc_hmac_zero(hmac_ctx);

	return ret;
}

static void lc_pbkdf2_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t pw[] = { FIPS140_MOD(0x70), 0x61, 0x73, 0x73,
				      0x77, 0x6f, 0x72, 0x64 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t salt[] = { 0x73, 0x61, 0x6c, 0x74 };
	LC_FIPS_RODATA_SECTION
	static const uint8_t exp_256[] = { 0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b,
					   0x46, 0xd3, 0x2d, 0x0a, 0xdf, 0xf9,
					   0x28, 0xf0, 0x6d, 0xd0, 0x2a, 0x30,
					   0x3f, 0x8e };
	uint8_t act[sizeof(exp_256)];

	LC_SELFTEST_RUN(LC_ALG_STATUS_PBKDF2);

	lc_pbkdf2_nocheck(lc_sha256, pw, sizeof(pw), salt, sizeof(salt), 2, act,
			  sizeof(act));
	lc_compare_selftest(LC_ALG_STATUS_PBKDF2, act, exp_256,
			    sizeof(exp_256), "PBKDF2");
}

LC_INTERFACE_FUNCTION(int, lc_pbkdf2, const struct lc_hash *hash,
		      const uint8_t *pw, size_t pwlen, const uint8_t *salt,
		      size_t saltlen, const uint32_t count, uint8_t *key,
		      size_t keylen)
{
	lc_pbkdf2_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_PBKDF2);

	return lc_pbkdf2_nocheck(hash, pw, pwlen, salt, saltlen, count, key,
				 keylen);
}
