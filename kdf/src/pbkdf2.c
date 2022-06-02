/* PBKDF2 - SP800-132
 *
 * Copyright (C) 2016 - 2022, Stephan Mueller <smueller@chronox.de>
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

#include <errno.h>
#include <limits.h>

#include "conv_be_le.h"
#include "lc_hmac.h"
#include "lc_pbkdf2.h"
#include "memset_secure.h"
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
#define LOW_ITERATION_COUNT	(UINT32_C(1<<16))
#define SAFE_ITERATION_COUNT	(UINT32_C(1<<18))
#define SAFE_ITERATION_TIME	(UINT32_C(1<<27)) /* more than 100,000,000 ns */
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

DSO_PUBLIC
int lc_pbkdf2(const struct lc_hash *hash,
	      const uint8_t *pw, size_t pwlen,
	      const uint8_t *salt, size_t saltlen,
	      const uint32_t count,
	      uint8_t *key, size_t keylen)
{
	LC_HMAC_CTX_ON_STACK(hmac_ctx, hash);
	size_t h;
	uint32_t i = 1;
#define MAX_DIGESTSIZE 64
	uint8_t u[LC_SHA_MAX_SIZE_DIGEST]
				__attribute__ ((aligned (sizeof(uint64_t))));

	if (keylen > INT_MAX)
		return -EMSGSIZE;

	if (count == 0)
		return -EINVAL;

	lc_hmac_init(hmac_ctx, pw, pwlen);
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
	memset_secure(u, 0, h);
	lc_hmac_zero(hmac_ctx);

	return 0;
}
