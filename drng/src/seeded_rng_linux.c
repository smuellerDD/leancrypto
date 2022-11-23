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

#include "seeded_rng.h"

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

ssize_t get_full_entropy(uint8_t *buffer, size_t bufferlen)
{
	return getrandom_random(buffer, bufferlen);
}
