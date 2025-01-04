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

#ifndef MEMCPY_SECURE_INTERNAL_H
#define MEMCPY_SECURE_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bitshift.h"
#include "cpufeatures.h"
#include "lc_memcpy_secure.h"

static inline int memcpy_secure_aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

static inline void *memcpy_secure_8(void *d, const void *s, size_t n)
{
	const uint8_t *sp = s;
	uint8_t *dp = d;

	while (n) {
		*dp = *sp;
		n--;
		dp++;
		sp++;
	}

	return d;
}

static inline void *memcpy_secure_32_aligned(void *d, const void *s, size_t n)
{
	/*
	 * We can ignore the alignment warning as we checked
	 * for proper alignment.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	uint32_t *d_word = (uint32_t *)d;
	const uint32_t *s_word = (const uint32_t *)s;
#pragma GCC diagnostic pop

	for (; n >= sizeof(*d_word); n -= sizeof(*d_word))
		*d_word++ = *s_word++;

	memcpy_secure_8((uint8_t *)d_word, (const uint8_t *)s_word, n);

	return d;
}

static inline void *memcpy_secure_32(void *d, const void *s, size_t n)
{
	const uint8_t *sp;
	uint8_t *dp;

	if (memcpy_secure_aligned(d, sizeof(uint32_t) - 1) &&
	    memcpy_secure_aligned(s, sizeof(uint32_t) - 1))
		return memcpy_secure_32_aligned(d, s, n);

	dp = d;
	sp = s;

	while (n > sizeof(uint32_t)) {
		val32_to_ptr(dp, ptr_to_32(sp));
		n -= sizeof(uint32_t);
		dp += sizeof(uint32_t);
		sp += sizeof(uint32_t);
	}

	memcpy_secure_8(dp, sp, n);

	return d;
}

#ifdef __LP64__
static inline void *memcpy_secure_64_aligned(void *d, const void *s, size_t n)
{
	/*
	 * We can ignore the alignment warning as we checked
	 * for proper alignment.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	uint64_t *d_dword = (uint64_t *)d;
	const uint64_t *s_dword = (const uint64_t *)s;
#pragma GCC diagnostic pop

	for (; n >= sizeof(*d_dword); n -= sizeof(*d_dword))
		*d_dword++ = *s_dword++;

	memcpy_secure_32_aligned((uint8_t *)d_dword, (uint8_t *)s_dword, n);

	return d;
}

#else

static inline void *memcpy_secure_64_aligned(void *d, const void *s, size_t n)
{
	return memcpy_secure_32_aligned(d, s, n);
}
#endif

static inline void *memcpy_secure_64(void *d, const void *s, size_t n)
{
	const uint8_t *sp;
	uint8_t *dp;

#ifdef __LP64__
	if (memcpy_secure_aligned(d, sizeof(uint64_t) - 1) &&
	    memcpy_secure_aligned(s, sizeof(uint64_t) - 1))
		return memcpy_secure_64_aligned(d, s, n);
#endif

	dp = d;
	sp = s;

	while (n > sizeof(uint64_t)) {
		val64_to_ptr(dp, ptr_to_64(sp));
		n -= sizeof(uint64_t);
		dp += sizeof(uint64_t);
		sp += sizeof(uint64_t);
	}

	memcpy_secure_32(dp, sp, n);

	return d;
}

#ifdef __cplusplus
}
#endif

#endif /* MEMCPY_SECURE_INTERNAL_H */
