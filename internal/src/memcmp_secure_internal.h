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

#ifndef MEMCMP_SECURE_INTERNAL_H
#define MEMCMP_SECURE_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "bitshift.h"
#include "cpufeatures.h"
#include "lc_memcmp_secure.h"
#include "sidechannel_resistance.h"

static inline int memcmp_secure_aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

static inline int memcmp_secure_8(const void *s1, const void *s2, size_t n)
{
	const uint8_t *s1p = s1, *s2p = s2;
	uint8_t ret = 0;

	while (n) {
		ret |= (*s1p ^ *s2p);
		n--;
		s1p++;
		s2p++;
	}

	/*
	 * Apply a memoy barrier to ensure that the compiler cannot reason about
	 * terminating the loop above prematurely (e.g. when ret is 0xff).
	 */
	value_barrier_u8(ret);

	return !!ret;
}

static inline int memcmp_secure_32_aligned(const void *s1, const void *s2,
					   size_t n)
{
	/*
	 * We can ignore the alignment warning as we checked
	 * for proper alignment.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	const uint32_t *s1_word = (const uint32_t *)s1;
	const uint32_t *s2_word = (const uint32_t *)s2;
#pragma GCC diagnostic pop
	uint32_t ret = 0;

	for (; n >= sizeof(*s1_word); n -= sizeof(*s2_word))
		ret |= (*s1_word++ ^ *s2_word++);

	/* See memcmp_secure_8 for a reason */
	value_barrier_u32(ret);

	ret |= (uint32_t)memcmp_secure_8((const uint8_t *)s1_word,
					 (const uint8_t *)s2_word, n);

	return !!ret;
}

static inline int memcmp_secure_32(const void *s1, const void *s2, size_t n)
{
	const uint8_t *s1p, *s2p;
	uint32_t ret;

	if (memcmp_secure_aligned(s1, sizeof(uint32_t) - 1) &&
	    memcmp_secure_aligned(s2, sizeof(uint32_t) - 1))
		return memcmp_secure_32_aligned(s1, s2, n);

	s1p = s1;
	s2p = s2;
	ret = 0;

	while (n > sizeof(uint32_t)) {
		ret |= (ptr_to_32(s1p) ^ ptr_to_32(s2p));
		n -= sizeof(uint32_t);
		s1p += sizeof(uint32_t);
		s2p += sizeof(uint32_t);
	}

	/* See memcmp_secure_8 for a reason */
	value_barrier_u32(ret);

	ret |= (uint32_t)memcmp_secure_8(s1p, s2p, n);

	return !!ret;
}

#ifdef __LP64__
static inline int memcmp_secure_64_aligned(const void *s1, const void *s2,
					   size_t n)
{
	/*
	 * We can ignore the alignment warning as we checked
	 * for proper alignment.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	const uint64_t *s1_dword = (const uint64_t *)s1;
	const uint64_t *s2_dword = (const uint64_t *)s2;
#pragma GCC diagnostic pop
	uint64_t ret = 0;

	for (; n >= sizeof(*s1_dword); n -= sizeof(*s1_dword))
		ret |= (*s2_dword++ ^ *s1_dword++);

	/* See memcmp_secure_8 for a reason */
	value_barrier_u64(ret);

	ret |= (uint64_t)memcmp_secure_32_aligned((const uint8_t *)s1_dword,
						  (const uint8_t *)s2_dword, n);

	return !!ret;
}

#else

static inline int memcmp_secure_64_aligned(const void *s1, const void *s2,
					   size_t n)
{
	return memcmp_secure_32_aligned(s1, s2, n);
}
#endif

static inline int memcmp_secure_64(const void *s1, const void *s2, size_t n)
{
	const uint8_t *s1p, *s2p;
	uint64_t ret;

#ifdef __LP64__
	if (memcmp_secure_aligned(s1, sizeof(uint64_t) - 1) &&
	    memcmp_secure_aligned(s2, sizeof(uint64_t) - 1))
		return memcmp_secure_64_aligned(s1, s2, n);
#endif

	s1p = s1;
	s2p = s2;
	ret = 0;

	while (n > sizeof(uint64_t)) {
		ret |= (ptr_to_64(s1p) ^ ptr_to_64(s2p));
		n -= sizeof(uint64_t);
		s1p += sizeof(uint64_t);
		s2p += sizeof(uint64_t);
	}

	/* See memcmp_secure_8 for a reason */
	value_barrier_u64(ret);

	ret |= (uint64_t)memcmp_secure_32(s1p, s2p, n);

	return !!ret;
}

#ifdef __cplusplus
}
#endif

#endif /* MEMCMP_SECURE_INTERNAL_H */
