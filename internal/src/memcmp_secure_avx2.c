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

#include "ext_headers_x86.h"
#include "memcmp_secure_internal.h"
#include "visibility.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

static inline int
memcmp_secure_256_avx2_aligned(const void *s1, const void *s2, size_t n)
{
	/*
	 * We can ignore the alignment warning as we checked
	 * for proper alignment.
	 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	__m256i *s1_qword = (__m256i *)s1;
	__m256i *s2_qword = (__m256i *)s2;
#pragma GCC diagnostic pop
	__m256i reti = _mm256_setzero_si256();
	uint64_t result[4] __attribute__((__aligned__(32)));
	unsigned int i;
	int ret = 0;

	for (; n >= sizeof(*s1_qword); n -= sizeof(*s1_qword))
		reti = _mm256_or_si256(
			reti, _mm256_xor_si256(*s2_qword++, *s1_qword++));

	_mm256_store_si256((__m256i*) result, reti);
	for (i = 0; i < ARRAY_SIZE(result); i++)
		ret |= !!result[i];

	ret |= memcmp_secure_64_aligned((uint8_t *)s1_qword,
					(uint8_t *)s2_qword, n);

	return ret;
}

static inline int
memcmp_secure_256(const void *s1, const void *s2, size_t n)
{
	if ((lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2) &&
	    memcmp_secure_aligned(s1, sizeof(__m256i) - 1) &&
	    memcmp_secure_aligned(s2, sizeof(__m256i) - 1))
		return memcmp_secure_256_avx2_aligned(s1, s2, n);
	else

	return memcmp_secure_64(s1, s2, n);
}

LC_INTERFACE_FUNCTION(
int, lc_memcmp_secure, const void *s1, size_t s1n, const void *s2, size_t s2n)
{
	size_t n = s1n;

	int ret = 0;

	if (s1n != s2n) {
		ret = 1;
		n = (s1n > s2n) ? s2n : s1n;
	}

	ret |= memcmp_secure_256(s1, s2, n);

	return ret;
}
