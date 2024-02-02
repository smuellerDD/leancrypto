/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef XOR256_H
#define XOR256_H

#include "build_bug_on.h"
#include "xor.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LC_XOR_MIN_ALIGNMENT(min, requested)                                   \
	((min < requested) ? (requested) : (min))

#ifdef LC_HOST_X86_64

/*
 * The load of data into __m256i does not require alignment, the store
 * requires 64 bit alignment by using _mm_storel_pd / _mm_storeh_pd.
 */
#define LC_XOR_AVX2_ALIGNMENT (sizeof(uint64_t))
#define LC_XOR_ALIGNMENT(min) LC_XOR_MIN_ALIGNMENT(min, LC_XOR_AVX2_ALIGNMENT)

/*
 * AVX2 implementation of XOR (processing 256 bit chunks)
 */
#include "ext_headers_x86.h"
static inline void xor_256_aligned(uint8_t *dst, const uint8_t *src,
				   size_t size)
{
	__m256i dst_256, src_256;

	LC_FPU_ENABLE;
	for (; size >= sizeof(src_256); size -= sizeof(src_256),
					dst += sizeof(dst_256),
					src += sizeof(src_256)) {
		__m128d t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
		dst_256 = _mm256_set_epi8(dst[31], dst[30], dst[29], dst[28],
					  dst[27], dst[26], dst[25], dst[24],
					  dst[23], dst[22], dst[21], dst[20],
					  dst[19], dst[18], dst[17], dst[16],
					  dst[15], dst[14], dst[13], dst[12],
					  dst[11], dst[10], dst[9], dst[8],
					  dst[7], dst[6], dst[5], dst[4],
					  dst[3], dst[2], dst[1], dst[0]);
		src_256 = _mm256_set_epi8(src[31], src[30], src[29], src[28],
					  src[27], src[26], src[25], src[24],
					  src[23], src[22], src[21], src[20],
					  src[19], src[18], src[17], src[16],
					  src[15], src[14], src[13], src[12],
					  src[11], src[10], src[9], src[8],
					  src[7], src[6], src[5], src[4],
					  src[3], src[2], src[1], src[0]);
#pragma GCC diagnostic pop

		dst_256 = _mm256_xor_si256(dst_256, src_256);

		/*
		 * We can ignore the alignment warning as we checked
		 * for proper alignment.
		 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		t = _mm_castsi128_pd(_mm256_castsi256_si128(dst_256));
		_mm_storel_pd((__attribute__((__may_alias__)) double *)&dst[0],
			      t);
		_mm_storeh_pd((__attribute__((__may_alias__)) double *)&dst[8],
			      t);
		t = _mm_castsi128_pd(_mm256_extracti128_si256(dst_256, 1));
		_mm_storel_pd((__attribute__((__may_alias__)) double *)&dst[16],
			      t);
		_mm_storeh_pd((__attribute__((__may_alias__)) double *)&dst[24],
			      t);
#pragma GCC diagnostic pop
	}
	LC_FPU_DISABLE;

	/*
	 * As we skip the xor_64 alignment check, guarantee it at compile time.
	 */
	BUILD_BUG_ON(LC_XOR_AVX2_ALIGNMENT < sizeof(uint64_t));
	xor_64_aligned(dst, src, size);
}

static inline void xor_256(uint8_t *dst, const uint8_t *src, size_t size)
{
	if (!aligned(src, LC_XOR_AVX2_ALIGNMENT - 1) ||
	    !aligned(dst, LC_XOR_AVX2_ALIGNMENT - 1)) {
		xor_64(dst, src, size);
	} else {
		xor_256_aligned(dst, src, size);
	}
}

#elif (defined(LC_HOST_ARM32_NEON) || defined(LC_HOST_AARCH64)) &&             \
	!defined(LINUX_KERNEL)

/*
 * The load of data into uint64x2_t requires 64 bit alignment, the store
 * requires 64 bit alignment.
 */
#define LC_XOR_NEON_ALIGNMENT (sizeof(uint64_t))
#define LC_XOR_ALIGNMENT(min) LC_XOR_MIN_ALIGNMENT(min, LC_XOR_NEON_ALIGNMENT)

/*
 * ARM Neon implementation of XOR (processing 128 bit chunks)
 */
/* This code cannot be compiled for the Linux kernel as of now */
#include <arm_neon.h>
#include "ext_headers_arm.h"
static inline void xor_256_aligned(uint8_t *dst, const uint8_t *src,
				   size_t size)
{
	uint64x2_t dst_128, src_128;

	if (!aligned(src, sizeof(uint64x2_t) - 1) ||
	    !aligned(dst, sizeof(uint64x2_t) - 1)) {
		xor_64(dst, src, size);
		return;
	}

	LC_NEON_ENABLE;
	for (; size >= sizeof(src_128); size -= sizeof(src_128),
					dst += sizeof(dst_128),
					src += sizeof(src_128)) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		src_128 = vld1q_u64((uint64_t *)src);
		dst_128 = vld1q_u64((uint64_t *)dst);
#pragma GCC diagnostic pop

		dst_128 = veorq_u64(dst_128, src_128);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		vst1q_u64((uint64_t *)dst, dst_128);
#pragma GCC diagnostic pop
	}
	LC_NEON_DISABLE;

	/*
	 * As we skip the xor_64 alignment check, guarantee it at compile time.
	 */
	BUILD_BUG_ON(LC_XOR_NEON_ALIGNMENT < sizeof(uint64_t));
	xor_64_aligned(dst, src, size);
}

static inline void xor_256(uint8_t *dst, const uint8_t *src, size_t size)
{
	if (!aligned(src, LC_XOR_NEON_ALIGNMENT - 1) ||
	    !aligned(dst, LC_XOR_NEON_ALIGNMENT - 1)) {
		xor_64(dst, src, size);
	} else {
		xor_256_aligned(dst, src, size);
	}
}

#else

#define LC_XOR_ALIGNMENT(min) LC_XOR_MIN_ALIGNMENT(min, (sizeof(uint64_t)))

static inline void xor_256(uint8_t *dst, const uint8_t *src, size_t size)
{
	xor_64(dst, src, size);
}

#endif

#ifdef __cplusplus
}
#endif

#endif /* XOR256_H */
