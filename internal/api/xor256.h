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

#include "xor.h"
#include "ext_headers_x86.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AVX2 implementation of XOR
 */
static void xor_256(uint8_t *dst, const uint8_t *src, size_t size)
{
	__m256i dst_256, src_256;

	for (; size >= sizeof(src_256);
	       size -= sizeof(src_256),
		dst += sizeof(dst_256),
		src += sizeof(src_256)) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
		dst_256 = _mm256_set_epi8(
			dst[31], dst[30], dst[29], dst[28], dst[27], dst[26],
			dst[25], dst[24], dst[23], dst[22], dst[21], dst[20],
			dst[19], dst[18], dst[17], dst[16], dst[15], dst[14],
			dst[13], dst[12], dst[11], dst[10],  dst[9],  dst[8],
			 dst[7],  dst[6],  dst[5],  dst[4],  dst[3],  dst[2],
			 dst[1],  dst[0]);
		src_256 = _mm256_set_epi8(
			src[31], src[30], src[29], src[28], src[27], src[26],
			src[25], src[24], src[23], src[22], src[21], src[20],
			src[19], src[18], src[17], src[16], src[15], src[14],
			src[13], src[12], src[11], src[10],  src[9],  src[8],
			 src[7],  src[6],  src[5],  src[4],  src[3],  src[2],
			 src[1],  src[0]);
#pragma GCC diagnostic pop
		__m128d t;

		dst_256 = _mm256_xor_si256(dst_256, src_256);

		/*
		 * We can ignore the alignment warning as we checked
		 * for proper alignment.
		 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		t = _mm_castsi128_pd(_mm256_castsi256_si128(dst_256));
		_mm_storel_pd(
			(__attribute__((__may_alias__)) double *)&dst[0], t);
		_mm_storeh_pd(
			(__attribute__((__may_alias__)) double *)&dst[8], t);
		t = _mm_castsi128_pd(_mm256_extracti128_si256(dst_256, 1));
		_mm_storel_pd(
			(__attribute__((__may_alias__)) double *)&dst[16], t);
		_mm_storeh_pd(
			(__attribute__((__may_alias__)) double *)&dst[24], t);
#pragma GCC diagnostic pop
	}

	xor_64(dst, src, size);
}

#ifdef __cplusplus
}
#endif

#endif /* XOR256_H */
