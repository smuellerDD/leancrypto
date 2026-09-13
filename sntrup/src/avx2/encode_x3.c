/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The SNTRUP code is derived in parts from the code base
 * https://libntruprime.cr.yp.to/ which uses the following license:
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.; This is free software;
 * see the source for copying conditions. There is NO; warranty; not even for
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * SPDX-License-Identifier: LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT
 */

#include "ext_headers_x86.h"
#include "sntrup_decode_int16.h"
#include "sntrup_int16.h"
#include "params.h"
#include "visibility.h"

LC_FIPS_RODATA_SECTION
static const __attribute((aligned(32))) uint8_t lobytes_buf[32] = {
	255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0,
	255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0,
};
#define lobytes (*(__m256i *)lobytes_buf)

void Small_encode_avx2(uint8_t *s, const void *v,
		       struct ws_small_encode *ws_full)
{
	const uint8_t *f = (const uint8_t *)v;
	struct ws_small_encode_avx2 *ws = &ws_full->u.avx2;
	int loop;
	const uint8_t *nextf = f + 128 - 4 * overshoot;
	uint8_t *nexts = s + 32 - overshoot;

	LC_FPU_ENABLE;

	for (loop = loops; loop > 0; --loop) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		ws->f0 = _mm256_loadu_si256((const __m256i *)(f + 0));
		ws->f1 = _mm256_loadu_si256((const __m256i *)(f + 32));
		ws->f2 = _mm256_loadu_si256((const __m256i *)(f + 64));
		ws->f3 = _mm256_loadu_si256((const __m256i *)(f + 96));
#pragma GCC diagnostic pop
		f = nextf;
		nextf += 128;

		ws->a0 =
			_mm256_packus_epi16(ws->f0 & lobytes, ws->f1 & lobytes);
		/* 0 2 4 6 8 10 12 14 32 34 36 38 40 42 44 46 */
		/* 16 18 20 22 24 26 28 30 48 50 52 54 56 58 60 62 */
		ws->a1 = _mm256_packus_epi16(_mm256_srli_epi16(ws->f0, 8),
					     _mm256_srli_epi16(ws->f1, 8));
		/* 1 3 ... */
		ws->a2 =
			_mm256_packus_epi16(ws->f2 & lobytes, ws->f3 & lobytes);
		ws->a3 = _mm256_packus_epi16(_mm256_srli_epi16(ws->f2, 8),
					     _mm256_srli_epi16(ws->f3, 8));

		ws->a0 = _mm256_add_epi8(
			ws->a0,
			_mm256_slli_epi16(ws->a1 & _mm256_set1_epi8(63), 2));
		ws->a2 = _mm256_add_epi8(
			ws->a2,
			_mm256_slli_epi16(ws->a3 & _mm256_set1_epi8(63), 2));

		ws->b0 =
			_mm256_packus_epi16(ws->a0 & lobytes, ws->a2 & lobytes);
		/* 0 4 8 12 32 36 40 44 64 68 72 76 96 100 104 108 */
		/* 16 20 24 28 48 52 56 60 80 84 88 92 112 116 120 124 */
		ws->b2 = _mm256_packus_epi16(_mm256_srli_epi16(ws->a0, 8),
					     _mm256_srli_epi16(ws->a2, 8));
		/* 2 6 ... */

		ws->b0 = _mm256_add_epi8(
			ws->b0,
			_mm256_slli_epi16(ws->b2 & _mm256_set1_epi8(15), 4));

		ws->b0 = _mm256_permutevar8x32_epi32(
			ws->b0, _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0));

		ws->b0 = _mm256_add_epi8(ws->b0, _mm256_set1_epi8(85));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		_mm256_storeu_si256((__m256i *)s, ws->b0);
#pragma GCC diagnostic pop
		s = nexts;
		nexts += 32;
	}

	LC_FPU_DISABLE;

	*s++ = *f++ + 1;
}
