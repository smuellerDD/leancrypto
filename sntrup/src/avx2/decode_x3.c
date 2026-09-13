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
#include "params.h"
#include "visibility.h"

void Small_decode_avx2(void *v, const uint8_t *s,
		       struct ws_small_decode *ws_full)
{
	struct ws_small_decode_avx2 *ws = &ws_full->u.avx2;
	uint8_t *f = (uint8_t *)v;
	int loop;
	uint8_t *nextf = f + 128 - 4 * overshoot;
	const unsigned char *nexts = s + 32 - overshoot;

	LC_FPU_ENABLE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	for (loop = loops; loop > 0; --loop) {
		ws->s0 = _mm256_loadu_si256((const __m256i *)s);
		s = nexts;
		nexts += 32;

		ws->s1 = _mm256_srli_epi16(ws->s0 & _mm256_set1_epi8(-16), 4);
		ws->s0 &= _mm256_set1_epi8(15);

		ws->a0 = _mm256_unpacklo_epi8(ws->s0, ws->s1);
		/* 0 0>>4 1 1>>4 2 2>>4 3 3>>4 4 4>>4 5 5>>4 6 6>>4 7 7>>4 */
		/* 16 16>>4 ... */
		ws->a1 = _mm256_unpackhi_epi8(ws->s0, ws->s1);
		/* 8 8>>4 9 9>>4 10 10>>4 ... */
		/* 24 24>>4 ... */

		ws->a2 = _mm256_srli_epi16(ws->a0 & _mm256_set1_epi8(12), 2);
		ws->a3 = _mm256_srli_epi16(ws->a1 & _mm256_set1_epi8(12), 2);
		ws->a0 &= _mm256_set1_epi8(3);
		ws->a1 &= _mm256_set1_epi8(3);

		ws->b0 = _mm256_unpacklo_epi8(ws->a0, ws->a2);
		/* 0 0>>2 0>>4 0>>6 1 1>>2 1>>4 1>>6 */
		/* 2 2>>2 2>>4 2>>6 3 3>>2 3>>4 3>.6 */
		/* 16 16>>2 16>>4 16>>6 ... */
		ws->b2 = _mm256_unpackhi_epi8(ws->a0, ws->a2);
		/* 4 4>>2 ... */
		ws->b1 = _mm256_unpacklo_epi8(ws->a1, ws->a3);
		/* 8 8>>2 ... */
		ws->b3 = _mm256_unpackhi_epi8(ws->a1, ws->a3);
		/* 12 12>>2 ... */

		ws->f0 = _mm256_permute2x128_si256(ws->b0, ws->b2, 0x20);
		ws->f2 = _mm256_permute2x128_si256(ws->b0, ws->b2, 0x31);
		ws->f1 = _mm256_permute2x128_si256(ws->b1, ws->b3, 0x20);
		ws->f3 = _mm256_permute2x128_si256(ws->b1, ws->b3, 0x31);

		ws->f0 = _mm256_add_epi8(ws->f0, _mm256_set1_epi8(-1));
		ws->f1 = _mm256_add_epi8(ws->f1, _mm256_set1_epi8(-1));
		ws->f2 = _mm256_add_epi8(ws->f2, _mm256_set1_epi8(-1));
		ws->f3 = _mm256_add_epi8(ws->f3, _mm256_set1_epi8(-1));

		_mm256_storeu_si256((__m256i *)(f + 0), ws->f0);
		_mm256_storeu_si256((__m256i *)(f + 32), ws->f1);
		_mm256_storeu_si256((__m256i *)(f + 64), ws->f2);
		_mm256_storeu_si256((__m256i *)(f + 96), ws->f3);
		f = nextf;
		nextf += 128;
	}
#pragma GCC diagnostic pop

	LC_FPU_DISABLE;

	*f = ((uint8_t)(*s & 3)) - 1;
}
