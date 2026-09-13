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

void sntrup_encode_pxfreeze3_avx2(uint8_t *s, const void *v,
				  struct ws_encode_pxfreeze3 *ws_full)
{
	const int16_t *r = (const int16_t *)v;
	struct ws_encode_pxfreeze3_avx2 *ws = &ws_full->u.avx2;

	int i = p - 16;

	LC_FPU_ENABLE;

	for (;;) {
		do {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
			ws->x = _mm256_loadu_si256((__m256i *)r);
			ws->y = _mm256_mulhrs_epi16(ws->x,
						    _mm256_set1_epi16(10923));
			ws->x = _mm256_sub_epi16(ws->x, ws->y);
			ws->y = _mm256_add_epi16(ws->y, ws->y);
			ws->x = _mm256_sub_epi16(ws->x, ws->y);
			ws->x0 = _mm256_extractf128_si256(ws->x, 0);
			ws->x1 = _mm256_extractf128_si256(ws->x, 1);
			_mm_storeu_si128((__m128i *)s,
					 _mm_packs_epi16(ws->x0, ws->x1));
#pragma GCC diagnostic pop
			i -= 16;
			r += 16;
			s += 16;
		} while (i >= 0);
		if (i <= -16)
			break;
		r += i;
		s += i;
	}

	LC_FPU_DISABLE;
}
