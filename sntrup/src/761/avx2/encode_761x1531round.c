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

void sntrup_encode_761x1531round_avx2(uint8_t *out, const void *v,
				      struct ws_round_encode *ws_full)
{
	const int16_t *R0 = (const int16_t *)v;
	struct ws_round_encode_avx2 *ws = &ws_full->u.avx2;
	/* XXX: caller could overlap R with input */
	long i;
	const uint16_t *reading;
	uint16_t *writing;

	LC_FPU_ENABLE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	reading = (uint16_t *)R0;
	writing = ws->R;
	i = 48;
	while (i > 0) {
		--i;
		if (!i) {
			reading -= 8;
			writing -= 4;
			out -= 4;
		}
		ws->x = _mm256_loadu_si256((__m256i *)reading);
		ws->x = _mm256_mulhrs_epi16(ws->x, _mm256_set1_epi16(10923));
		ws->x = _mm256_add_epi16(ws->x, _mm256_add_epi16(ws->x, ws->x));
		ws->x = _mm256_add_epi16(ws->x, _mm256_set1_epi16(2295));
		ws->x &= _mm256_set1_epi16(16383);
		ws->x = _mm256_mulhi_epi16(ws->x, _mm256_set1_epi16(21846));
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(1531));
		ws->x = _mm256_add_epi32(ws->y, ws->x);
		ws->x = _mm256_shuffle_epi8(
			ws->x,
			_mm256_set_epi8(12, 8, 4, 0, 12, 8, 4, 0, 14, 13, 10, 9,
					6, 5, 2, 1, 12, 8, 4, 0, 12, 8, 4, 0,
					14, 13, 10, 9, 6, 5, 2, 1));
		ws->x = _mm256_permute4x64_epi64(ws->x, 0xd8);
		_mm_storeu_si128((__m128i *)writing,
				 _mm256_extractf128_si256(ws->x, 0));
		*((uint32_t *)(out + 0)) =
			(uint32_t)_mm256_extract_epi32(ws->x, 4);
		*((uint32_t *)(out + 4)) =
			(uint32_t)_mm256_extract_epi32(ws->x, 6);
		reading += 16;
		writing += 8;
		out += 8;
	}
	ws->R[380] =
		(uint16_t)((((3 * ((10923 * R0[760] + 16384) >> 15) + 2295) &
			     16383) *
			    10923) >>
			   15);

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 12;
	while (i > 0) {
		--i;
		if (!i) {
			reading -= 4;
			writing -= 2;
			out -= 4;
		}
		ws->x = _mm256_loadu_si256((__m256i *)(reading + 0));
		ws->x2 = _mm256_loadu_si256((__m256i *)(reading + 16));
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->y2 = ws->x2 & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x2 = _mm256_srli_epi32(ws->x2, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(9157));
		ws->x2 = _mm256_mullo_epi32(ws->x2, _mm256_set1_epi32(9157));
		ws->x = _mm256_add_epi32(ws->y, ws->x);
		ws->x2 = _mm256_add_epi32(ws->y2, ws->x2);
		ws->x = _mm256_shuffle_epi8(
			ws->x,
			_mm256_set_epi8(15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9,
					8, 5, 4, 1, 0, 15, 14, 11, 10, 7, 6, 3,
					2, 13, 12, 9, 8, 5, 4, 1, 0));
		ws->x2 = _mm256_shuffle_epi8(
			ws->x2,
			_mm256_set_epi8(15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9,
					8, 5, 4, 1, 0, 15, 14, 11, 10, 7, 6, 3,
					2, 13, 12, 9, 8, 5, 4, 1, 0));
		ws->x = _mm256_permute4x64_epi64(ws->x, 0xd8);
		ws->x2 = _mm256_permute4x64_epi64(ws->x2, 0xd8);
		_mm256_storeu_si256((__m256i *)writing,
				    _mm256_permute2f128_si256(ws->x, ws->x2,
							      0x31));
		_mm256_storeu_si256((__m256i *)out,
				    _mm256_permute2f128_si256(ws->x, ws->x2,
							      0x20));
		reading += 32;
		writing += 16;
		out += 32;
	}
	ws->R[190] = ws->R[380];

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 12;
	while (i > 0) {
		--i;
		if (!i) {
			reading -= 2;
			writing -= 1;
			out -= 1;
		}
		ws->x = _mm256_loadu_si256((__m256i *)reading);
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(1280));
		ws->x = _mm256_add_epi32(ws->y, ws->x);
		ws->x = _mm256_shuffle_epi8(
			ws->x,
			_mm256_set_epi8(12, 8, 4, 0, 12, 8, 4, 0, 14, 13, 10, 9,
					6, 5, 2, 1, 12, 8, 4, 0, 12, 8, 4, 0,
					14, 13, 10, 9, 6, 5, 2, 1));
		ws->x = _mm256_permute4x64_epi64(ws->x, 0xd8);
		_mm_storeu_si128((__m128i *)writing,
				 _mm256_extractf128_si256(ws->x, 0));
		*((uint32_t *)(out + 0)) =
			(uint32_t)_mm256_extract_epi32(ws->x, 4);
		*((uint32_t *)(out + 4)) =
			(uint32_t)_mm256_extract_epi32(ws->x, 6);
		reading += 16;
		writing += 8;
		out += 8;
	}
	ws->R[95] = ws->R[190];

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 3;
	while (i > 0) {
		--i;
		ws->x = _mm256_loadu_si256((__m256i *)(reading + 0));
		ws->x2 = _mm256_loadu_si256((__m256i *)(reading + 16));
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->y2 = ws->x2 & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x2 = _mm256_srli_epi32(ws->x2, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(6400));
		ws->x2 = _mm256_mullo_epi32(ws->x2, _mm256_set1_epi32(6400));
		ws->x = _mm256_add_epi32(ws->y, ws->x);
		ws->x2 = _mm256_add_epi32(ws->y2, ws->x2);
		ws->x = _mm256_shuffle_epi8(
			ws->x,
			_mm256_set_epi8(15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9,
					8, 5, 4, 1, 0, 15, 14, 11, 10, 7, 6, 3,
					2, 13, 12, 9, 8, 5, 4, 1, 0));
		ws->x2 = _mm256_shuffle_epi8(
			ws->x2,
			_mm256_set_epi8(15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9,
					8, 5, 4, 1, 0, 15, 14, 11, 10, 7, 6, 3,
					2, 13, 12, 9, 8, 5, 4, 1, 0));
		ws->x = _mm256_permute4x64_epi64(ws->x, 0xd8);
		ws->x2 = _mm256_permute4x64_epi64(ws->x2, 0xd8);
		_mm256_storeu_si256((__m256i *)writing,
				    _mm256_permute2f128_si256(ws->x, ws->x2,
							      0x31));
		_mm256_storeu_si256((__m256i *)out,
				    _mm256_permute2f128_si256(ws->x, ws->x2,
							      0x20));
		reading += 32;
		writing += 16;
		out += 32;
	}

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 3;
	while (i > 0) {
		--i;
		ws->x = _mm256_loadu_si256((__m256i *)reading);
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(625));
		ws->x = _mm256_add_epi32(ws->y, ws->x);
		ws->x = _mm256_shuffle_epi8(
			ws->x,
			_mm256_set_epi8(12, 8, 4, 0, 12, 8, 4, 0, 14, 13, 10, 9,
					6, 5, 2, 1, 12, 8, 4, 0, 12, 8, 4, 0,
					14, 13, 10, 9, 6, 5, 2, 1));
		ws->x = _mm256_permute4x64_epi64(ws->x, 0xd8);
		_mm_storeu_si128((__m128i *)writing,
				 _mm256_extractf128_si256(ws->x, 0));
		*((uint32_t *)(out + 0)) =
			(uint32_t)_mm256_extract_epi32(ws->x, 4);
		*((uint32_t *)(out + 4)) =
			(uint32_t)_mm256_extract_epi32(ws->x, 6);
		reading += 16;
		writing += 8;
		out += 8;
	}

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 2;
	while (i > 0) {
		--i;
		if (!i) {
			reading -= 8;
			writing -= 4;
			out -= 4;
		}
		ws->x = _mm256_loadu_si256((__m256i *)reading);
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(1526));
		ws->x = _mm256_add_epi32(ws->y, ws->x);
		ws->x = _mm256_shuffle_epi8(
			ws->x,
			_mm256_set_epi8(12, 8, 4, 0, 12, 8, 4, 0, 14, 13, 10, 9,
					6, 5, 2, 1, 12, 8, 4, 0, 12, 8, 4, 0,
					14, 13, 10, 9, 6, 5, 2, 1));
		ws->x = _mm256_permute4x64_epi64(ws->x, 0xd8);
		_mm_storeu_si128((__m128i *)writing,
				 _mm256_extractf128_si256(ws->x, 0));
		*((uint32_t *)(out + 0)) =
			(uint32_t)_mm256_extract_epi32(ws->x, 4);
		*((uint32_t *)(out + 4)) =
			(uint32_t)_mm256_extract_epi32(ws->x, 6);
		reading += 16;
		writing += 8;
		out += 8;
	}

	LC_FPU_DISABLE;

	for (i = 0; i < 6; ++i) {
		ws->r0 = ws->R[2 * i];
		ws->r1 = ws->R[2 * i + 1];
		ws->r2 = ws->r0 + ws->r1 * (uint32_t)9097;
		*out++ = (uint8_t)ws->r2;
		ws->r2 >>= 8;
		*out++ = (uint8_t)ws->r2;
		ws->r2 >>= 8;
		ws->R[i] = (uint16_t)ws->r2;
	}

	for (i = 0; i < 3; ++i) {
		ws->r0 = ws->R[2 * i];
		ws->r1 = ws->R[2 * i + 1];
		ws->r2 = ws->r0 + ws->r1 * (uint32_t)1263;
		*out++ = (uint8_t)ws->r2;
		ws->r2 >>= 8;
		ws->R[i] = (uint16_t)ws->r2;
	}

	ws->r0 = ws->R[0];
	ws->r1 = ws->R[1];
	ws->r2 = ws->r0 + ws->r1 * (uint32_t)6232;
	*out++ = (uint8_t)ws->r2;
	ws->r2 >>= 8;
	*out++ = (uint8_t)ws->r2;
	ws->r2 >>= 8;
	ws->R[0] = (uint16_t)ws->r2;
	ws->R[1] = ws->R[2];

	ws->r0 = ws->R[0];
	ws->r1 = ws->R[1];
	ws->r2 = ws->r0 + ws->r1 * (uint32_t)593;
	*out++ = (uint8_t)ws->r2;
	ws->r2 >>= 8;
	ws->R[0] = (uint16_t)ws->r2;

	ws->r0 = ws->R[0];
	*out++ = (uint8_t)ws->r0;
	ws->r0 >>= 8;
	*out++ = (uint8_t)ws->r0;
#pragma GCC diagnostic pop
}
