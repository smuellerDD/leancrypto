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

void sntrup_encode_1013x7177_avx2(uint8_t *out, const void *v,
				  struct ws_encode *ws_full)
{
	const int16_t *R0 = (const int16_t *)v;
	struct ws_encode_avx2 *ws = &ws_full->u.avx2;
	/* XXX: caller could overlap R with input */
	long i;
	const uint16_t *reading;
	uint16_t *writing;

	reading = (uint16_t *)R0;
	writing = ws->R;
	i = 32;

	LC_FPU_ENABLE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	while (i > 0) {
		--i;
		if (!i) {
			reading -= 12;
			writing -= 6;
			out -= 12;
		}
		ws->x = _mm256_loadu_si256((__m256i *)(reading + 0));
		ws->x2 = _mm256_loadu_si256((__m256i *)(reading + 16));
		ws->x = _mm256_add_epi16(ws->x, _mm256_set1_epi16(3588));
		ws->x2 = _mm256_add_epi16(ws->x2, _mm256_set1_epi16(3588));
		ws->x &= _mm256_set1_epi16(16383);
		ws->x2 &= _mm256_set1_epi16(16383);
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->y2 = ws->x2 & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x2 = _mm256_srli_epi32(ws->x2, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(7177));
		ws->x2 = _mm256_mullo_epi32(ws->x2, _mm256_set1_epi32(7177));
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
	ws->R[506] = ((R0[1012] + 3588) & 16383);

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 32;
	while (i > 0) {
		--i;
		if (!i) {
			reading -= 6;
			writing -= 3;
			out -= 3;
		}
		ws->x = _mm256_loadu_si256((__m256i *)reading);
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(786));
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
	ws->R[253] = ws->R[506];

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 8;
	while (i > 0) {
		--i;
		if (!i) {
			reading -= 2;
			writing -= 1;
			out -= 2;
		}
		ws->x = _mm256_loadu_si256((__m256i *)(reading + 0));
		ws->x2 = _mm256_loadu_si256((__m256i *)(reading + 16));
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->y2 = ws->x2 & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x2 = _mm256_srli_epi32(ws->x2, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(2414));
		ws->x2 = _mm256_mullo_epi32(ws->x2, _mm256_set1_epi32(2414));
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

	for (i = 0; i < 63; ++i) {
		ws->r0 = ws->R[2 * i];
		ws->r1 = ws->R[2 * i + 1];
		ws->r2 = ws->r0 + ws->r1 * (uint32_t)89;
		ws->R[i] = (uint16_t)ws->r2;
	}
	ws->R[63] = ws->R[126];

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 2;
	while (i > 0) {
		--i;
		if (!i) {
			reading -= 2;
			writing -= 1;
			out -= 2;
		}
		ws->x = _mm256_loadu_si256((__m256i *)(reading + 0));
		ws->x2 = _mm256_loadu_si256((__m256i *)(reading + 16));
		ws->y = ws->x & _mm256_set1_epi32(65535);
		ws->y2 = ws->x2 & _mm256_set1_epi32(65535);
		ws->x = _mm256_srli_epi32(ws->x, 16);
		ws->x2 = _mm256_srli_epi32(ws->x2, 16);
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(7921));
		ws->x2 = _mm256_mullo_epi32(ws->x2, _mm256_set1_epi32(7921));
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
	ws->r0 = ws->R[62];
	ws->r1 = ws->R[63];
	ws->r2 = ws->r0 + ws->r1 * (uint32_t)7921;
	*out++ = (uint8_t)ws->r2;
	ws->r2 >>= 8;
	ws->R[31] = (uint16_t)ws->r2;

	reading = (uint16_t *)ws->R;
	writing = ws->R;
	i = 2;
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
		ws->x = _mm256_mullo_epi32(ws->x, _mm256_set1_epi32(958));
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

	ws->r0 = ws->R[30];
	ws->r1 = ws->R[31];
	ws->r2 = ws->r0 + ws->r1 * (uint32_t)958;
	*out++ = (uint8_t)ws->r2;
	ws->r2 >>= 8;
	*out++ = (uint8_t)ws->r2;
	ws->r2 >>= 8;
	ws->R[15] = (uint16_t)ws->r2;

	for (i = 0; i < 7; ++i) {
		ws->r0 = ws->R[2 * i];
		ws->r1 = ws->R[2 * i + 1];
		ws->r2 = ws->r0 + ws->r1 * (uint32_t)3586;
		*out++ = (uint8_t)ws->r2;
		ws->r2 >>= 8;
		*out++ = (uint8_t)ws->r2;
		ws->r2 >>= 8;
		ws->R[i] = (uint16_t)ws->r2;
	}
	ws->r0 = ws->R[14];
	ws->r1 = ws->R[15];
	ws->r2 = ws->r0 + ws->r1 * (uint32_t)3586;
	*out++ = (uint8_t)ws->r2;
	ws->r2 >>= 8;
	ws->R[7] = (uint16_t)ws->r2;

	for (i = 0; i < 4; ++i) {
		ws->r0 = ws->R[2 * i];
		ws->r1 = ws->R[2 * i + 1];
		ws->r2 = ws->r0 + ws->r1 * (uint32_t)197;
		*out++ = (uint8_t)ws->r2;
		ws->r2 >>= 8;
		ws->R[i] = (uint16_t)ws->r2;
	}

	for (i = 0; i < 2; ++i) {
		ws->r0 = ws->R[2 * i];
		ws->r1 = ws->R[2 * i + 1];
		ws->r2 = ws->r0 + ws->r1 * (uint32_t)152;
		*out++ = (uint8_t)ws->r2;
		ws->r2 >>= 8;
		ws->R[i] = (uint16_t)ws->r2;
	}

	ws->r0 = ws->R[0];
	ws->r1 = ws->R[1];
	ws->r2 = ws->r0 + ws->r1 * (uint32_t)91;
	*out++ = (uint8_t)ws->r2;
	ws->r2 >>= 8;
	ws->R[0] = (uint16_t)ws->r2;

	ws->r0 = ws->R[0];
	*out++ = (uint8_t)ws->r0;
	ws->r0 >>= 8;
	*out++ = (uint8_t)ws->r0;

#pragma GCC diagnostic pop
}
