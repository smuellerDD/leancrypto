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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include "dilithium_rejsample_avx2.h"
#include "ext_headers_x86.h"
#include "lc_dilithium.h"

const uint8_t idxlut[256][8] = {
	{ 0, 0, 0, 0, 0, 0, 0, 0 }, { 0, 0, 0, 0, 0, 0, 0, 0 },
	{ 1, 0, 0, 0, 0, 0, 0, 0 }, { 0, 1, 0, 0, 0, 0, 0, 0 },
	{ 2, 0, 0, 0, 0, 0, 0, 0 }, { 0, 2, 0, 0, 0, 0, 0, 0 },
	{ 1, 2, 0, 0, 0, 0, 0, 0 }, { 0, 1, 2, 0, 0, 0, 0, 0 },
	{ 3, 0, 0, 0, 0, 0, 0, 0 }, { 0, 3, 0, 0, 0, 0, 0, 0 },
	{ 1, 3, 0, 0, 0, 0, 0, 0 }, { 0, 1, 3, 0, 0, 0, 0, 0 },
	{ 2, 3, 0, 0, 0, 0, 0, 0 }, { 0, 2, 3, 0, 0, 0, 0, 0 },
	{ 1, 2, 3, 0, 0, 0, 0, 0 }, { 0, 1, 2, 3, 0, 0, 0, 0 },
	{ 4, 0, 0, 0, 0, 0, 0, 0 }, { 0, 4, 0, 0, 0, 0, 0, 0 },
	{ 1, 4, 0, 0, 0, 0, 0, 0 }, { 0, 1, 4, 0, 0, 0, 0, 0 },
	{ 2, 4, 0, 0, 0, 0, 0, 0 }, { 0, 2, 4, 0, 0, 0, 0, 0 },
	{ 1, 2, 4, 0, 0, 0, 0, 0 }, { 0, 1, 2, 4, 0, 0, 0, 0 },
	{ 3, 4, 0, 0, 0, 0, 0, 0 }, { 0, 3, 4, 0, 0, 0, 0, 0 },
	{ 1, 3, 4, 0, 0, 0, 0, 0 }, { 0, 1, 3, 4, 0, 0, 0, 0 },
	{ 2, 3, 4, 0, 0, 0, 0, 0 }, { 0, 2, 3, 4, 0, 0, 0, 0 },
	{ 1, 2, 3, 4, 0, 0, 0, 0 }, { 0, 1, 2, 3, 4, 0, 0, 0 },
	{ 5, 0, 0, 0, 0, 0, 0, 0 }, { 0, 5, 0, 0, 0, 0, 0, 0 },
	{ 1, 5, 0, 0, 0, 0, 0, 0 }, { 0, 1, 5, 0, 0, 0, 0, 0 },
	{ 2, 5, 0, 0, 0, 0, 0, 0 }, { 0, 2, 5, 0, 0, 0, 0, 0 },
	{ 1, 2, 5, 0, 0, 0, 0, 0 }, { 0, 1, 2, 5, 0, 0, 0, 0 },
	{ 3, 5, 0, 0, 0, 0, 0, 0 }, { 0, 3, 5, 0, 0, 0, 0, 0 },
	{ 1, 3, 5, 0, 0, 0, 0, 0 }, { 0, 1, 3, 5, 0, 0, 0, 0 },
	{ 2, 3, 5, 0, 0, 0, 0, 0 }, { 0, 2, 3, 5, 0, 0, 0, 0 },
	{ 1, 2, 3, 5, 0, 0, 0, 0 }, { 0, 1, 2, 3, 5, 0, 0, 0 },
	{ 4, 5, 0, 0, 0, 0, 0, 0 }, { 0, 4, 5, 0, 0, 0, 0, 0 },
	{ 1, 4, 5, 0, 0, 0, 0, 0 }, { 0, 1, 4, 5, 0, 0, 0, 0 },
	{ 2, 4, 5, 0, 0, 0, 0, 0 }, { 0, 2, 4, 5, 0, 0, 0, 0 },
	{ 1, 2, 4, 5, 0, 0, 0, 0 }, { 0, 1, 2, 4, 5, 0, 0, 0 },
	{ 3, 4, 5, 0, 0, 0, 0, 0 }, { 0, 3, 4, 5, 0, 0, 0, 0 },
	{ 1, 3, 4, 5, 0, 0, 0, 0 }, { 0, 1, 3, 4, 5, 0, 0, 0 },
	{ 2, 3, 4, 5, 0, 0, 0, 0 }, { 0, 2, 3, 4, 5, 0, 0, 0 },
	{ 1, 2, 3, 4, 5, 0, 0, 0 }, { 0, 1, 2, 3, 4, 5, 0, 0 },
	{ 6, 0, 0, 0, 0, 0, 0, 0 }, { 0, 6, 0, 0, 0, 0, 0, 0 },
	{ 1, 6, 0, 0, 0, 0, 0, 0 }, { 0, 1, 6, 0, 0, 0, 0, 0 },
	{ 2, 6, 0, 0, 0, 0, 0, 0 }, { 0, 2, 6, 0, 0, 0, 0, 0 },
	{ 1, 2, 6, 0, 0, 0, 0, 0 }, { 0, 1, 2, 6, 0, 0, 0, 0 },
	{ 3, 6, 0, 0, 0, 0, 0, 0 }, { 0, 3, 6, 0, 0, 0, 0, 0 },
	{ 1, 3, 6, 0, 0, 0, 0, 0 }, { 0, 1, 3, 6, 0, 0, 0, 0 },
	{ 2, 3, 6, 0, 0, 0, 0, 0 }, { 0, 2, 3, 6, 0, 0, 0, 0 },
	{ 1, 2, 3, 6, 0, 0, 0, 0 }, { 0, 1, 2, 3, 6, 0, 0, 0 },
	{ 4, 6, 0, 0, 0, 0, 0, 0 }, { 0, 4, 6, 0, 0, 0, 0, 0 },
	{ 1, 4, 6, 0, 0, 0, 0, 0 }, { 0, 1, 4, 6, 0, 0, 0, 0 },
	{ 2, 4, 6, 0, 0, 0, 0, 0 }, { 0, 2, 4, 6, 0, 0, 0, 0 },
	{ 1, 2, 4, 6, 0, 0, 0, 0 }, { 0, 1, 2, 4, 6, 0, 0, 0 },
	{ 3, 4, 6, 0, 0, 0, 0, 0 }, { 0, 3, 4, 6, 0, 0, 0, 0 },
	{ 1, 3, 4, 6, 0, 0, 0, 0 }, { 0, 1, 3, 4, 6, 0, 0, 0 },
	{ 2, 3, 4, 6, 0, 0, 0, 0 }, { 0, 2, 3, 4, 6, 0, 0, 0 },
	{ 1, 2, 3, 4, 6, 0, 0, 0 }, { 0, 1, 2, 3, 4, 6, 0, 0 },
	{ 5, 6, 0, 0, 0, 0, 0, 0 }, { 0, 5, 6, 0, 0, 0, 0, 0 },
	{ 1, 5, 6, 0, 0, 0, 0, 0 }, { 0, 1, 5, 6, 0, 0, 0, 0 },
	{ 2, 5, 6, 0, 0, 0, 0, 0 }, { 0, 2, 5, 6, 0, 0, 0, 0 },
	{ 1, 2, 5, 6, 0, 0, 0, 0 }, { 0, 1, 2, 5, 6, 0, 0, 0 },
	{ 3, 5, 6, 0, 0, 0, 0, 0 }, { 0, 3, 5, 6, 0, 0, 0, 0 },
	{ 1, 3, 5, 6, 0, 0, 0, 0 }, { 0, 1, 3, 5, 6, 0, 0, 0 },
	{ 2, 3, 5, 6, 0, 0, 0, 0 }, { 0, 2, 3, 5, 6, 0, 0, 0 },
	{ 1, 2, 3, 5, 6, 0, 0, 0 }, { 0, 1, 2, 3, 5, 6, 0, 0 },
	{ 4, 5, 6, 0, 0, 0, 0, 0 }, { 0, 4, 5, 6, 0, 0, 0, 0 },
	{ 1, 4, 5, 6, 0, 0, 0, 0 }, { 0, 1, 4, 5, 6, 0, 0, 0 },
	{ 2, 4, 5, 6, 0, 0, 0, 0 }, { 0, 2, 4, 5, 6, 0, 0, 0 },
	{ 1, 2, 4, 5, 6, 0, 0, 0 }, { 0, 1, 2, 4, 5, 6, 0, 0 },
	{ 3, 4, 5, 6, 0, 0, 0, 0 }, { 0, 3, 4, 5, 6, 0, 0, 0 },
	{ 1, 3, 4, 5, 6, 0, 0, 0 }, { 0, 1, 3, 4, 5, 6, 0, 0 },
	{ 2, 3, 4, 5, 6, 0, 0, 0 }, { 0, 2, 3, 4, 5, 6, 0, 0 },
	{ 1, 2, 3, 4, 5, 6, 0, 0 }, { 0, 1, 2, 3, 4, 5, 6, 0 },
	{ 7, 0, 0, 0, 0, 0, 0, 0 }, { 0, 7, 0, 0, 0, 0, 0, 0 },
	{ 1, 7, 0, 0, 0, 0, 0, 0 }, { 0, 1, 7, 0, 0, 0, 0, 0 },
	{ 2, 7, 0, 0, 0, 0, 0, 0 }, { 0, 2, 7, 0, 0, 0, 0, 0 },
	{ 1, 2, 7, 0, 0, 0, 0, 0 }, { 0, 1, 2, 7, 0, 0, 0, 0 },
	{ 3, 7, 0, 0, 0, 0, 0, 0 }, { 0, 3, 7, 0, 0, 0, 0, 0 },
	{ 1, 3, 7, 0, 0, 0, 0, 0 }, { 0, 1, 3, 7, 0, 0, 0, 0 },
	{ 2, 3, 7, 0, 0, 0, 0, 0 }, { 0, 2, 3, 7, 0, 0, 0, 0 },
	{ 1, 2, 3, 7, 0, 0, 0, 0 }, { 0, 1, 2, 3, 7, 0, 0, 0 },
	{ 4, 7, 0, 0, 0, 0, 0, 0 }, { 0, 4, 7, 0, 0, 0, 0, 0 },
	{ 1, 4, 7, 0, 0, 0, 0, 0 }, { 0, 1, 4, 7, 0, 0, 0, 0 },
	{ 2, 4, 7, 0, 0, 0, 0, 0 }, { 0, 2, 4, 7, 0, 0, 0, 0 },
	{ 1, 2, 4, 7, 0, 0, 0, 0 }, { 0, 1, 2, 4, 7, 0, 0, 0 },
	{ 3, 4, 7, 0, 0, 0, 0, 0 }, { 0, 3, 4, 7, 0, 0, 0, 0 },
	{ 1, 3, 4, 7, 0, 0, 0, 0 }, { 0, 1, 3, 4, 7, 0, 0, 0 },
	{ 2, 3, 4, 7, 0, 0, 0, 0 }, { 0, 2, 3, 4, 7, 0, 0, 0 },
	{ 1, 2, 3, 4, 7, 0, 0, 0 }, { 0, 1, 2, 3, 4, 7, 0, 0 },
	{ 5, 7, 0, 0, 0, 0, 0, 0 }, { 0, 5, 7, 0, 0, 0, 0, 0 },
	{ 1, 5, 7, 0, 0, 0, 0, 0 }, { 0, 1, 5, 7, 0, 0, 0, 0 },
	{ 2, 5, 7, 0, 0, 0, 0, 0 }, { 0, 2, 5, 7, 0, 0, 0, 0 },
	{ 1, 2, 5, 7, 0, 0, 0, 0 }, { 0, 1, 2, 5, 7, 0, 0, 0 },
	{ 3, 5, 7, 0, 0, 0, 0, 0 }, { 0, 3, 5, 7, 0, 0, 0, 0 },
	{ 1, 3, 5, 7, 0, 0, 0, 0 }, { 0, 1, 3, 5, 7, 0, 0, 0 },
	{ 2, 3, 5, 7, 0, 0, 0, 0 }, { 0, 2, 3, 5, 7, 0, 0, 0 },
	{ 1, 2, 3, 5, 7, 0, 0, 0 }, { 0, 1, 2, 3, 5, 7, 0, 0 },
	{ 4, 5, 7, 0, 0, 0, 0, 0 }, { 0, 4, 5, 7, 0, 0, 0, 0 },
	{ 1, 4, 5, 7, 0, 0, 0, 0 }, { 0, 1, 4, 5, 7, 0, 0, 0 },
	{ 2, 4, 5, 7, 0, 0, 0, 0 }, { 0, 2, 4, 5, 7, 0, 0, 0 },
	{ 1, 2, 4, 5, 7, 0, 0, 0 }, { 0, 1, 2, 4, 5, 7, 0, 0 },
	{ 3, 4, 5, 7, 0, 0, 0, 0 }, { 0, 3, 4, 5, 7, 0, 0, 0 },
	{ 1, 3, 4, 5, 7, 0, 0, 0 }, { 0, 1, 3, 4, 5, 7, 0, 0 },
	{ 2, 3, 4, 5, 7, 0, 0, 0 }, { 0, 2, 3, 4, 5, 7, 0, 0 },
	{ 1, 2, 3, 4, 5, 7, 0, 0 }, { 0, 1, 2, 3, 4, 5, 7, 0 },
	{ 6, 7, 0, 0, 0, 0, 0, 0 }, { 0, 6, 7, 0, 0, 0, 0, 0 },
	{ 1, 6, 7, 0, 0, 0, 0, 0 }, { 0, 1, 6, 7, 0, 0, 0, 0 },
	{ 2, 6, 7, 0, 0, 0, 0, 0 }, { 0, 2, 6, 7, 0, 0, 0, 0 },
	{ 1, 2, 6, 7, 0, 0, 0, 0 }, { 0, 1, 2, 6, 7, 0, 0, 0 },
	{ 3, 6, 7, 0, 0, 0, 0, 0 }, { 0, 3, 6, 7, 0, 0, 0, 0 },
	{ 1, 3, 6, 7, 0, 0, 0, 0 }, { 0, 1, 3, 6, 7, 0, 0, 0 },
	{ 2, 3, 6, 7, 0, 0, 0, 0 }, { 0, 2, 3, 6, 7, 0, 0, 0 },
	{ 1, 2, 3, 6, 7, 0, 0, 0 }, { 0, 1, 2, 3, 6, 7, 0, 0 },
	{ 4, 6, 7, 0, 0, 0, 0, 0 }, { 0, 4, 6, 7, 0, 0, 0, 0 },
	{ 1, 4, 6, 7, 0, 0, 0, 0 }, { 0, 1, 4, 6, 7, 0, 0, 0 },
	{ 2, 4, 6, 7, 0, 0, 0, 0 }, { 0, 2, 4, 6, 7, 0, 0, 0 },
	{ 1, 2, 4, 6, 7, 0, 0, 0 }, { 0, 1, 2, 4, 6, 7, 0, 0 },
	{ 3, 4, 6, 7, 0, 0, 0, 0 }, { 0, 3, 4, 6, 7, 0, 0, 0 },
	{ 1, 3, 4, 6, 7, 0, 0, 0 }, { 0, 1, 3, 4, 6, 7, 0, 0 },
	{ 2, 3, 4, 6, 7, 0, 0, 0 }, { 0, 2, 3, 4, 6, 7, 0, 0 },
	{ 1, 2, 3, 4, 6, 7, 0, 0 }, { 0, 1, 2, 3, 4, 6, 7, 0 },
	{ 5, 6, 7, 0, 0, 0, 0, 0 }, { 0, 5, 6, 7, 0, 0, 0, 0 },
	{ 1, 5, 6, 7, 0, 0, 0, 0 }, { 0, 1, 5, 6, 7, 0, 0, 0 },
	{ 2, 5, 6, 7, 0, 0, 0, 0 }, { 0, 2, 5, 6, 7, 0, 0, 0 },
	{ 1, 2, 5, 6, 7, 0, 0, 0 }, { 0, 1, 2, 5, 6, 7, 0, 0 },
	{ 3, 5, 6, 7, 0, 0, 0, 0 }, { 0, 3, 5, 6, 7, 0, 0, 0 },
	{ 1, 3, 5, 6, 7, 0, 0, 0 }, { 0, 1, 3, 5, 6, 7, 0, 0 },
	{ 2, 3, 5, 6, 7, 0, 0, 0 }, { 0, 2, 3, 5, 6, 7, 0, 0 },
	{ 1, 2, 3, 5, 6, 7, 0, 0 }, { 0, 1, 2, 3, 5, 6, 7, 0 },
	{ 4, 5, 6, 7, 0, 0, 0, 0 }, { 0, 4, 5, 6, 7, 0, 0, 0 },
	{ 1, 4, 5, 6, 7, 0, 0, 0 }, { 0, 1, 4, 5, 6, 7, 0, 0 },
	{ 2, 4, 5, 6, 7, 0, 0, 0 }, { 0, 2, 4, 5, 6, 7, 0, 0 },
	{ 1, 2, 4, 5, 6, 7, 0, 0 }, { 0, 1, 2, 4, 5, 6, 7, 0 },
	{ 3, 4, 5, 6, 7, 0, 0, 0 }, { 0, 3, 4, 5, 6, 7, 0, 0 },
	{ 1, 3, 4, 5, 6, 7, 0, 0 }, { 0, 1, 3, 4, 5, 6, 7, 0 },
	{ 2, 3, 4, 5, 6, 7, 0, 0 }, { 0, 2, 3, 4, 5, 6, 7, 0 },
	{ 1, 2, 3, 4, 5, 6, 7, 0 }, { 0, 1, 2, 3, 4, 5, 6, 7 }
};

unsigned int rej_uniform_avx(int32_t *restrict r,
			     const uint8_t buf[REJ_UNIFORM_BUFLEN + 8])
{
	unsigned int ctr, pos;
	uint32_t good;
	__m256i d, tmp;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	LC_FPU_ENABLE;
	const __m256i bound = _mm256_set1_epi32(LC_DILITHIUM_Q);
	const __m256i mask = _mm256_set1_epi32(0x7FFFFF);
	const __m256i idx8 =
		_mm256_set_epi8(-1, 15, 14, 13, -1, 12, 11, 10, -1, 9, 8, 7, -1,
				6, 5, 4, -1, 11, 10, 9, -1, 8, 7, 6, -1, 5, 4,
				3, -1, 2, 1, 0);
#pragma GCC diagnostic pop
	uint32_t t;

	ctr = pos = 0;
	while (pos <= REJ_UNIFORM_BUFLEN - 24) {
		d = _mm256_loadu_si256((__m256i_u *)&buf[pos]);
		d = _mm256_permute4x64_epi64(d, 0x94);
		d = _mm256_shuffle_epi8(d, idx8);
		d = _mm256_and_si256(d, mask);
		pos += 24;

		tmp = _mm256_sub_epi32(d, bound);
		good = (uint32_t)_mm256_movemask_ps((__m256)tmp);
		tmp = _mm256_cvtepu8_epi32(
			_mm_loadl_epi64((__m128i_u *)&idxlut[good]));
		d = _mm256_permutevar8x32_epi32(d, tmp);

		_mm256_storeu_si256((__m256i_u *)&r[ctr], d);
		ctr += (uint32_t)_mm_popcnt_u32(good);

		if (ctr > LC_DILITHIUM_N - 8)
			break;
	}
	LC_FPU_DISABLE;

	while (ctr < LC_DILITHIUM_N && pos <= REJ_UNIFORM_BUFLEN - 3) {
		t = buf[pos++];
		t |= (uint32_t)buf[pos++] << 8;
		t |= (uint32_t)buf[pos++] << 16;
		t &= 0x7FFFFF;

		if (t < LC_DILITHIUM_Q)
			r[ctr++] = (int32_t)t;
	}

	return ctr;
}

#if LC_DILITHIUM_ETA == 2
unsigned int rej_eta_avx(int32_t *restrict r,
			 const uint8_t buf[REJ_UNIFORM_ETA_BUFLEN])
{
	unsigned int ctr, pos;
	uint32_t good;
	__m256i f0, f1, f2;
	__m128i g0, g1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	LC_FPU_ENABLE;
	const __m256i mask = _mm256_set1_epi8(15);
	const __m256i eta = _mm256_set1_epi8(LC_DILITHIUM_ETA);
	const __m256i bound = mask;
	const __m256i v = _mm256_set1_epi32(-6560);
	const __m256i p = _mm256_set1_epi32(5);
#pragma GCC diagnostic pop
	uint32_t t0, t1;

	ctr = pos = 0;
	while (ctr <= LC_DILITHIUM_N - 8 &&
	       pos <= REJ_UNIFORM_ETA_BUFLEN - 16) {
		f0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i_u *)&buf[pos]));
		f1 = _mm256_slli_epi16(f0, 4);
		f0 = _mm256_or_si256(f0, f1);
		f0 = _mm256_and_si256(f0, mask);

		f1 = _mm256_sub_epi8(f0, bound);
		f0 = _mm256_sub_epi8(eta, f0);
		good = (uint32_t)_mm256_movemask_epi8(f1);

		g0 = _mm256_castsi256_si128(f0);
		g1 = _mm_loadl_epi64((__m128i_u *)&idxlut[good & 0xFF]);
		g1 = _mm_shuffle_epi8(g0, g1);
		f1 = _mm256_cvtepi8_epi32(g1);
		f2 = _mm256_mulhrs_epi16(f1, v);
		f2 = _mm256_mullo_epi16(f2, p);
		f1 = _mm256_add_epi32(f1, f2);
		_mm256_storeu_si256((__m256i_u *)&r[ctr], f1);
		ctr += (uint32_t)_mm_popcnt_u32(good & 0xFF);
		good >>= 8;
		pos += 4;

		if (ctr > LC_DILITHIUM_N - 8)
			break;
		g0 = _mm_bsrli_si128(g0, 8);
		g1 = _mm_loadl_epi64((__m128i_u *)&idxlut[good & 0xFF]);
		g1 = _mm_shuffle_epi8(g0, g1);
		f1 = _mm256_cvtepi8_epi32(g1);
		f2 = _mm256_mulhrs_epi16(f1, v);
		f2 = _mm256_mullo_epi16(f2, p);
		f1 = _mm256_add_epi32(f1, f2);
		_mm256_storeu_si256((__m256i_u *)&r[ctr], f1);
		ctr += (uint32_t)_mm_popcnt_u32(good & 0xFF);
		good >>= 8;
		pos += 4;

		if (ctr > LC_DILITHIUM_N - 8)
			break;
		g0 = _mm256_extracti128_si256(f0, 1);
		g1 = _mm_loadl_epi64((__m128i_u *)&idxlut[good & 0xFF]);
		g1 = _mm_shuffle_epi8(g0, g1);
		f1 = _mm256_cvtepi8_epi32(g1);
		f2 = _mm256_mulhrs_epi16(f1, v);
		f2 = _mm256_mullo_epi16(f2, p);
		f1 = _mm256_add_epi32(f1, f2);
		_mm256_storeu_si256((__m256i_u *)&r[ctr], f1);
		ctr += (uint32_t)_mm_popcnt_u32(good & 0xFF);
		good >>= 8;
		pos += 4;

		if (ctr > LC_DILITHIUM_N - 8)
			break;
		g0 = _mm_bsrli_si128(g0, 8);
		g1 = _mm_loadl_epi64((__m128i_u *)&idxlut[good]);
		g1 = _mm_shuffle_epi8(g0, g1);
		f1 = _mm256_cvtepi8_epi32(g1);
		f2 = _mm256_mulhrs_epi16(f1, v);
		f2 = _mm256_mullo_epi16(f2, p);
		f1 = _mm256_add_epi32(f1, f2);
		_mm256_storeu_si256((__m256i_u *)&r[ctr], f1);
		ctr += (uint32_t)_mm_popcnt_u32(good);
		pos += 4;
	}
	LC_FPU_DISABLE;

	while (ctr < LC_DILITHIUM_N && pos < REJ_UNIFORM_ETA_BUFLEN) {
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;

		if (t0 < 15) {
			t0 = t0 - (205 * t0 >> 10) * 5;
			r[ctr++] = (int32_t)(2 - t0);
		}
		if (t1 < 15 && ctr < LC_DILITHIUM_N) {
			t1 = t1 - (205 * t1 >> 10) * 5;
			r[ctr++] = (int32_t)(2 - t1);
		}
	}

	return ctr;
}

#elif LC_DILITHIUM_ETA == 4
unsigned int rej_eta_avx(int32_t *restrict r,
			 const uint8_t buf[REJ_UNIFORM_ETA_BUFLEN])
{
	unsigned int ctr, pos;
	uint32_t good;
	__m256i f0, f1;
	__m128i g0, g1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	LC_FPU_ENABLE;
	const __m256i mask = _mm256_set1_epi8(15);
	const __m256i eta = _mm256_set1_epi8(4);
	const __m256i bound = _mm256_set1_epi8(9);
#pragma GCC diagnostic pop
	uint32_t t0, t1;

	ctr = pos = 0;
	while (ctr <= LC_DILITHIUM_N - 8 &&
	       pos <= REJ_UNIFORM_ETA_BUFLEN - 16) {

		f0 = _mm256_cvtepu8_epi16(
			_mm_loadu_si128((__m128i_u *)&buf[pos]));
		f1 = _mm256_slli_epi16(f0,4);
		f0 = _mm256_or_si256(f0,f1);
		f0 = _mm256_and_si256(f0,mask);

		f1 = _mm256_sub_epi8(f0,bound);
		f0 = _mm256_sub_epi8(eta,f0);
		good =  (uint32_t)_mm256_movemask_epi8(f1);

		g0 = _mm256_castsi256_si128(f0);
		g1 = _mm_loadl_epi64((__m128i_u *)&idxlut[good & 0xFF]);
		g1 = _mm_shuffle_epi8(g0,g1);
		f1 = _mm256_cvtepi8_epi32(g1);
		_mm256_storeu_si256((__m256i_u *)&r[ctr],f1);
		ctr +=  (uint32_t)_mm_popcnt_u32(good & 0xFF);
		good >>= 8;
		pos += 4;

		if (ctr > LC_DILITHIUM_N - 8)
			break;
		g0 = _mm_bsrli_si128(g0,8);
		g1 = _mm_loadl_epi64((__m128i_u *)&idxlut[good & 0xFF]);
		g1 = _mm_shuffle_epi8(g0,g1);
		f1 = _mm256_cvtepi8_epi32(g1);
		_mm256_storeu_si256((__m256i_u *)&r[ctr],f1);
		ctr += (uint32_t)_mm_popcnt_u32(good & 0xFF);
		good >>= 8;
		pos += 4;

		if (ctr > LC_DILITHIUM_N - 8)
			break;
		g0 = _mm256_extracti128_si256(f0,1);
		g1 = _mm_loadl_epi64((__m128i_u *)&idxlut[good & 0xFF]);
		g1 = _mm_shuffle_epi8(g0,g1);
		f1 = _mm256_cvtepi8_epi32(g1);
		_mm256_storeu_si256((__m256i_u *)&r[ctr],f1);
		ctr +=  (uint32_t)_mm_popcnt_u32(good & 0xFF);
		good >>= 8;
		pos += 4;

		if (ctr > LC_DILITHIUM_N - 8)
			break;
		g0 = _mm_bsrli_si128(g0,8);
		g1 = _mm_loadl_epi64((__m128i_u *)&idxlut[good]);
		g1 = _mm_shuffle_epi8(g0,g1);
		f1 = _mm256_cvtepi8_epi32(g1);
		_mm256_storeu_si256((__m256i_u *)&r[ctr],f1);
		ctr +=  (uint32_t)_mm_popcnt_u32(good);
		pos += 4;
	}
	LC_FPU_DISABLE;

	while (ctr < LC_DILITHIUM_N && pos < REJ_UNIFORM_ETA_BUFLEN) {
		t0 = buf[pos] & 0x0F;
		t1 = buf[pos++] >> 4;

		if (t0 < 9)
			r[ctr++] = (int32_t)(4 - t0);
		if (t1 < 9 && ctr < LC_DILITHIUM_N)
			r[ctr++] = (int32_t)(4 - t1);
	}

	return ctr;
}

#else
#error "Undefined LC_DILITHIUM_ETA"
#endif
