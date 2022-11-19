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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include <stdint.h>
#include <immintrin.h>

#include "kyber_poly_avx2.h"
#include "lc_kyber.h"

/**
 * cbd2
 *
 * Given an array of uniformly random bytes, compute polynomial with
 * coefficients distributed according to a centered binomial distribution with
 * parameter eta=2
 *
 * @param r pointer to output polynomial
 * @param buf pointer to aligned input byte array
 */
void cbd2(poly * restrict r, const __m256i buf[2 * LC_KYBER_N / 128])
{
	unsigned int i;
	__m256i f0, f1, f2, f3;
	const __m256i mask55 = _mm256_set1_epi32(0x55555555);
	const __m256i mask33 = _mm256_set1_epi32(0x33333333);
	const __m256i mask03 = _mm256_set1_epi32(0x03030303);
	const __m256i mask0F = _mm256_set1_epi32(0x0F0F0F0F);

	for (i = 0; i < LC_KYBER_N / 64; i++) {
		f0 = _mm256_load_si256(&buf[i]);

		f1 = _mm256_srli_epi16(f0, 1);
		f0 = _mm256_and_si256(mask55, f0);
		f1 = _mm256_and_si256(mask55, f1);
		f0 = _mm256_add_epi8(f0, f1);

		f1 = _mm256_srli_epi16(f0, 2);
		f0 = _mm256_and_si256(mask33, f0);
		f1 = _mm256_and_si256(mask33, f1);
		f0 = _mm256_add_epi8(f0, mask33);
		f0 = _mm256_sub_epi8(f0, f1);

		f1 = _mm256_srli_epi16(f0, 4);
		f0 = _mm256_and_si256(mask0F, f0);
		f1 = _mm256_and_si256(mask0F, f1);
		f0 = _mm256_sub_epi8(f0, mask03);
		f1 = _mm256_sub_epi8(f1, mask03);

		f2 = _mm256_unpacklo_epi8(f0, f1);
		f3 = _mm256_unpackhi_epi8(f0, f1);

		f0 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f2));
		f1 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f2,1));
		f2 = _mm256_cvtepi8_epi16(_mm256_castsi256_si128(f3));
		f3 = _mm256_cvtepi8_epi16(_mm256_extracti128_si256(f3,1));

		_mm256_store_si256(&r->vec[4*i+0], f0);
		_mm256_store_si256(&r->vec[4*i+1], f2);
		_mm256_store_si256(&r->vec[4*i+2], f1);
		_mm256_store_si256(&r->vec[4*i+3], f3);
	}
}
