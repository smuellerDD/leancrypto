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

#include "dilithium_type.h"
#include "dilithium_consts_avx2.h"
#include "dilithium_rejsample_avx2.h"
#include "dilithium_rounding_avx2.h"
#include "ext_headers_x86.h"

#define _mm256_blendv_epi32(a, b, mask)                                        \
	_mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a),           \
					     _mm256_castsi256_ps(b),           \
					     _mm256_castsi256_ps(mask)))

/**
 * @brief power2round_avx
 *
 * For finite field elements a, compute a0, a1 such that
 * a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}.
 * Assumes a to be positive standard representative.
 *
 * @param a1 output array of length N/8 with high bits
 * @param a0 output array of length N/8 with low bits a0
 * @param a: input array of length N/8
 */
void power2round_avx(__m256i *a1, __m256i *a0, const __m256i *a)
{
	unsigned int i;
	__m256i f, f0, f1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	LC_FPU_ENABLE;
	const __m256i mask = _mm256_set1_epi32(-(1 << LC_DILITHIUM_D));
	const __m256i half = _mm256_set1_epi32((1 << (LC_DILITHIUM_D - 1)) - 1);
#pragma GCC diagnostic pop

	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		f = _mm256_load_si256(&a[i]);
		f1 = _mm256_add_epi32(f, half);
		f0 = _mm256_and_si256(f1, mask);
		f1 = _mm256_srli_epi32(f1, LC_DILITHIUM_D);
		f0 = _mm256_sub_epi32(f, f0);
		_mm256_store_si256(&a1[i], f1);
		_mm256_store_si256(&a0[i], f0);
	}
	LC_FPU_DISABLE;
}

/**
 * @brief decompose_avx
 *
 * For finite field element a, compute high and low parts a0, a1 such that
 * a mod^+ Q = a1*ALPHA + a0 with -ALPHA/2 < a0 <= ALPHA/2 except if
 * a1 = (Q-1)/ALPHA where we set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
 * Assumes a to be positive standard representative.
 *
 * @param a1 output array of length N/8 with high parts
 * @param a0 output array of length N/8 with low parts a0
 * @param a input array of length N/8
 */
void decompose_avx(__m256i *a1, __m256i *a0, const __m256i *a)
{
	unsigned int i;
	__m256i f, f0, f1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	LC_FPU_ENABLE;
	const __m256i q = _mm256_load_si256(&dilithium_qdata.vec[_8XQ / 8]);
	const __m256i hq = _mm256_srli_epi32(q, 1);
	const __m256i v = _mm256_set1_epi32(1025);
	const __m256i alpha = _mm256_set1_epi32(2 * LC_DILITHIUM_GAMMA2);
	const __m256i off = _mm256_set1_epi32(127);
	const __m256i shift = _mm256_set1_epi32(512);
	const __m256i mask = _mm256_set1_epi32(15);
#pragma GCC diagnostic pop

	for (i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_load_si256(&a[i]);
		f1 = _mm256_add_epi32(f, off);
		f1 = _mm256_srli_epi32(f1, 7);
		f1 = _mm256_mulhi_epu16(f1, v);
		f1 = _mm256_mulhrs_epi16(f1, shift);
		f1 = _mm256_and_si256(f1, mask);
		f0 = _mm256_mullo_epi32(f1, alpha);
		f0 = _mm256_sub_epi32(f, f0);
		f = _mm256_cmpgt_epi32(f0, hq);
		f = _mm256_and_si256(f, q);
		f0 = _mm256_sub_epi32(f0, f);
		_mm256_store_si256(&a1[i], f1);
		_mm256_store_si256(&a0[i], f0);
	}
	LC_FPU_DISABLE;
}

/**
 * @brief make_hint_avx
 *
 * Compute indices of polynomial coefficients whose low bits overflow into the
 * high bits.
 *
 * @param hint hint array
 * @param a0 low bits of input elements
 * @param a1 high bits of input elements
 *
 * @return number of overflowing low bits
 */
unsigned int make_hint_avx(uint8_t hint[LC_DILITHIUM_N],
			   const __m256i *restrict a0,
			   const __m256i *restrict a1)
{
	unsigned int i, n = 0;
	__m256i f0, f1, g0, g1;
	uint32_t bad;
	uint64_t idx;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	LC_FPU_ENABLE;
	const __m256i low = _mm256_set1_epi32(-LC_DILITHIUM_GAMMA2);
	const __m256i high = _mm256_set1_epi32(LC_DILITHIUM_GAMMA2);
#pragma GCC diagnostic pop

	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		f0 = _mm256_load_si256(&a0[i]);
		f1 = _mm256_load_si256(&a1[i]);
		g0 = _mm256_abs_epi32(f0);
		g0 = _mm256_cmpgt_epi32(g0, high);
		g1 = _mm256_cmpeq_epi32(f0, low);
		g1 = _mm256_sign_epi32(g1, f1);
		g0 = _mm256_or_si256(g0, g1);

		bad = (uint32_t)_mm256_movemask_ps((__m256)g0);
		memcpy(&idx, idxlut[bad], 8);
		idx += (uint64_t)0x0808080808080808 * i;
		memcpy(&hint[n], &idx, 8);
		n += (unsigned int)_mm_popcnt_u32(bad);
	}
	LC_FPU_DISABLE;

	return n;
}

/**
 * @brief use_hint_avx
 *
 * Correct high parts according to hint.
 *
 * @param b output array of length N/8 with corrected high parts
 * @param a input array of length N/8
 * @param a input array of length N/8 with hint bits
 */
void use_hint_avx(__m256i *b, const __m256i *a, const __m256i *restrict hint)
{
	unsigned int i;
	__m256i a0[LC_DILITHIUM_N / 8];
	__m256i f, g, h, t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	LC_FPU_ENABLE;
	const __m256i zero = _mm256_setzero_si256();
	const __m256i mask = _mm256_set1_epi32(15);
	LC_FPU_DISABLE;
#pragma GCC diagnostic pop

	decompose_avx(b, a0, a);

	LC_FPU_ENABLE;
	for (i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_load_si256(&a0[i]);
		g = _mm256_load_si256(&b[i]);
		h = _mm256_load_si256(&hint[i]);
		t = _mm256_blendv_epi32(zero, h, f);
		t = _mm256_slli_epi32(t, 1);
		h = _mm256_sub_epi32(h, t);
		g = _mm256_add_epi32(g, h);
		g = _mm256_and_si256(g, mask);
		_mm256_store_si256(&b[i], g);
	}
	LC_FPU_DISABLE;
}
