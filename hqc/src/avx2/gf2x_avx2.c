/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://pqc-hqc.org/
 *
 * The code is referenced as Public Domain
 */
/**
 * @file gf2x.c
 * @brief AVX2 implementation of multiplication of two polynomials
 */

#include "gf2x_avx2.h"
#include "helper.h"
#include "hqc_type.h"

/**
 * @brief Compute o(x) = a(x) mod \f$ X^n - 1\f$
 *
 * This function computes the modular reduction of the polynomial a(x)
 *
 * @param[out] o Pointer to the result
 * @param[in] a256 Pointer to the polynomial a(x)
 */
static inline void reduce(__m256i *o, const __m256i *a256)
{
	__m256i r256, carry256;
	uint64_t *a = (uint64_t *)a256;
	uint64_t *tmp_reduce = (uint64_t *)o;
	static const int32_t dec64 = LC_HQC_PARAM_N & 0x3f;
	static const int32_t d0 = LC_HQC_WORD - dec64;
	size_t i, i2;

	for (i = LC_HQC_LAST64; i < (LC_HQC_PARAM_N >> 5) - 4; i += 4) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		r256 = _mm256_lddqu_si256((__m256i const *)(&a[i]));
#pragma GCC diagnostic pop
		r256 = _mm256_srli_epi64(r256, dec64);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		carry256 = _mm256_lddqu_si256((__m256i const *)(&a[i + 1]));
#pragma GCC diagnostic pop
		carry256 = _mm256_slli_epi64(carry256, d0);
		r256 ^= carry256;
		i2 = (i - LC_HQC_LAST64) >> 2;
		o[i2] = a256[i2] ^ r256;
	}

	i = i - LC_HQC_LAST64;

	for (; i < LC_HQC_LAST64 + 1; i++) {
		uint64_t r = a[i + LC_HQC_LAST64] >> dec64;
		uint64_t carry = a[i + LC_HQC_LAST64 + 1] << d0;
		r ^= carry;
		tmp_reduce[i] = a[i] ^ r;
	}

	tmp_reduce[LC_HQC_LAST64] &= LC_HQC_RED_MASK;
}

/**
 * @brief Compute C(x) = A(x)*B(x) 
 * A(x) and B(x) are stored in 128-bit registers
 * This function computes A(x)*B(x) using Karatsuba
 *
 * @param[out] C Pointer to the result
 * @param[in] A Pointer to the polynomial A(x)
 * @param[in] B Pointer to the polynomial B(x)
 */
static inline void karat_mult_1(__m128i *C, const __m128i *A, const __m128i *B,
				struct vect_mul_ws *ws)
{
	ws->karat_mult_1.Al = _mm_loadu_si128(A);
	ws->karat_mult_1.Ah = _mm_loadu_si128(A + 1);
	ws->karat_mult_1.Bl = _mm_loadu_si128(B);
	ws->karat_mult_1.Bh = _mm_loadu_si128(B + 1);

	// Computation of Al.Bl=D0
	ws->karat_mult_1.DD0 = _mm_clmulepi64_si128(ws->karat_mult_1.Al,
						    ws->karat_mult_1.Bl, 0);
	ws->karat_mult_1.DD2 = _mm_clmulepi64_si128(ws->karat_mult_1.Al,
						    ws->karat_mult_1.Bl, 0x11);
	ws->karat_mult_1.AAlpAAh =
		_mm_xor_si128(ws->karat_mult_1.Al,
			      _mm_shuffle_epi32(ws->karat_mult_1.Al, 0x4e));
	ws->karat_mult_1.BBlpBBh =
		_mm_xor_si128(ws->karat_mult_1.Bl,
			      _mm_shuffle_epi32(ws->karat_mult_1.Bl, 0x4e));
	ws->karat_mult_1.DD1 = _mm_xor_si128(
		_mm_xor_si128(ws->karat_mult_1.DD0, ws->karat_mult_1.DD2),
		_mm_clmulepi64_si128(ws->karat_mult_1.AAlpAAh,
				     ws->karat_mult_1.BBlpBBh, 0));
	ws->karat_mult_1.D0[0] = _mm_xor_si128(
		ws->karat_mult_1.DD0,
		_mm_unpacklo_epi64(_mm_setzero_si128(), ws->karat_mult_1.DD1));
	ws->karat_mult_1.D0[1] = _mm_xor_si128(
		ws->karat_mult_1.DD2,
		_mm_unpackhi_epi64(ws->karat_mult_1.DD1, _mm_setzero_si128()));

	//	Computation of Ah.Bh=D2
	ws->karat_mult_1.DD0 = _mm_clmulepi64_si128(ws->karat_mult_1.Ah,
						    ws->karat_mult_1.Bh, 0);
	ws->karat_mult_1.DD2 = _mm_clmulepi64_si128(ws->karat_mult_1.Ah,
						    ws->karat_mult_1.Bh, 0x11);
	ws->karat_mult_1.AAlpAAh =
		_mm_xor_si128(ws->karat_mult_1.Ah,
			      _mm_shuffle_epi32(ws->karat_mult_1.Ah, 0x4e));
	ws->karat_mult_1.BBlpBBh =
		_mm_xor_si128(ws->karat_mult_1.Bh,
			      _mm_shuffle_epi32(ws->karat_mult_1.Bh, 0x4e));
	ws->karat_mult_1.DD1 = _mm_xor_si128(
		_mm_xor_si128(ws->karat_mult_1.DD0, ws->karat_mult_1.DD2),
		_mm_clmulepi64_si128(ws->karat_mult_1.AAlpAAh,
				     ws->karat_mult_1.BBlpBBh, 0));
	ws->karat_mult_1.D2[0] = _mm_xor_si128(
		ws->karat_mult_1.DD0,
		_mm_unpacklo_epi64(_mm_setzero_si128(), ws->karat_mult_1.DD1));
	ws->karat_mult_1.D2[1] = _mm_xor_si128(
		ws->karat_mult_1.DD2,
		_mm_unpackhi_epi64(ws->karat_mult_1.DD1, _mm_setzero_si128()));

	// Computation of AlpAh.BlpBh=D1
	// initialisation of AlpAh and BlpBh
	ws->karat_mult_1.AlpAh =
		_mm_xor_si128(ws->karat_mult_1.Al, ws->karat_mult_1.Ah);
	ws->karat_mult_1.BlpBh =
		_mm_xor_si128(ws->karat_mult_1.Bl, ws->karat_mult_1.Bh);

	ws->karat_mult_1.DD0 = _mm_clmulepi64_si128(ws->karat_mult_1.AlpAh,
						    ws->karat_mult_1.BlpBh, 0);
	ws->karat_mult_1.DD2 = _mm_clmulepi64_si128(
		ws->karat_mult_1.AlpAh, ws->karat_mult_1.BlpBh, 0x11);
	ws->karat_mult_1.AAlpAAh =
		_mm_xor_si128(ws->karat_mult_1.AlpAh,
			      _mm_shuffle_epi32(ws->karat_mult_1.AlpAh, 0x4e));
	ws->karat_mult_1.BBlpBBh =
		_mm_xor_si128(ws->karat_mult_1.BlpBh,
			      _mm_shuffle_epi32(ws->karat_mult_1.BlpBh, 0x4e));
	ws->karat_mult_1.DD1 = _mm_xor_si128(
		_mm_xor_si128(ws->karat_mult_1.DD0, ws->karat_mult_1.DD2),
		_mm_clmulepi64_si128(ws->karat_mult_1.AAlpAAh,
				     ws->karat_mult_1.BBlpBBh, 0));
	ws->karat_mult_1.D1[0] = _mm_xor_si128(
		ws->karat_mult_1.DD0,
		_mm_unpacklo_epi64(_mm_setzero_si128(), ws->karat_mult_1.DD1));
	ws->karat_mult_1.D1[1] = _mm_xor_si128(
		ws->karat_mult_1.DD2,
		_mm_unpackhi_epi64(ws->karat_mult_1.DD1, _mm_setzero_si128()));

	// Computation of C
	ws->karat_mult_1.middle =
		_mm_xor_si128(ws->karat_mult_1.D0[1], ws->karat_mult_1.D2[0]);

	C[0] = ws->karat_mult_1.D0[0];
	C[1] = ws->karat_mult_1.middle ^ ws->karat_mult_1.D0[0] ^
	       ws->karat_mult_1.D1[0];
	C[2] = ws->karat_mult_1.middle ^ ws->karat_mult_1.D1[1] ^
	       ws->karat_mult_1.D2[1];
	C[3] = ws->karat_mult_1.D2[1];
}

/**
 * @brief Compute C(x) = A(x)*B(x) 
 *
 * This function computes A(x)*B(x) using Karatsuba
 * A(x) and B(x) are stored in 256-bit registers
 * @param[out] C Pointer to the result
 * @param[in] A Pointer to the polynomial A(x)
 * @param[in] B Pointer to the polynomial B(x)
 */
static inline void karat_mult_2(__m256i *C, const __m256i *A, const __m256i *B,
				struct vect_mul_ws *ws)
{
	__m128i *A128 = (__m128i *)A, *B128 = (__m128i *)B;

	karat_mult_1((__m128i *)ws->karat_mult_2.D0, A128, B128, ws);
	karat_mult_1((__m128i *)ws->karat_mult_2.D2, A128 + 2, B128 + 2, ws);

	ws->karat_mult_2.SAA = _mm256_xor_si256(A[0], A[1]);
	ws->karat_mult_2.SBB = _mm256_xor_si256(B[0], B[1]);
	karat_mult_1((__m128i *)ws->karat_mult_2.D1,
		     (__m128i *)&ws->karat_mult_2.SAA,
		     (__m128i *)&ws->karat_mult_2.SBB, ws);

	ws->karat_mult_2.middle = _mm256_xor_si256(ws->karat_mult_2.D0[1],
						   ws->karat_mult_2.D2[0]);

	C[0] = ws->karat_mult_2.D0[0];
	C[1] = ws->karat_mult_2.middle ^ ws->karat_mult_2.D0[0] ^
	       ws->karat_mult_2.D1[0];
	C[2] = ws->karat_mult_2.middle ^ ws->karat_mult_2.D1[1] ^
	       ws->karat_mult_2.D2[1];
	C[3] = ws->karat_mult_2.D2[1];
}

/**
 * @brief Compute C(x) = A(x)*B(x) 
 *
 * This function computes A(x)*B(x) using Karatsuba
 * A(x) and B(x) are stored in 256-bit registers
 * @param[out] C Pointer to the result
 * @param[in] A Pointer to the polynomial A(x)
 * @param[in] B Pointer to the polynomial B(x)
 */
static inline void karat_mult_4(__m256i *C, const __m256i *A, const __m256i *B,
				struct vect_mul_ws *ws)
{
	karat_mult_2(ws->karat_mult_4.D0, A, B, ws);
	karat_mult_2(ws->karat_mult_4.D2, A + 2, B + 2, ws);
	ws->karat_mult_4.SAA[0] = A[0] ^ A[2];
	ws->karat_mult_4.SBB[0] = B[0] ^ B[2];
	ws->karat_mult_4.SAA[1] = A[1] ^ A[3];
	ws->karat_mult_4.SBB[1] = B[1] ^ B[3];
	karat_mult_2(ws->karat_mult_4.D1, ws->karat_mult_4.SAA,
		     ws->karat_mult_4.SBB, ws);

	ws->karat_mult_4.middle0 = _mm256_xor_si256(ws->karat_mult_4.D0[2],
						    ws->karat_mult_4.D2[0]);
	ws->karat_mult_4.middle1 = _mm256_xor_si256(ws->karat_mult_4.D0[3],
						    ws->karat_mult_4.D2[1]);

	C[0] = ws->karat_mult_4.D0[0];
	C[1] = ws->karat_mult_4.D0[1];
	C[2] = ws->karat_mult_4.middle0 ^ ws->karat_mult_4.D0[0] ^
	       ws->karat_mult_4.D1[0];
	C[3] = ws->karat_mult_4.middle1 ^ ws->karat_mult_4.D0[1] ^
	       ws->karat_mult_4.D1[1];
	C[4] = ws->karat_mult_4.middle0 ^ ws->karat_mult_4.D1[2] ^
	       ws->karat_mult_4.D2[2];
	C[5] = ws->karat_mult_4.middle1 ^ ws->karat_mult_4.D1[3] ^
	       ws->karat_mult_4.D2[3];
	C[6] = ws->karat_mult_4.D2[2];
	C[7] = ws->karat_mult_4.D2[3];
}

/**
 * @brief Compute C(x) = A(x)*B(x) 
 *
 * This function computes A(x)*B(x) using Karatsuba
 * A(x) and B(x) are stored in 256-bit registers
 * @param[out] C Pointer to the result
 * @param[in] A Pointer to the polynomial A(x)
 * @param[in] B Pointer to the polynomial B(x)
 */
static inline void karat_mult_8(__m256i *C, const __m256i *A, const __m256i *B,
				struct vect_mul_ws *ws)
{
	karat_mult_4(ws->karat_mult_8.D0, A, B, ws);
	karat_mult_4(ws->karat_mult_8.D2, A + 4, B + 4, ws);
	for (size_t i = 0; i < 4; i++) {
		size_t is = i + 4;
		ws->karat_mult_8.SAA[i] = A[i] ^ A[is];
		ws->karat_mult_8.SBB[i] = B[i] ^ B[is];
	}

	karat_mult_4(ws->karat_mult_8.D1, ws->karat_mult_8.SAA,
		     ws->karat_mult_8.SBB, ws);

	for (size_t i = 0; i < 4; i++) {
		size_t is = i + 4;
		size_t is2 = is + 4;
		size_t is3 = is2 + 4;

		ws->karat_mult_8.middle = _mm256_xor_si256(
			ws->karat_mult_8.D0[is], ws->karat_mult_8.D2[i]);

		C[i] = ws->karat_mult_8.D0[i];
		C[is] = ws->karat_mult_8.middle ^ ws->karat_mult_8.D0[i] ^
			ws->karat_mult_8.D1[i];
		C[is2] = ws->karat_mult_8.middle ^ ws->karat_mult_8.D1[is] ^
			 ws->karat_mult_8.D2[is];
		C[is3] = ws->karat_mult_8.D2[is];
	}
}

/**
 * @brief Compute C(x) = A(x)*B(x) 
 *
 * This function computes A(x)*B(x) using Karatsuba
 * A(x) and B(x) are stored in 256-bit registers
 * @param[out] C Pointer to the result
 * @param[in] A Pointer to the polynomial A(x)
 * @param[in] B Pointer to the polynomial B(x)
 */
static inline void __maybe_unused karat_mult_16(__m256i *C, const __m256i *A,
						const __m256i *B,
						struct vect_mul_ws *ws)
{
	karat_mult_8(ws->karat_mult_16.D0, A, B, ws);
	karat_mult_8(ws->karat_mult_16.D2, A + 8, B + 8, ws);

	for (size_t i = 0; i < 8; i++) {
		size_t is = i + 8;
		ws->karat_mult_16.SAA[i] = A[i] ^ A[is];
		ws->karat_mult_16.SBB[i] = B[i] ^ B[is];
	}

	karat_mult_8(ws->karat_mult_16.D1, ws->karat_mult_16.SAA,
		     ws->karat_mult_16.SBB, ws);

	for (size_t i = 0; i < 8; i++) {
		size_t is = i + 8;
		size_t is2 = is + 8;
		size_t is3 = is2 + 8;

		ws->karat_mult_16.middle = _mm256_xor_si256(
			ws->karat_mult_16.D0[is], ws->karat_mult_16.D2[i]);

		C[i] = ws->karat_mult_16.D0[i];
		C[is] = ws->karat_mult_16.middle ^ ws->karat_mult_16.D0[i] ^
			ws->karat_mult_16.D1[i];
		C[is2] = ws->karat_mult_16.middle ^ ws->karat_mult_16.D1[is] ^
			 ws->karat_mult_16.D2[is];
		C[is3] = ws->karat_mult_16.D2[is];
	}
}

/**
 * @brief Compute C(x) = A(x)*B(x) 
 *
 * This function computes A(x)*B(x) using Karatsuba
 * A(x) and B(x) are stored in 256-bit registers
 * @param[out] C Pointer to the result
 * @param[in] A Pointer to the polynomial A(x)
 * @param[in] B Pointer to the polynomial B(x)
 */
#if (LC_HQC_TYPE == 128) || (LC_HQC_TYPE == 192)
static inline void karat_mult_3(__m256i *Out, __m256i *A, __m256i *B,
				struct vect_mul_ws *ws)
{
	__m256i *a0, *b0, *a1, *b1, *a2, *b2;

	a0 = A;
	a1 = A + LC_HQC_T_3W_256;
	a2 = A + (LC_HQC_T_3W_256 << 1);

	b0 = B;
	b1 = B + LC_HQC_T_3W_256;
	b2 = B + (LC_HQC_T_3W_256 << 1);

	for (size_t i = 0; i < LC_HQC_T_3W_256; i++) {
		ws->karat_mult_3.aa01[i] = a0[i] ^ a1[i];
		ws->karat_mult_3.bb01[i] = b0[i] ^ b1[i];

		ws->karat_mult_3.aa12[i] = a2[i] ^ a1[i];
		ws->karat_mult_3.bb12[i] = b2[i] ^ b1[i];

		ws->karat_mult_3.aa02[i] = a0[i] ^ a2[i];
		ws->karat_mult_3.bb02[i] = b0[i] ^ b2[i];
	}

#if (LC_HQC_TYPE == 128)
	karat_mult_8(ws->karat_mult_3.D0, a0, b0, ws);
	karat_mult_8(ws->karat_mult_3.D1, a1, b1, ws);
	karat_mult_8(ws->karat_mult_3.D2, a2, b2, ws);

	karat_mult_8(ws->karat_mult_3.D3, ws->karat_mult_3.aa01,
		     ws->karat_mult_3.bb01, ws);
	karat_mult_8(ws->karat_mult_3.D4, ws->karat_mult_3.aa02,
		     ws->karat_mult_3.bb02, ws);
	karat_mult_8(ws->karat_mult_3.D5, ws->karat_mult_3.aa12,
		     ws->karat_mult_3.bb12, ws);
#elif (LC_HQC_TYPE == 192)
	karat_mult_16(ws->karat_mult_3.D0, a0, b0, ws);
	karat_mult_16(ws->karat_mult_3.D1, a1, b1, ws);
	karat_mult_16(ws->karat_mult_3.D2, a2, b2, ws);

	karat_mult_16(ws->karat_mult_3.D3, ws->karat_mult_3.aa01,
		      ws->karat_mult_3.bb01, ws);
	karat_mult_16(ws->karat_mult_3.D4, ws->karat_mult_3.aa02,
		      ws->karat_mult_3.bb02, ws);
	karat_mult_16(ws->karat_mult_3.D5, ws->karat_mult_3.aa12,
		      ws->karat_mult_3.bb12, ws);
#endif

	for (size_t i = 0; i < LC_HQC_T_3W_256; i++) {
		size_t j = i + LC_HQC_T_3W_256;

		ws->karat_mult_3.middle0 = ws->karat_mult_3.D0[i] ^
					   ws->karat_mult_3.D1[i] ^
					   ws->karat_mult_3.D0[j];
		ws->karat_mult_3.ro256[i] = ws->karat_mult_3.D0[i];
		ws->karat_mult_3.ro256[j] =
			ws->karat_mult_3.D3[i] ^ ws->karat_mult_3.middle0;
		ws->karat_mult_3.ro256[j + LC_HQC_T_3W_256] =
			ws->karat_mult_3.D4[i] ^ ws->karat_mult_3.D2[i] ^
			ws->karat_mult_3.D3[j] ^ ws->karat_mult_3.D1[j] ^
			ws->karat_mult_3.middle0;
		ws->karat_mult_3.middle0 = ws->karat_mult_3.D1[j] ^
					   ws->karat_mult_3.D2[i] ^
					   ws->karat_mult_3.D2[j];
		ws->karat_mult_3.ro256[j + (LC_HQC_T_3W_256 << 1)] =
			ws->karat_mult_3.D5[i] ^ ws->karat_mult_3.D4[j] ^
			ws->karat_mult_3.D0[j] ^ ws->karat_mult_3.D1[i] ^
			ws->karat_mult_3.middle0;
		ws->karat_mult_3.ro256[i + (LC_HQC_T_3W_256 << 2)] =
			ws->karat_mult_3.D5[j] ^ ws->karat_mult_3.middle0;
		ws->karat_mult_3.ro256[j + (LC_HQC_T_3W_256 << 2)] =
			ws->karat_mult_3.D2[j];
	}

	for (size_t i = 0; i < LC_HQC_T2REC_3W_256; i++)
		Out[i] = ws->karat_mult_3.ro256[i];
}

#elif (LC_HQC_TYPE == 256)

static inline void karat_mult_5(__m256i *Out, const __m256i *A,
				const __m256i *B, struct vect_mul_ws *ws)
{
	const __m256i *a0, *b0, *a1, *b1, *a2, *b2, *a3, *b3, *a4, *b4;

	a0 = A;
	a1 = a0 + LC_HQC_T_5W_256;
	a2 = a1 + LC_HQC_T_5W_256;
	a3 = a2 + LC_HQC_T_5W_256;
	a4 = a3 + LC_HQC_T_5W_256;
	b0 = B;
	b1 = b0 + LC_HQC_T_5W_256;
	b2 = b1 + LC_HQC_T_5W_256;
	b3 = b2 + LC_HQC_T_5W_256;
	b4 = b3 + LC_HQC_T_5W_256;

	for (size_t i = 0; i < LC_HQC_T_5W_256; i++) {
		ws->karat_mult_5.aa01[i] = a0[i] ^ a1[i];
		ws->karat_mult_5.bb01[i] = b0[i] ^ b1[i];

		ws->karat_mult_5.aa02[i] = a0[i] ^ a2[i];
		ws->karat_mult_5.bb02[i] = b0[i] ^ b2[i];

		ws->karat_mult_5.aa03[i] = a0[i] ^ a3[i];
		ws->karat_mult_5.bb03[i] = b0[i] ^ b3[i];

		ws->karat_mult_5.aa04[i] = a0[i] ^ a4[i];
		ws->karat_mult_5.bb04[i] = b0[i] ^ b4[i];

		ws->karat_mult_5.aa12[i] = a2[i] ^ a1[i];
		ws->karat_mult_5.bb12[i] = b2[i] ^ b1[i];

		ws->karat_mult_5.aa13[i] = a3[i] ^ a1[i];
		ws->karat_mult_5.bb13[i] = b3[i] ^ b1[i];

		ws->karat_mult_5.aa14[i] = a4[i] ^ a1[i];
		ws->karat_mult_5.bb14[i] = b4[i] ^ b1[i];

		ws->karat_mult_5.aa23[i] = a2[i] ^ a3[i];
		ws->karat_mult_5.bb23[i] = b2[i] ^ b3[i];

		ws->karat_mult_5.aa24[i] = a2[i] ^ a4[i];
		ws->karat_mult_5.bb24[i] = b2[i] ^ b4[i];

		ws->karat_mult_5.aa34[i] = a3[i] ^ a4[i];
		ws->karat_mult_5.bb34[i] = b3[i] ^ b4[i];
	}

	karat_mult_16(ws->karat_mult_5.D0, a0, b0, ws);
	karat_mult_16(ws->karat_mult_5.D1, a1, b1, ws);
	karat_mult_16(ws->karat_mult_5.D2, a2, b2, ws);
	karat_mult_16(ws->karat_mult_5.D3, a3, b3, ws);
	karat_mult_16(ws->karat_mult_5.D4, a4, b4, ws);

	karat_mult_16(ws->karat_mult_5.D01, ws->karat_mult_5.aa01,
		      ws->karat_mult_5.bb01, ws);
	karat_mult_16(ws->karat_mult_5.D02, ws->karat_mult_5.aa02,
		      ws->karat_mult_5.bb02, ws);
	karat_mult_16(ws->karat_mult_5.D03, ws->karat_mult_5.aa03,
		      ws->karat_mult_5.bb03, ws);
	karat_mult_16(ws->karat_mult_5.D04, ws->karat_mult_5.aa04,
		      ws->karat_mult_5.bb04, ws);

	karat_mult_16(ws->karat_mult_5.D12, ws->karat_mult_5.aa12,
		      ws->karat_mult_5.bb12, ws);
	karat_mult_16(ws->karat_mult_5.D13, ws->karat_mult_5.aa13,
		      ws->karat_mult_5.bb13, ws);
	karat_mult_16(ws->karat_mult_5.D14, ws->karat_mult_5.aa14,
		      ws->karat_mult_5.bb14, ws);

	karat_mult_16(ws->karat_mult_5.D23, ws->karat_mult_5.aa23,
		      ws->karat_mult_5.bb23, ws);
	karat_mult_16(ws->karat_mult_5.D24, ws->karat_mult_5.aa24,
		      ws->karat_mult_5.bb24, ws);

	karat_mult_16(ws->karat_mult_5.D34, ws->karat_mult_5.aa34,
		      ws->karat_mult_5.bb34, ws);

	for (size_t i = 0; i < LC_HQC_T_5W_256; i++) {
		ws->karat_mult_5.ro256[i] = ws->karat_mult_5.D0[i];
		ws->karat_mult_5.ro256[i + LC_HQC_T_5W_256] =
			ws->karat_mult_5.D0[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D01[i] ^ ws->karat_mult_5.D0[i] ^
			ws->karat_mult_5.D1[i];
		ws->karat_mult_5.ro256[i + 2 * LC_HQC_T_5W_256] =
			ws->karat_mult_5.D1[i] ^ ws->karat_mult_5.D02[i] ^
			ws->karat_mult_5.D0[i] ^ ws->karat_mult_5.D2[i] ^
			ws->karat_mult_5.D01[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D0[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D1[i + LC_HQC_T_5W_256];
		ws->karat_mult_5.ro256[i + 3 * LC_HQC_T_5W_256] =
			ws->karat_mult_5.D1[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D03[i] ^ ws->karat_mult_5.D0[i] ^
			ws->karat_mult_5.D3[i] ^ ws->karat_mult_5.D12[i] ^
			ws->karat_mult_5.D1[i] ^ ws->karat_mult_5.D2[i] ^
			ws->karat_mult_5.D02[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D0[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D2[i + LC_HQC_T_5W_256];
		ws->karat_mult_5.ro256[i + 4 * LC_HQC_T_5W_256] =
			ws->karat_mult_5.D2[i] ^ ws->karat_mult_5.D04[i] ^
			ws->karat_mult_5.D0[i] ^ ws->karat_mult_5.D4[i] ^
			ws->karat_mult_5.D13[i] ^ ws->karat_mult_5.D1[i] ^
			ws->karat_mult_5.D3[i] ^
			ws->karat_mult_5.D03[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D0[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D3[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D12[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D1[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D2[i + LC_HQC_T_5W_256];
		ws->karat_mult_5.ro256[i + 5 * LC_HQC_T_5W_256] =
			ws->karat_mult_5.D2[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D14[i] ^ ws->karat_mult_5.D1[i] ^
			ws->karat_mult_5.D4[i] ^ ws->karat_mult_5.D23[i] ^
			ws->karat_mult_5.D2[i] ^ ws->karat_mult_5.D3[i] ^
			ws->karat_mult_5.D04[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D0[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D4[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D13[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D1[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D3[i + LC_HQC_T_5W_256];
		ws->karat_mult_5.ro256[i + 6 * LC_HQC_T_5W_256] =
			ws->karat_mult_5.D3[i] ^ ws->karat_mult_5.D24[i] ^
			ws->karat_mult_5.D2[i] ^ ws->karat_mult_5.D4[i] ^
			ws->karat_mult_5.D14[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D1[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D4[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D23[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D2[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D3[i + LC_HQC_T_5W_256];
		ws->karat_mult_5.ro256[i + 7 * LC_HQC_T_5W_256] =
			ws->karat_mult_5.D3[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D34[i] ^ ws->karat_mult_5.D3[i] ^
			ws->karat_mult_5.D4[i] ^
			ws->karat_mult_5.D24[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D2[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D4[i + LC_HQC_T_5W_256];
		ws->karat_mult_5.ro256[i + 8 * LC_HQC_T_5W_256] =
			ws->karat_mult_5.D4[i] ^
			ws->karat_mult_5.D34[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D3[i + LC_HQC_T_5W_256] ^
			ws->karat_mult_5.D4[i + LC_HQC_T_5W_256];
		ws->karat_mult_5.ro256[i + 9 * LC_HQC_T_5W_256] =
			ws->karat_mult_5.D4[i + LC_HQC_T_5W_256];
	}

	for (size_t i = 0; i < LC_HQC_T_5W_256 * 10; i++)
		Out[i] = ws->karat_mult_5.ro256[i];
}
#endif

/**
 * @brief Compute B(x) = A(x)/(x+1) 
 *
 * This function computes A(x)/(x+1) using a Quercia like algorithm
 * @param[out] out Pointer to the result
 * @param[in] in Pointer to the polynomial A(x)
 * @param[in] size used to define the number of coeeficients of A
 */
#if (LC_HQC_TYPE == 128) || (LC_HQC_TYPE == 192)

static inline void divide_by_x_plus_one_256(__m256i *out, __m256i *in,
					    size_t size)
{
	uint64_t *A = (uint64_t *)in;
	uint64_t *B = (uint64_t *)out;

	B[0] = A[0];
	for (size_t i = 1; i < 2 * (size << 2); i++)
		B[i] = B[i - 1] ^ A[i];
}

#elif (LC_HQC_TYPE == 256)

static inline void divide_by_x_plus_one_256(__m256i *in, __m256i *out,
					    size_t size)
{
	out[0] = in[0];
	for (size_t i = 1; i < 2 * (size + 2); i++)
		out[i] = out[i - 1] ^ in[i];
}

#endif

/**
 * @brief Compute C(x) = A(x)*B(x) using TOOM3Mult with recursive call 
 *
 * This function computes A(x)*B(x) using recursive TOOM-COOK3 Multiplication
 * @param[out] Out Pointer to the result
 * @param[in] A Pointer to the polynomial A(x)
 * @param[in] B Pointer to the polynomial B(x)
 */
#if (LC_HQC_TYPE == 128) || (LC_HQC_TYPE == 192)
static inline void toom_3_mult(__m256i *Out, const __m256i *A256,
			       const __m256i *B256, struct vect_mul_ws *ws)
{
	const __m256i zero = (__m256i){ 0ul, 0ul, 0ul, 0ul };

	uint64_t *A = (uint64_t *)A256;
	uint64_t *B = (uint64_t *)B256;

	size_t T2 = LC_HQC_T_TM3R_3W_64 << 1;
	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256 - 1; i++) {
		size_t i4 = i << 2;
		size_t i42 = i4 - 2;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		ws->toom_3_mult.U0[i] =
			_mm256_lddqu_si256((__m256i const *)(&A[i4]));
		ws->toom_3_mult.V0[i] =
			_mm256_lddqu_si256((__m256i const *)(&B[i4]));
		ws->toom_3_mult.U1[i] = _mm256_lddqu_si256(
			(__m256i const *)(&A[i42 + LC_HQC_T_TM3R_3W_64]));
		ws->toom_3_mult.V1[i] = _mm256_lddqu_si256(
			(__m256i const *)(&B[i42 + LC_HQC_T_TM3R_3W_64]));
		ws->toom_3_mult.U2[i] =
			_mm256_lddqu_si256((__m256i const *)(&A[i4 + T2 - 4]));
		ws->toom_3_mult.V2[i] =
			_mm256_lddqu_si256((__m256i const *)(&B[i4 + T2 - 4]));
#pragma GCC diagnostic pop
	}

	for (size_t i = LC_HQC_T_TM3R_3W_256 - 1; i < LC_HQC_T_TM3R_3W_256;
	     i++) {
		size_t i4 = i << 2;
		size_t i41 = i4 + 1;

		ws->toom_3_mult.U0[i] =
			(__m256i){ (long long)A[i4], (long long)A[i41], 0x0ul,
				   0x0ul };
		ws->toom_3_mult.V0[i] =
			(__m256i){ (long long)B[i4], (long long)B[i41], 0x0ul,
				   0x0ul };

		ws->toom_3_mult.U1[i] =
			(__m256i){ (long long)A[i4 + LC_HQC_T_TM3R_3W_64 - 2],
				   (long long)A[i41 + LC_HQC_T_TM3R_3W_64 - 2],
				   0x0ul, 0x0ul };
		ws->toom_3_mult.V1[i] =
			(__m256i){ (long long)B[i4 + LC_HQC_T_TM3R_3W_64 - 2],
				   (long long)B[i41 + LC_HQC_T_TM3R_3W_64 - 2],
				   0x0ul, 0x0ul };

		ws->toom_3_mult.U2[i] =
			(__m256i){ (long long)A[i4 - 4 + T2],
				   (long long)A[i4 - 3 + T2], 0x0ul, 0x0ul };
		ws->toom_3_mult.V2[i] =
			(__m256i){ (long long)B[i4 - 4 + T2],
				   (long long)B[i4 - 3 + T2], 0x0ul, 0x0ul };
	}

	// EVALUATION PHASE : x= X^64
	// P(X): P0=(0); P1=(1); P2=(x); P3=(1+x); P4=(\infty)
	// Evaluation: 5*2 add, 2*2 shift; 5 mul (n)
	//W3 = U2 + U1 + U0 ; W2 = V2 + V1 + V0

	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256; i++) {
		ws->toom_3_mult.W3[i] = ws->toom_3_mult.U0[i] ^
					ws->toom_3_mult.U1[i] ^
					ws->toom_3_mult.U2[i];
		ws->toom_3_mult.W2[i] = ws->toom_3_mult.V0[i] ^
					ws->toom_3_mult.V1[i] ^
					ws->toom_3_mult.V2[i];
	}

	//W1 = W2 * W3
	karat_mult_3(ws->toom_3_mult.W1, ws->toom_3_mult.W2, ws->toom_3_mult.W3,
		     ws);

	//W0 =(U1 + U2*x)*x ; W4 =(V1 + V2*x)*x (SIZE = T_TM3R_3W_256 !)
	uint64_t *U1_64 = ((uint64_t *)ws->toom_3_mult.U1);
	uint64_t *U2_64 = ((uint64_t *)ws->toom_3_mult.U2);

	uint64_t *V1_64 = ((uint64_t *)ws->toom_3_mult.V1);
	uint64_t *V2_64 = ((uint64_t *)ws->toom_3_mult.V2);

	ws->toom_3_mult.W0[0] = (__m256i){ 0ul, (long long)U1_64[0],
					   (long long)(U1_64[1] ^ U2_64[0]),
					   (long long)(U1_64[2] ^ U2_64[1]) };
	ws->toom_3_mult.W4[0] = (__m256i){ 0ul, (long long)V1_64[0],
					   (long long)(V1_64[1] ^ V2_64[0]),
					   (long long)(V1_64[2] ^ V2_64[1]) };

	U1_64 = ((uint64_t *)ws->toom_3_mult.U1) + 3;
	U2_64 = ((uint64_t *)ws->toom_3_mult.U2) + 2;

	V1_64 = ((uint64_t *)ws->toom_3_mult.V1) + 3;
	V2_64 = ((uint64_t *)ws->toom_3_mult.V2) + 2;

	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256 - 1; i++) {
		size_t i4 = i << 2;
		size_t i1 = i + 1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		ws->toom_3_mult.W0[i1] =
			_mm256_lddqu_si256((__m256i const *)(&U1_64[i4]));
		ws->toom_3_mult.W0[i1] ^=
			_mm256_lddqu_si256((__m256i const *)(&U2_64[i4]));

		ws->toom_3_mult.W4[i1] =
			_mm256_lddqu_si256((__m256i const *)(&V1_64[i4]));
		ws->toom_3_mult.W4[i1] ^=
			_mm256_lddqu_si256((__m256i const *)(&V2_64[i4]));
#pragma GCC diagnostic pop
	}

	//W3 = W3 + W0; W2 = W2 + W4
	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256; i++) {
		ws->toom_3_mult.W3[i] ^= ws->toom_3_mult.W0[i];
		ws->toom_3_mult.W2[i] ^= ws->toom_3_mult.W4[i];
	}

	//W0 = W0 + U0; W4 = W4 + V0
	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256; i++) {
		ws->toom_3_mult.W0[i] ^= ws->toom_3_mult.U0[i];
		ws->toom_3_mult.W4[i] ^= ws->toom_3_mult.V0[i];
	}

	//W3 = W3 * W2; W2 = W0 * W4
	karat_mult_3(ws->toom_3_mult.tmp, ws->toom_3_mult.W3,
		     ws->toom_3_mult.W2, ws);

	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256); i++) {
		ws->toom_3_mult.W3[i] = ws->toom_3_mult.tmp[i];
	}

	karat_mult_3(ws->toom_3_mult.W2, ws->toom_3_mult.W0, ws->toom_3_mult.W4,
		     ws);

	//W4 = U2 * V2; W0 = U0 * V0
	karat_mult_3(ws->toom_3_mult.W4, ws->toom_3_mult.U2, ws->toom_3_mult.V2,
		     ws);
	karat_mult_3(ws->toom_3_mult.W0, ws->toom_3_mult.U0, ws->toom_3_mult.V0,
		     ws);

	//INTERPOLATION PHASE
	//W3 = W3 + W2
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256); i++) {
		ws->toom_3_mult.W3[i] ^= ws->toom_3_mult.W2[i];
	}

	//W1 = W1 + W0
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256); i++) {
		ws->toom_3_mult.W1[i] ^= ws->toom_3_mult.W0[i];
	}

	//W2 =(W2 + W0)/x -> x = X^64
	U1_64 = ((uint64_t *)ws->toom_3_mult.W2) + 1;
	U2_64 = ((uint64_t *)ws->toom_3_mult.W0) + 1;

	for (size_t i = 0; i < (LC_HQC_T_TM3R_3W_256 << 1); i++) {
		size_t i4 = i << 2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		ws->toom_3_mult.W2[i] =
			_mm256_lddqu_si256((__m256i const *)(&U1_64[i4]));
		ws->toom_3_mult.W2[i] ^=
			_mm256_lddqu_si256((__m256i const *)(&U2_64[i4]));
#pragma GCC diagnostic pop
	}

	//W2 =(W2 + W3 + W4*(x^3+1))/(x+1)
	U1_64 = ((uint64_t *)ws->toom_3_mult.W4);
	ws->toom_3_mult.tmp[0] =
		ws->toom_3_mult.W2[0] ^ ws->toom_3_mult.W3[0] ^
		ws->toom_3_mult.W4[0] ^
		(__m256i) { 0x0ul, 0x0ul, 0x0ul, (long long)U1_64[0] };
	U1_64++;

	for (size_t i = 1; i < (LC_HQC_T_TM3R_3W_256 << 1) - 1; i++) {
		size_t i4 = i << 2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		ws->toom_3_mult.tmp[i] =
			ws->toom_3_mult.W2[i] ^ ws->toom_3_mult.W3[i] ^
			ws->toom_3_mult.W4[i] ^
			_mm256_lddqu_si256((__m256i const *)(&U1_64[i4 - 4]));
#pragma GCC diagnostic pop
	}

	divide_by_x_plus_one_256(ws->toom_3_mult.W2, ws->toom_3_mult.tmp,
				 LC_HQC_T_TM3R_3W_256);
	ws->toom_3_mult.W2[2 * (LC_HQC_T_TM3R_3W_256)-1] = zero;

	//W3 =(W3 + W1)/(x*(x+1))
	U1_64 = ((uint64_t *)ws->toom_3_mult.W3) + 1;
	U2_64 = ((uint64_t *)ws->toom_3_mult.W1) + 1;
	for (size_t i = 0; i < (LC_HQC_T_TM3R_3W_256 << 1) - 1; i++) {
		size_t i4 = i << 2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		ws->toom_3_mult.tmp[i] =
			_mm256_lddqu_si256((__m256i const *)(&U1_64[i4])) ^
			_mm256_lddqu_si256((__m256i const *)(&U2_64[i4]));
#pragma GCC diagnostic pop
	}

	divide_by_x_plus_one_256(ws->toom_3_mult.W3, ws->toom_3_mult.tmp,
				 LC_HQC_T_TM3R_3W_256);
	ws->toom_3_mult.W3[2 * (LC_HQC_T_TM3R_3W_256)-1] = zero;

	//W1 = W1 + W4 + W2
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256); i++) {
		ws->toom_3_mult.W1[i] ^=
			ws->toom_3_mult.W2[i] ^ ws->toom_3_mult.W4[i];
	}

	//W2 = W2 + W3
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256); i++) {
		ws->toom_3_mult.W2[i] ^= ws->toom_3_mult.W3[i];
	}

	// Recomposition
	//W  = W0+ W1*x+ W2*x^2+ W3*x^3 + W4*x^4
	//Attention : W0, W1, W4 of size 2*T_TM3R_3W_256, W2 and W3 of size 2*(T_TM3R_3W_256)
	for (size_t i = 0; i < (LC_HQC_T_TM3R_3W_256 << 1) - 1; i++) {
		ws->toom_3_mult.ro256[i] = ws->toom_3_mult.W0[i];
		ws->toom_3_mult.ro256[i + 2 * LC_HQC_T_TM3R_3W_256 - 1] =
			ws->toom_3_mult.W2[i];
		ws->toom_3_mult.ro256[i + 4 * LC_HQC_T_TM3R_3W_256 - 2] =
			ws->toom_3_mult.W4[i];
	}

	ws->toom_3_mult.ro256[(LC_HQC_T_TM3R_3W_256 << 1) - 1] =
		ws->toom_3_mult.W0[(LC_HQC_T_TM3R_3W_256 << 1) - 1] ^
		ws->toom_3_mult.W2[0];
	ws->toom_3_mult.ro256[(LC_HQC_T_TM3R_3W_256 << 2) - 2] =
		ws->toom_3_mult.W2[(LC_HQC_T_TM3R_3W_256 << 1) - 1] ^
		ws->toom_3_mult.W4[0];
	ws->toom_3_mult.ro256[(LC_HQC_T_TM3R_3W_256 * 6) - 3] =
		ws->toom_3_mult.W4[(LC_HQC_T_TM3R_3W_256 << 1) - 1];

	U1_64 = ((uint64_t *)&ws->toom_3_mult.ro256[LC_HQC_T_TM3R_3W_256]) - 2;
	U2_64 = ((uint64_t *)&ws->toom_3_mult
			 .ro256[3 * LC_HQC_T_TM3R_3W_256 - 1]) -
		2;

	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256 << 1; i++) {
		size_t i4 = i << 2;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
		__m256i aux = _mm256_lddqu_si256((__m256i *)(&U1_64[i4])) ^
			      ws->toom_3_mult.W1[i];
		_mm256_storeu_si256((__m256i *)(&U1_64[i4]), aux);
		aux = _mm256_lddqu_si256((__m256i *)(&U2_64[i4])) ^
		      ws->toom_3_mult.W3[i];
		_mm256_storeu_si256((__m256i *)(&U2_64[i4]), aux);
#pragma GCC diagnostic pop
	}

	for (size_t i = 0; i < 6 * LC_HQC_T_TM3R_3W_256 - 2; i++) {
		_mm256_storeu_si256(((__m256i *)Out) + i,
				    ws->toom_3_mult.ro256[i]);
	}
}

#elif (LC_HQC_TYPE == 256)

static void toom_3_mult(__m256i *Out, const __m256i *A, const __m256i *B,
			struct vect_mul_ws *ws)
{
	LC_FIPS_RODATA_SECTION
	static const __m256i zero = { 0ul, 0ul, 0ul, 0ul };
	size_t T2 = LC_HQC_T_TM3R_3W_256 << 1;

	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256; i++) {
		ws->toom_3_mult.U0[i] = A[i];
		ws->toom_3_mult.V0[i] = B[i];
		ws->toom_3_mult.U1[i] = A[i + LC_HQC_T_TM3R_3W_256];
		ws->toom_3_mult.V1[i] = B[i + LC_HQC_T_TM3R_3W_256];
		ws->toom_3_mult.U2[i] = A[i + T2];
		ws->toom_3_mult.V2[i] = B[i + T2];
	}

	for (size_t i = LC_HQC_T_TM3R_3W_256; i < LC_HQC_T_TM3R_3W_256 + 2;
	     i++) {
		ws->toom_3_mult.U0[i] = zero;
		ws->toom_3_mult.V0[i] = zero;
		ws->toom_3_mult.U1[i] = zero;
		ws->toom_3_mult.V1[i] = zero;
		ws->toom_3_mult.U2[i] = zero;
		ws->toom_3_mult.V2[i] = zero;
	}

	// EVALUATION PHASE : x= X^256
	// P(X): P0=(0); P1=(1); P2=(x); P3=(1+x); P4=(\infty)
	// Evaluation: 5*2 add, 2*2 shift; 5 mul (n)
	//W3 = U2 + U1 + U0 ; W2 = V2 + V1 + V0

	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256; i++) {
		ws->toom_3_mult.W3[i] = ws->toom_3_mult.U0[i] ^
					ws->toom_3_mult.U1[i] ^
					ws->toom_3_mult.U2[i];
		ws->toom_3_mult.W2[i] = ws->toom_3_mult.V0[i] ^
					ws->toom_3_mult.V1[i] ^
					ws->toom_3_mult.V2[i];
	}

	for (size_t i = LC_HQC_T_TM3R_3W_256; i < LC_HQC_T_TM3R_3W_256 + 2;
	     i++) {
		ws->toom_3_mult.W2[i] = zero;
		ws->toom_3_mult.W3[i] = zero;
	}

	//W1 = W2 * W3
	karat_mult_5(ws->toom_3_mult.W1, ws->toom_3_mult.W2, ws->toom_3_mult.W3,
		     ws);

	//W0 =(U1 + U2*x)*x ; W4 =(V1 + V2*x)*x (SIZE = T_TM3_3W_256 + 2 !)
	ws->toom_3_mult.W0[0] = zero;
	ws->toom_3_mult.W4[0] = zero;

	ws->toom_3_mult.W0[1] = ws->toom_3_mult.U1[0];
	ws->toom_3_mult.W4[1] = ws->toom_3_mult.V1[0];

	for (size_t i = 1; i < LC_HQC_T_TM3R_3W_256 + 1; i++) {
		ws->toom_3_mult.W0[i + 1] =
			ws->toom_3_mult.U1[i] ^ ws->toom_3_mult.U2[i - 1];
		ws->toom_3_mult.W4[i + 1] =
			ws->toom_3_mult.V1[i] ^ ws->toom_3_mult.V2[i - 1];
	}

	ws->toom_3_mult.W0[LC_HQC_T_TM3R_3W_256 + 1] =
		ws->toom_3_mult.U2[LC_HQC_T_TM3R_3W_256 - 1];
	ws->toom_3_mult.W4[LC_HQC_T_TM3R_3W_256 + 1] =
		ws->toom_3_mult.V2[LC_HQC_T_TM3R_3W_256 - 1];

	//W3 = W3 + W0      ; W2 = W2 + W4
	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256 + 2; i++) {
		ws->toom_3_mult.W3[i] ^= ws->toom_3_mult.W0[i];
		ws->toom_3_mult.W2[i] ^= ws->toom_3_mult.W4[i];
	}

	//W0 = W0 + U0      ; W4 = W4 + V0
	for (size_t i = 0; i < LC_HQC_T_TM3R_3W_256 + 2; i++) {
		ws->toom_3_mult.W0[i] ^= ws->toom_3_mult.U0[i];
		ws->toom_3_mult.W4[i] ^= ws->toom_3_mult.V0[i];
	}

	//W3 = W3 * W2      ; W2 = W0 * W4
	karat_mult_5(ws->toom_3_mult.tmp, ws->toom_3_mult.W3,
		     ws->toom_3_mult.W2, ws);
	for (int32_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256 + 2); i++) {
		ws->toom_3_mult.W3[i] = ws->toom_3_mult.tmp[i];
	}

	karat_mult_5(ws->toom_3_mult.W2, ws->toom_3_mult.W0, ws->toom_3_mult.W4,
		     ws);

	//W4 = U2 * V2      ; W0 = U0 * V0
	karat_mult_5(ws->toom_3_mult.W4, ws->toom_3_mult.U2, ws->toom_3_mult.V2,
		     ws);
	karat_mult_5(ws->toom_3_mult.W0, ws->toom_3_mult.U0, ws->toom_3_mult.V0,
		     ws);

	//INTERPOLATION PHASE
	//9 add, 1 shift, 1 Smul, 2 Sdiv (2n)
	//W3 = W3 + W2
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256 + 2); i++) {
		ws->toom_3_mult.W3[i] ^= ws->toom_3_mult.W2[i];
	}

	//W1 = W1 + W0
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256); i++) {
		ws->toom_3_mult.W1[i] ^= ws->toom_3_mult.W0[i];
	}

	//W2 =(W2 + W0)/x
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256 + 2) - 1; i++) {
		size_t i1 = i + 1;

		ws->toom_3_mult.W2[i] =
			ws->toom_3_mult.W2[i1] ^ ws->toom_3_mult.W0[i1];
	}

	ws->toom_3_mult.W2[2 * (LC_HQC_T_TM3R_3W_256 + 2) - 1] = zero;

	//W2 =(W2 + W3 + W4*(x^3+1))/(x+1)
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256 + 2); i++) {
		ws->toom_3_mult.tmp[i] = ws->toom_3_mult.W2[i] ^
					 ws->toom_3_mult.W3[i] ^
					 ws->toom_3_mult.W4[i];
	}

	ws->toom_3_mult.tmp[2 * (LC_HQC_T_TM3R_3W_256 + 2)] = zero;
	ws->toom_3_mult.tmp[2 * (LC_HQC_T_TM3R_3W_256 + 2) + 1] = zero;
	ws->toom_3_mult.tmp[2 * (LC_HQC_T_TM3R_3W_256 + 2) + 2] = zero;

	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256); i++) {
		ws->toom_3_mult.tmp[i + 3] ^= ws->toom_3_mult.W4[i];
	}

	divide_by_x_plus_one_256(ws->toom_3_mult.tmp, ws->toom_3_mult.W2,
				 LC_HQC_T_TM3R_3W_256);

	//W3 =(W3 + W1)/(x*(x+1))
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256 + 2) - 1; i++) {
		size_t i1 = i + 1;

		ws->toom_3_mult.tmp[i] =
			ws->toom_3_mult.W3[i1] ^ ws->toom_3_mult.W1[i1];
	}

	ws->toom_3_mult.tmp[2 * (LC_HQC_T_TM3R_3W_256 + 2) - 1] = zero;
	divide_by_x_plus_one_256(ws->toom_3_mult.tmp, ws->toom_3_mult.W3,
				 LC_HQC_T_TM3R_3W_256);

	//W1 = W1 + W4 + W2
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256 + 2); i++) {
		ws->toom_3_mult.W1[i] ^=
			ws->toom_3_mult.W2[i] ^ ws->toom_3_mult.W4[i];
	}

	//W2 = W2 + W3
	for (size_t i = 0; i < 2 * (LC_HQC_T_TM3R_3W_256 + 2); i++) {
		ws->toom_3_mult.W2[i] ^= ws->toom_3_mult.W3[i];
	}

	//Recomposition
	//W  = W0+ W1*x+ W2*x^2+ W3*x^3 + W4*x^4
	//Note that : W0, W1, W4 of size 2*T_TM3_3W_256, W2 and W3 of size 2*(T_TM3_3W_256+2)
	for (int32_t i = 0; i < LC_HQC_T_TM3R_3W_256; i++) {
		ws->toom_3_mult.ro256[i] = ws->toom_3_mult.W0[i];
		ws->toom_3_mult.ro256[i + LC_HQC_T_TM3R_3W_256] =
			ws->toom_3_mult.W0[i + LC_HQC_T_TM3R_3W_256] ^
			ws->toom_3_mult.W1[i];
		ws->toom_3_mult.ro256[i + 2 * LC_HQC_T_TM3R_3W_256] =
			ws->toom_3_mult.W1[i + LC_HQC_T_TM3R_3W_256] ^
			ws->toom_3_mult.W2[i];
		ws->toom_3_mult.ro256[i + 3 * LC_HQC_T_TM3R_3W_256] =
			ws->toom_3_mult.W2[i + LC_HQC_T_TM3R_3W_256] ^
			ws->toom_3_mult.W3[i];
		ws->toom_3_mult.ro256[i + 4 * LC_HQC_T_TM3R_3W_256] =
			ws->toom_3_mult.W3[i + LC_HQC_T_TM3R_3W_256] ^
			ws->toom_3_mult.W4[i];
		ws->toom_3_mult.ro256[i + 5 * LC_HQC_T_TM3R_3W_256] =
			ws->toom_3_mult.W4[i + LC_HQC_T_TM3R_3W_256];
	}

	ws->toom_3_mult.ro256[4 * LC_HQC_T_TM3R_3W_256] ^=
		ws->toom_3_mult.W2[2 * LC_HQC_T_TM3R_3W_256];
	ws->toom_3_mult.ro256[5 * LC_HQC_T_TM3R_3W_256] ^=
		ws->toom_3_mult.W3[2 * LC_HQC_T_TM3R_3W_256];

	ws->toom_3_mult.ro256[1 + 4 * LC_HQC_T_TM3R_3W_256] ^=
		ws->toom_3_mult.W2[1 + 2 * LC_HQC_T_TM3R_3W_256];
	ws->toom_3_mult.ro256[1 + 5 * LC_HQC_T_TM3R_3W_256] ^=
		ws->toom_3_mult.W3[1 + 2 * LC_HQC_T_TM3R_3W_256];

	ws->toom_3_mult.ro256[2 + 4 * LC_HQC_T_TM3R_3W_256] ^=
		ws->toom_3_mult.W2[2 + 2 * LC_HQC_T_TM3R_3W_256];
	ws->toom_3_mult.ro256[2 + 5 * LC_HQC_T_TM3R_3W_256] ^=
		ws->toom_3_mult.W3[2 + 2 * LC_HQC_T_TM3R_3W_256];

	ws->toom_3_mult.ro256[3 + 4 * LC_HQC_T_TM3R_3W_256] ^=
		ws->toom_3_mult.W2[3 + 2 * LC_HQC_T_TM3R_3W_256];
	ws->toom_3_mult.ro256[3 + 5 * LC_HQC_T_TM3R_3W_256] ^=
		ws->toom_3_mult.W3[3 + 2 * LC_HQC_T_TM3R_3W_256];

	uint64_t *ro64 = (uint64_t *)ws->toom_3_mult.ro256;
	uint64_t *Out64 = (uint64_t *)Out;
	for (size_t i = 0; i < LC_HQC_VEC_N_256_SIZE_64 << 1; i++)
		Out64[i] = ro64[i];
}

#endif

/**
 * @brief Multiply two polynomials modulo \f$ X^n - 1\f$.
 *
 * This functions multiplies a dense polynomial <b>a1</b> (of Hamming weight
 * equal to <b>weight</b>) and a dense polynomial <b>a2</b>. The multiplication
 * is done modulo \f$ X^n - 1\f$.
 *
 * @param[out] o Pointer to the result
 * @param[in] a1 Pointer to a polynomial
 * @param[in] a2 Pointer to a polynomial
 */
void vect_mul_avx2(__m256i *o, const __m256i *a1, const __m256i *a2,
		   struct vect_mul_ws *ws)
{
	toom_3_mult(ws->a1_times_a2, a1, a2, ws);
	reduce(o, ws->a1_times_a2);
}
