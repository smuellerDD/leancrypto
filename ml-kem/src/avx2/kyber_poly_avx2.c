/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_internal.h"
#include "ext_headers_x86.h"

#include "kyber_poly_avx2.h"
#include "shake_4x_avx2.h"

void poly_compress(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES],
		   const poly *restrict a);

/**
 * @brief poly_compress
 *
 * Compression and subsequent serialization of a polynomial. The coefficients
 * of the input polynomial are assumed to lie in the invertal [0,q], i.e. the
 * polynomial must be reduced by poly_reduce().
 *
 * @param r pointer to output byte array (of length
 *	    LC_KYBER_POLYCOMPRESSEDBYTES)
 * @param a pointer to input polynomial
 */
#if (LC_KYBER_POLYCOMPRESSEDBYTES == 160)
void poly_compress_avx(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES],
		       const poly *restrict a)
{
	/*
	 * For some unkown reason, this code compiles, but does not work
	 * correctly when compiled with GCC < 13!
	 */
#if defined(LINUX_KERNEL) && defined(__GNUC__) && (__GNUC__ < 13)
	poly_compress(r, a);
#else /* LINUX_KERNEL */

	unsigned int i;
	__m256i f0, f1;
	__m128i t0, t1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	const __m256i v = _mm256_load_si256(&kyber_qdata.vec[_16XV / 16]);
	const __m256i shift1 = _mm256_set1_epi16(1 << 10);
	const __m256i mask = _mm256_set1_epi16(31);
	const __m256i shift2 = _mm256_set1_epi16((32 << 8) + 1);
	const __m256i shift3 = _mm256_set1_epi32((1024 << 16) + 1);
	const __m256i sllvdidx = _mm256_set1_epi64x(12);
	const __m256i shufbidx =
		_mm256_set_epi8(8, -1, -1, -1, -1, -1, 4, 3, 2, 1, 0, -1, 12,
				11, 10, 9, -1, 12, 11, 10, 9, 8, -1, -1, -1, -1,
				-1, 4, 3, 2, 1, 0);
#pragma GCC diagnostic pop

	LC_FPU_ENABLE;
	for (i = 0; i < LC_KYBER_N / 32; i++) {
		f0 = _mm256_load_si256(&a->vec[2 * i + 0]);
		f1 = _mm256_load_si256(&a->vec[2 * i + 1]);
		f0 = _mm256_mulhi_epi16(f0, v);
		f1 = _mm256_mulhi_epi16(f1, v);
		f0 = _mm256_mulhrs_epi16(f0, shift1);
		f1 = _mm256_mulhrs_epi16(f1, shift1);
		f0 = _mm256_and_si256(f0, mask);
		f1 = _mm256_and_si256(f1, mask);
		f0 = _mm256_packus_epi16(f0, f1);
		f0 = _mm256_maddubs_epi16(
			f0,
			shift2); // a0 a1 a2 a3 b0 b1 b2 b3 a4 a5 a6 a7 b4 b5 b6 b7
		f0 = _mm256_madd_epi16(f0, shift3); // a0 a1 b0 b1 a2 a3 b2 b3
		f0 = _mm256_sllv_epi32(f0, sllvdidx);
		f0 = _mm256_srlv_epi64(f0, sllvdidx);
		f0 = _mm256_shuffle_epi8(f0, shufbidx);
		t0 = _mm256_castsi256_si128(f0);
		t1 = _mm256_extracti128_si256(f0, 1);
		t0 = _mm_blendv_epi8(t0, t1, _mm256_castsi256_si128(shufbidx));
		_mm_storeu_si128((__m128i_u *)&r[20 * i + 0], t0);
		memcpy(&r[20 * i + 16], &t1, 4);
	}
	LC_FPU_DISABLE;

#endif /* LINUX_KERNEL */
}

/**
 * @brief poly_decompress
 *
 * De-serialization and subsequent decompression of a polynomial;
 * approximate inverse of poly_compress
 *
 * @param r pointer to output polynomial
 * @param a pointer to input byte array  (of length
 *	    LC_KYBER_POLYCOMPRESSEDBYTES bytes)
 */
void poly_decompress_avx(poly *restrict r,
			 const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES])
{
	unsigned int i;
	__m128i t;
	__m256i f;
	int16_t ti;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	const __m256i q = _mm256_load_si256(&kyber_qdata.vec[_16XQ / 16]);
	const __m256i shufbidx =
		_mm256_set_epi8(9, 9, 9, 8, 8, 8, 8, 7, 7, 6, 6, 6, 6, 5, 5, 5,
				4, 4, 4, 3, 3, 3, 3, 2, 2, 1, 1, 1, 1, 0, 0, 0);
	const __m256i mask =
		_mm256_set_epi16(248, 1984, 62, 496, 3968, 124, 992, 31, 248,
				 1984, 62, 496, 3968, 124, 992, 31);
	const __m256i shift =
		_mm256_set_epi16(128, 16, 512, 64, 8, 256, 32, 1024, 128, 16,
				 512, 64, 8, 256, 32, 1024);
#pragma GCC diagnostic pop

	LC_FPU_ENABLE;
	for (i = 0; i < LC_KYBER_N / 16; i++) {
		t = _mm_loadl_epi64((__m128i_u *)&a[10 * i + 0]);
		memcpy(&ti, &a[10 * i + 8], 2);
		t = _mm_insert_epi16(t, ti, 4);
		f = _mm256_broadcastsi128_si256(t);
		f = _mm256_shuffle_epi8(f, shufbidx);
		f = _mm256_and_si256(f, mask);
		f = _mm256_mullo_epi16(f, shift);
		f = _mm256_mulhrs_epi16(f, q);
		_mm256_store_si256(&r->vec[i], f);
	}
	LC_FPU_DISABLE;
}

#elif (LC_KYBER_POLYCOMPRESSEDBYTES == 128)
void poly_compress_avx(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES],
		       const poly *restrict a)
{
	unsigned int i;
	__m256i f0, f1, f2, f3;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	const __m256i v = _mm256_load_si256(&kyber_qdata.vec[_16XV / 16]);
	const __m256i shift1 = _mm256_set1_epi16(1 << 9);
	const __m256i mask = _mm256_set1_epi16(15);
	const __m256i shift2 = _mm256_set1_epi16((16 << 8) + 1);
	const __m256i permdidx = _mm256_set_epi32(7, 3, 6, 2, 5, 1, 4, 0);
#pragma GCC diagnostic pop

	LC_FPU_ENABLE;
	for (i = 0; i < LC_KYBER_N / 64; i++) {
		f0 = _mm256_load_si256(&a->vec[4 * i + 0]);
		f1 = _mm256_load_si256(&a->vec[4 * i + 1]);
		f2 = _mm256_load_si256(&a->vec[4 * i + 2]);
		f3 = _mm256_load_si256(&a->vec[4 * i + 3]);
		f0 = _mm256_mulhi_epi16(f0, v);
		f1 = _mm256_mulhi_epi16(f1, v);
		f2 = _mm256_mulhi_epi16(f2, v);
		f3 = _mm256_mulhi_epi16(f3, v);
		f0 = _mm256_mulhrs_epi16(f0, shift1);
		f1 = _mm256_mulhrs_epi16(f1, shift1);
		f2 = _mm256_mulhrs_epi16(f2, shift1);
		f3 = _mm256_mulhrs_epi16(f3, shift1);
		f0 = _mm256_and_si256(f0, mask);
		f1 = _mm256_and_si256(f1, mask);
		f2 = _mm256_and_si256(f2, mask);
		f3 = _mm256_and_si256(f3, mask);
		f0 = _mm256_packus_epi16(f0, f1);
		f2 = _mm256_packus_epi16(f2, f3);
		f0 = _mm256_maddubs_epi16(f0, shift2);
		f2 = _mm256_maddubs_epi16(f2, shift2);
		f0 = _mm256_packus_epi16(f0, f2);
		f0 = _mm256_permutevar8x32_epi32(f0, permdidx);
		_mm256_storeu_si256((__m256i_u *)&r[32 * i], f0);
	}
	LC_FPU_DISABLE;
}

void poly_decompress_avx(poly *restrict r,
			 const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES])
{
	unsigned int i;
	__m128i t;
	__m256i f;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	const __m256i q = _mm256_load_si256(&kyber_qdata.vec[_16XQ / 16]);
	const __m256i shufbidx =
		_mm256_set_epi8(7, 7, 7, 7, 6, 6, 6, 6, 5, 5, 5, 5, 4, 4, 4, 4,
				3, 3, 3, 3, 2, 2, 2, 2, 1, 1, 1, 1, 0, 0, 0, 0);
	const __m256i mask = _mm256_set1_epi32(0x00F0000F);
	const __m256i shift = _mm256_set1_epi32((128 << 16) + 2048);
#pragma GCC diagnostic pop

	LC_FPU_ENABLE;
	for (i = 0; i < LC_KYBER_N / 16; i++) {
		t = _mm_loadl_epi64((__m128i_u *)&a[8 * i]);
		f = _mm256_broadcastsi128_si256(t);
		f = _mm256_shuffle_epi8(f, shufbidx);
		f = _mm256_and_si256(f, mask);
		f = _mm256_mullo_epi16(f, shift);
		f = _mm256_mulhrs_epi16(f, q);
		_mm256_store_si256(&r->vec[i], f);
	}
	LC_FPU_DISABLE;
}

#else
#error "Kyber AVX2 support incomplete"
#endif

/**
 * @brief poly_frommsg
 *
 * Convert 32-byte message to polynomial
 *
 * @param r pointer to output polynomial
 * @param msg pointer to input message
 */
void poly_frommsg_avx(poly *restrict r,
		      const uint8_t msg[LC_KYBER_INDCPA_MSGBYTES])
{
#if (LC_KYBER_INDCPA_MSGBYTES != 32)
#error "LC_KYBER_INDCPA_MSGBYTES must be equal to 32!"
#endif
	__m256i f, g0, g1, g2, g3, h0, h1, h2, h3;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	const __m256i shift =
		_mm256_broadcastsi128_si256(_mm_set_epi32(0, 1, 2, 3));
	const __m256i idx = _mm256_broadcastsi128_si256(_mm_set_epi8(
		15, 14, 11, 10, 7, 6, 3, 2, 13, 12, 9, 8, 5, 4, 1, 0));
	const __m256i hqs = _mm256_set1_epi16((LC_KYBER_Q + 1) / 2);
#pragma GCC diagnostic pop

#define FROMMSG64(i)                                                           \
	g3 = _mm256_shuffle_epi32(f, 0x55 * i);                                \
	g3 = _mm256_sllv_epi32(g3, shift);                                     \
	g3 = _mm256_shuffle_epi8(g3, idx);                                     \
	g0 = _mm256_slli_epi16(g3, 12);                                        \
	g1 = _mm256_slli_epi16(g3, 8);                                         \
	g2 = _mm256_slli_epi16(g3, 4);                                         \
	g0 = _mm256_srai_epi16(g0, 15);                                        \
	g1 = _mm256_srai_epi16(g1, 15);                                        \
	g2 = _mm256_srai_epi16(g2, 15);                                        \
	g3 = _mm256_srai_epi16(g3, 15);                                        \
	g0 = _mm256_and_si256(g0, hqs); /* 19 18 17 16  3  2  1  0 */          \
	g1 = _mm256_and_si256(g1, hqs); /* 23 22 21 20  7  6  5  4 */          \
	g2 = _mm256_and_si256(g2, hqs); /* 27 26 25 24 11 10  9  8 */          \
	g3 = _mm256_and_si256(g3, hqs); /* 31 30 29 28 15 14 13 12 */          \
	h0 = _mm256_unpacklo_epi64(g0, g1);                                    \
	h2 = _mm256_unpackhi_epi64(g0, g1);                                    \
	h1 = _mm256_unpacklo_epi64(g2, g3);                                    \
	h3 = _mm256_unpackhi_epi64(g2, g3);                                    \
	g0 = _mm256_permute2x128_si256(h0, h1, 0x20);                          \
	g2 = _mm256_permute2x128_si256(h0, h1, 0x31);                          \
	g1 = _mm256_permute2x128_si256(h2, h3, 0x20);                          \
	g3 = _mm256_permute2x128_si256(h2, h3, 0x31);                          \
	_mm256_store_si256(&r->vec[0 + 2 * i + 0], g0);                        \
	_mm256_store_si256(&r->vec[0 + 2 * i + 1], g1);                        \
	_mm256_store_si256(&r->vec[8 + 2 * i + 0], g2);                        \
	_mm256_store_si256(&r->vec[8 + 2 * i + 1], g3)

	f = _mm256_loadu_si256((__m256i_u *)msg);
	LC_FPU_ENABLE;
	FROMMSG64(0);
	FROMMSG64(1);
	FROMMSG64(2);
	FROMMSG64(3);
	LC_FPU_DISABLE;
}

/**
 * @brief poly_tomsg
 *
 * Convert polynomial to 32-byte message. The coefficients of the input
 * polynomial are assumed to lie in the invertal [0,q], i.e. the polynomial
 * must be reduced by poly_reduce().
 *
 * @param msg pointer to output message
 * @param a pointer to input polynomial
 */
void poly_tomsg_avx(uint8_t msg[LC_KYBER_INDCPA_MSGBYTES],
		    const poly *restrict a)
{
	unsigned int i;
	int small;
	__m256i f0, f1, g0, g1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	/* Due to const, the variables cannot be defined before */
	const __m256i hq = _mm256_set1_epi16((LC_KYBER_Q - 1) / 2);
	const __m256i hhq = _mm256_set1_epi16((LC_KYBER_Q - 1) / 4);
#pragma GCC diagnostic pop

	LC_FPU_ENABLE;
	for (i = 0; i < LC_KYBER_N / 32; i++) {
		f0 = _mm256_load_si256(&a->vec[2 * i + 0]);
		f1 = _mm256_load_si256(&a->vec[2 * i + 1]);
		f0 = _mm256_sub_epi16(hq, f0);
		f1 = _mm256_sub_epi16(hq, f1);
		g0 = _mm256_srai_epi16(f0, 15);
		g1 = _mm256_srai_epi16(f1, 15);
		f0 = _mm256_xor_si256(f0, g0);
		f1 = _mm256_xor_si256(f1, g1);
		f0 = _mm256_sub_epi16(f0, hhq);
		f1 = _mm256_sub_epi16(f1, hhq);
		f0 = _mm256_packs_epi16(f0, f1);
		f0 = _mm256_permute4x64_epi64(f0, 0xD8);
		small = _mm256_movemask_epi8(f0);
		memcpy(&msg[4 * i], &small, 4);
	}
	LC_FPU_DISABLE;
}

void poly_getnoise_eta1_4x(poly *r0, poly *r1, poly *r2, poly *r3,
			   const uint8_t seed[32], uint8_t nonce0,
			   uint8_t nonce1, uint8_t nonce2, uint8_t nonce3,
			   void *ws_buf, void *ws_keccak)
{
	keccakx4_state *state = ws_keccak;
	__m256i f;
#define BUFSIZE (NOISE_NBLOCKS * LC_SHAKE_256_SIZE_BLOCK)
	__m256i *vec0 = (__m256i *)ws_buf;
	__m256i *vec1 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE);
	__m256i *vec2 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 2;
	__m256i *vec3 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 3;
	uint8_t *coeffs0 = (uint8_t *)vec0;
	uint8_t *coeffs1 = (uint8_t *)vec1;
	uint8_t *coeffs2 = (uint8_t *)vec2;
	uint8_t *coeffs3 = (uint8_t *)vec3;
#undef BUFSIZE

	LC_FPU_ENABLE;
	f = _mm256_loadu_si256((__m256i_u *)seed);
	_mm256_store_si256(vec0, f);
	_mm256_store_si256(vec1, f);
	_mm256_store_si256(vec2, f);
	_mm256_store_si256(vec3, f);
	LC_FPU_DISABLE;

	coeffs0[32] = nonce0;
	coeffs1[32] = nonce1;
	coeffs2[32] = nonce2;
	coeffs3[32] = nonce3;

	shake256x4_absorb_once(state, coeffs0, coeffs1, coeffs2, coeffs3, 33);
	shake256x4_squeezeblocks(coeffs0, coeffs1, coeffs2, coeffs3,
				 NOISE_NBLOCKS, state);

	poly_cbd_eta1_avx(r0, vec0);
	poly_cbd_eta1_avx(r1, vec1);
	poly_cbd_eta1_avx(r2, vec2);
	poly_cbd_eta1_avx(r3, vec3);
}

/**
 * @brief kyber_poly_add
 *
 * Add two polynomials. No modular reduction is performed.
 *
 * @param r pointer to output polynomial
 * @param a pointer to first input polynomial
 * @param b pointer to second input polynomial
 */
void kyber_poly_add_avx(poly *r, const poly *a, const poly *b)
{
	unsigned int i;
	__m256i f0, f1;

	LC_FPU_ENABLE;
	for (i = 0; i < LC_KYBER_N / 16; i++) {
		f0 = _mm256_load_si256(&a->vec[i]);
		f1 = _mm256_load_si256(&b->vec[i]);
		f0 = _mm256_add_epi16(f0, f1);
		_mm256_store_si256(&r->vec[i], f0);
	}
	LC_FPU_DISABLE;
}

/**
 * @brief kyber_poly_sub
 *
 * Subtract two polynomials. No modular reduction is performed.
 *
 * @param r pointer to output polynomial
 * @param a pointer to first input polynomial
 * @param b pointer to second input polynomial
 */
void kyber_poly_sub_avx(poly *r, const poly *a, const poly *b)
{
	unsigned int i;
	__m256i f0, f1;

	LC_FPU_ENABLE;
	for (i = 0; i < LC_KYBER_N / 16; i++) {
		f0 = _mm256_load_si256(&a->vec[i]);
		f1 = _mm256_load_si256(&b->vec[i]);
		f0 = _mm256_sub_epi16(f0, f1);
		_mm256_store_si256(&r->vec[i], f0);
	}
	LC_FPU_DISABLE;
}
