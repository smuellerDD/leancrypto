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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include <stdint.h>
#include <immintrin.h>
#include <string.h>

#include "alignment_x86.h"
#include "dilithium_poly_avx2.h"
#include "../dilithium_service_helpers.h"
#include "lc_dilithium.h"
#include "lc_sha3.h"
#include "shake_4x_avx2.h"

#define _mm256_blendv_epi32(a,b,mask)					       \
	_mm256_castps_si256(_mm256_blendv_ps(_mm256_castsi256_ps(a),	       \
	_mm256_castsi256_ps(b),						       \
	_mm256_castsi256_ps(mask)))

/**
 * @brief poly_reduce_avx
 *
 * Inplace reduction of all coefficients of polynomial to representative in
 * [-6283009,6283007]. Assumes input coefficients to be at most 2^31 - 2^22 - 1
 * in absolute value.
 *
 * @param a pointer to input/output polynomial
 */
void poly_reduce_avx(poly *a)
{
	unsigned int i;
	__m256i f, g;
	const __m256i q = _mm256_load_si256(&dilithium_qdata.vec[_8XQ/8]);
	const __m256i off = _mm256_set1_epi32(1<<22);

	for (i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		g = _mm256_add_epi32(f,off);
		g = _mm256_srai_epi32(g,23);
		g = _mm256_mullo_epi32(g,q);
		f = _mm256_sub_epi32(f,g);
		_mm256_store_si256(&a->vec[i],f);
	}
}

/**
 * @brief poly_addq_avx
 *
 * For all coefficients of in/out polynomial add Q if coefficient is negative.
 *
 * @param a pointer to input/output polynomial
 */
void poly_caddq_avx(poly *a)
{
	unsigned int i;
	__m256i f, g;
	const __m256i q = _mm256_load_si256(&dilithium_qdata.vec[_8XQ/8]);
	const __m256i zero = _mm256_setzero_si256();

	for (i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		g = _mm256_blendv_epi32(zero,q,f);
		f = _mm256_add_epi32(f,g);
		_mm256_store_si256(&a->vec[i],f);
	}
}

/**
 * @brief poly_add_avx
 *
 * Add polynomials. No modular reduction is performed.
 *
 * @param c pointer to output polynomial
 * @param a pointer to first summand
 * @param b pointer to second summand
 */
void poly_add_avx(poly *c, const poly *a, const poly *b)
{
	unsigned int i;
	__m256i f, g;

	for (i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		g = _mm256_load_si256(&b->vec[i]);
		f = _mm256_add_epi32(f,g);
		_mm256_store_si256(&c->vec[i],f);
	}
}

/**
 * @brief poly_sub_avx
 *
 * Description: Subtract polynomials. No modular reduction is
 *              performed.
 *
 * Arguments:   - poly *c: pointer to output polynomial
 *              - const poly *a: pointer to first input polynomial
 *              - const poly *b: pointer to second input polynomial to be
 *                               subtraced from first input polynomial
 */
void poly_sub_avx(poly *c, const poly *a, const poly *b)
{
	unsigned int i;
	__m256i f, g;

	for (i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		g = _mm256_load_si256(&b->vec[i]);
		f = _mm256_sub_epi32(f,g);
		_mm256_store_si256(&c->vec[i],f);
	}
}

/**
 * @brief poly_shiftl_avx
 *
 * Multiply polynomial by 2^D without modular reduction. Assumes input
 * coefficients to be less than 2^{31-D} in absolute value.
 *
 * @param a pointer to input/output polynomial
 */
void poly_shiftl_avx(poly *a)
{
	unsigned int i;
	__m256i f;

	for (i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		f = _mm256_slli_epi32(f, LC_DILITHIUM_D);
		_mm256_store_si256(&a->vec[i],f);
	}
}

/**
 * @brief poly_chknorm
 *
 * Check infinity norm of polynomial against given bound. Assumes input
 * polynomial to be reduced by poly_reduce().
 *
 * @param a pointer to polynomial
 * @param B norm bound
 *
 * @return 0 if norm is strictly smaller than B <= (Q-1)/8 and 1 otherwise.
 */
int poly_chknorm_avx(const poly *a, int32_t B)
{
	unsigned int i;
	int r;
	__m256i f, t;
	const __m256i bound = _mm256_set1_epi32(B - 1);

	if (B > (LC_DILITHIUM_Q - 1) / 8)
		return 1;

	t = _mm256_setzero_si256();
	for (i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_load_si256(&a->vec[i]);
		f = _mm256_abs_epi32(f);
		f = _mm256_cmpgt_epi32(f,bound);
		t = _mm256_or_si256(t,f);
	}

	r = 1 - _mm256_testz_si256(t, t);
	return r;
}

void poly_uniform_4x_avx(poly *a0,
			 poly *a1,
			 poly *a2,
			 poly *a3,
			 const uint8_t seed[32],
			 uint16_t nonce0,
			 uint16_t nonce1,
			 uint16_t nonce2,
			 uint16_t nonce3,
			 void *ws_buf,
			 void *ws_keccak)
{
	keccakx4_state *state = ws_keccak;
	__m256i f;
	unsigned int ctr0, ctr1, ctr2, ctr3;
#define BUFSIZE (REJ_UNIFORM_BUFLEN + 8)
	__m256i *vec0 = (__m256i *)ws_buf;
	__m256i *vec1 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE);
	__m256i *vec2 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 2;
	__m256i *vec3 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 3;
	uint8_t *coeffs0 = (uint8_t *)vec0;
	uint8_t *coeffs1 = (uint8_t *)vec1;
	uint8_t *coeffs2 = (uint8_t *)vec2;
	uint8_t *coeffs3 = (uint8_t *)vec3;
#undef BUFSIZE

	f = _mm256_loadu_si256((__m256i_u *)seed);
	_mm256_store_si256(vec0, f);
	_mm256_store_si256(vec1, f);
	_mm256_store_si256(vec2, f);
	_mm256_store_si256(vec3, f);

	coeffs0[LC_DILITHIUM_SEEDBYTES+0] = (uint8_t)(nonce0);
	coeffs0[LC_DILITHIUM_SEEDBYTES+1] = (uint8_t)(nonce0 >> 8);
	coeffs1[LC_DILITHIUM_SEEDBYTES+0] = (uint8_t)(nonce1);
	coeffs1[LC_DILITHIUM_SEEDBYTES+1] = (uint8_t)(nonce1 >> 8);
	coeffs2[LC_DILITHIUM_SEEDBYTES+0] = (uint8_t)(nonce2);
	coeffs2[LC_DILITHIUM_SEEDBYTES+1] = (uint8_t)(nonce2 >> 8);
	coeffs3[LC_DILITHIUM_SEEDBYTES+0] = (uint8_t)(nonce3);
	coeffs3[LC_DILITHIUM_SEEDBYTES+1] = (uint8_t)(nonce3 >> 8);

	shake128x4_absorb_once(state, coeffs0, coeffs1, coeffs2, coeffs3,
			       LC_DILITHIUM_SEEDBYTES + 2);
	shake128x4_squeezeblocks(coeffs0, coeffs1, coeffs2, coeffs3,
				 REJ_UNIFORM_NBLOCKS, state);

	ctr0 = rej_uniform_avx(a0->coeffs, coeffs0);
	ctr1 = rej_uniform_avx(a1->coeffs, coeffs1);
	ctr2 = rej_uniform_avx(a2->coeffs, coeffs2);
	ctr3 = rej_uniform_avx(a3->coeffs, coeffs3);

	while (ctr0 < LC_DILITHIUM_N ||
	       ctr1 < LC_DILITHIUM_N ||
	       ctr2 < LC_DILITHIUM_N ||
	       ctr3 < LC_DILITHIUM_N) {
		shake128x4_squeezeblocks(coeffs0, coeffs1, coeffs2, coeffs3,
					 1, state);

		ctr0 += rej_uniform(a0->coeffs + ctr0,
				    LC_DILITHIUM_N - ctr0, coeffs0,
				    LC_SHAKE_128_SIZE_BLOCK);
		ctr1 += rej_uniform(a1->coeffs + ctr1,
				    LC_DILITHIUM_N - ctr1, coeffs1,
				    LC_SHAKE_128_SIZE_BLOCK);
		ctr2 += rej_uniform(a2->coeffs + ctr2,
				    LC_DILITHIUM_N - ctr2, coeffs2,
				    LC_SHAKE_128_SIZE_BLOCK);
		ctr3 += rej_uniform(a3->coeffs + ctr3,
				    LC_DILITHIUM_N - ctr3, coeffs3,
				    LC_SHAKE_128_SIZE_BLOCK);
	}
}

void poly_uniform_eta_4x_avx(poly *a0,
			     poly *a1,
			     poly *a2,
			     poly *a3,
			     const uint8_t seed[64],
			     uint16_t nonce0,
			     uint16_t nonce1,
			     uint16_t nonce2,
			     uint16_t nonce3,
			     void *ws_buf,
			     void *ws_keccak)
{
	unsigned int ctr0, ctr1, ctr2, ctr3;
	__m256i f;
	keccakx4_state *state = ws_keccak;
#define BUFSIZE (REJ_UNIFORM_ETA_BUFLEN)
	__m256i *vec0 = (__m256i *)ws_buf;
	__m256i *vec1 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE);
	__m256i *vec2 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 2;
	__m256i *vec3 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 3;
	uint8_t *coeffs0 = (uint8_t *)vec0;
	uint8_t *coeffs1 = (uint8_t *)vec1;
	uint8_t *coeffs2 = (uint8_t *)vec2;
	uint8_t *coeffs3 = (uint8_t *)vec3;
#undef BUFSIZE

	f = _mm256_loadu_si256((__m256i_u *)&seed[0]);
	_mm256_store_si256(&vec0[0],f);
	_mm256_store_si256(&vec1[0],f);
	_mm256_store_si256(&vec2[0],f);
	_mm256_store_si256(&vec3[0],f);
	f = _mm256_loadu_si256((__m256i_u *)&seed[32]);
	_mm256_store_si256(&vec0[1],f);
	_mm256_store_si256(&vec1[1],f);
	_mm256_store_si256(&vec2[1],f);
	_mm256_store_si256(&vec3[1],f);

	coeffs0[64] = (uint8_t)(nonce0);
	coeffs0[65] = (uint8_t)(nonce0 >> 8);
	coeffs1[64] = (uint8_t)(nonce1);
	coeffs1[65] = (uint8_t)(nonce1 >> 8);
	coeffs2[64] = (uint8_t)(nonce2);
	coeffs2[65] = (uint8_t)(nonce2 >> 8);
	coeffs3[64] = (uint8_t)(nonce3);
	coeffs3[65] = (uint8_t)(nonce3 >> 8);

	shake256x4_absorb_once(state, coeffs0, coeffs1, coeffs2, coeffs3, 66);
	shake256x4_squeezeblocks(coeffs0, coeffs1, coeffs2, coeffs3,
				 REJ_UNIFORM_ETA_NBLOCKS, state);

	ctr0 = rej_eta_avx(a0->coeffs, coeffs0);
	ctr1 = rej_eta_avx(a1->coeffs, coeffs1);
	ctr2 = rej_eta_avx(a2->coeffs, coeffs2);
	ctr3 = rej_eta_avx(a3->coeffs, coeffs3);

	while (ctr0 < LC_DILITHIUM_N ||
	       ctr1 < LC_DILITHIUM_N ||
	       ctr2 < LC_DILITHIUM_N ||
	       ctr3 < LC_DILITHIUM_N) {
		shake256x4_squeezeblocks(coeffs0, coeffs1, coeffs2, coeffs3, 1,
					 state);

		ctr0 += rej_eta(a0->coeffs + ctr0, LC_DILITHIUM_N - ctr0,
				coeffs0, LC_SHAKE_256_SIZE_BLOCK);
		ctr1 += rej_eta(a1->coeffs + ctr1, LC_DILITHIUM_N - ctr1,
				coeffs1, LC_SHAKE_256_SIZE_BLOCK);
		ctr2 += rej_eta(a2->coeffs + ctr2, LC_DILITHIUM_N - ctr2,
				coeffs2, LC_SHAKE_256_SIZE_BLOCK);
		ctr3 += rej_eta(a3->coeffs + ctr3, LC_DILITHIUM_N - ctr3,
				coeffs3, LC_SHAKE_256_SIZE_BLOCK);
	}
}

/**
 * @brief poly_uniform_gamma1_4x_avx
 *
 * Sample polynomial with uniformly random coefficients in [-(GAMMA1 - 1),
 * GAMMA1] by unpacking output stream of SHAKE256(seed|nonce).
 *
 * @param a pointer to output polynomial
 * @param seed[] byte array with seed of length CRHBYTES
 * @param nonce 16-bit nonce
 */
void poly_uniform_gamma1_4x_avx(poly *a0,
				poly *a1,
				poly *a2,
				poly *a3,
				const uint8_t seed[64],
				uint16_t nonce0,
				uint16_t nonce1,
				uint16_t nonce2,
				uint16_t nonce3,
				void *ws_buf,
				void *ws_keccak)
{
	keccakx4_state *state = ws_keccak;
	__m256i f;
#define BUFSIZE (POLY_UNIFORM_GAMMA1_NBLOCKS * LC_SHAKE_256_SIZE_BLOCK + 14)
	__m256i *vec0 = (__m256i *)ws_buf;
	__m256i *vec1 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE);
	__m256i *vec2 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 2;
	__m256i *vec3 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 3;
	uint8_t *coeffs0 = (uint8_t *)vec0;
	uint8_t *coeffs1 = (uint8_t *)vec1;
	uint8_t *coeffs2 = (uint8_t *)vec2;
	uint8_t *coeffs3 = (uint8_t *)vec3;
#undef BUFSIZE

	f = _mm256_loadu_si256((__m256i_u *)&seed[0]);
	_mm256_store_si256(&vec0[0], f);
	_mm256_store_si256(&vec1[0], f);
	_mm256_store_si256(&vec2[0], f);
	_mm256_store_si256(&vec3[0], f);
	f = _mm256_loadu_si256((__m256i_u *)&seed[32]);
	_mm256_store_si256(&vec0[1], f);
	_mm256_store_si256(&vec1[1], f);
	_mm256_store_si256(&vec2[1], f);
	_mm256_store_si256(&vec3[1], f);

	coeffs0[64] = (uint8_t)(nonce0);
	coeffs0[65] = (uint8_t)(nonce0 >> 8);
	coeffs1[64] = (uint8_t)(nonce1);
	coeffs1[65] = (uint8_t)(nonce1 >> 8);
	coeffs2[64] = (uint8_t)(nonce2);
	coeffs2[65] = (uint8_t)(nonce2 >> 8);
	coeffs3[64] = (uint8_t)(nonce3);
	coeffs3[65] = (uint8_t)(nonce3 >> 8);

	shake256x4_absorb_once(state, coeffs0, coeffs1, coeffs2, coeffs3, 66);
	shake256x4_squeezeblocks(coeffs0, coeffs1, coeffs2, coeffs3,
				 POLY_UNIFORM_GAMMA1_NBLOCKS, state);

	polyz_unpack_avx(a0, coeffs0);
	polyz_unpack_avx(a1, coeffs1);
	polyz_unpack_avx(a2, coeffs2);
	polyz_unpack_avx(a3, coeffs3);
}

/**
 * @brief poly_challenge_avx
 *
 * Implementation of H. Samples polynomial with TAU nonzero coefficients in
 * {-1,1} using the output stream of SHAKE256(seed).
 *
 * @param c pointer to output polynomial
 * @param mu[] byte array containing seed of length SEEDBYTES
 */
void poly_challenge_avx(poly * restrict c,
			const uint8_t seed[LC_DILITHIUM_SEEDBYTES])
{
	unsigned int i, b, pos;
	uint64_t signs;
	BUF_ALIGNED_UINT8_M256I(LC_SHAKE_256_SIZE_BLOCK) buf;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, seed, LC_DILITHIUM_SEEDBYTES);
	lc_hash_set_digestsize(hash_ctx, sizeof(buf));
	lc_hash_final(hash_ctx, buf.coeffs);

	memcpy(&signs, buf.coeffs, 8);
	pos = 8;

	memset(c->vec, 0, sizeof(poly));
	for (i = LC_DILITHIUM_N - LC_DILITHIUM_TAU; i < LC_DILITHIUM_N; ++i) {
		do {
			if (pos >= LC_SHAKE_256_SIZE_BLOCK) {
				lc_hash_final(hash_ctx, buf.coeffs);
				pos = 0;
			}

			b = buf.coeffs[pos++];
		} while(b > i);

		c->coeffs[i] = c->coeffs[b];
		c->coeffs[b] = (int32_t)(1 - 2*(signs & 1));
		signs >>= 1;
	}

	lc_hash_zero(hash_ctx);
	memset_secure(buf.coeffs, 0, sizeof(buf));
}

/**
 * @brief polyeta_pack_avx
 *
 * Bit-pack polynomial with coefficients in [-ETA,ETA].
 *
 * @param r pointer to output byte array with at least POLYETA_PACKEDBYTES bytes
 * @param a pointer to input polynomial
 */
void polyeta_pack_avx(uint8_t r[LC_DILITHIUM_POLYETA_PACKEDBYTES],
		      const poly * restrict a)
{
	unsigned int i;
	uint8_t t[8];

	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		t[0] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8*i+0]);
		t[1] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8*i+1]);
		t[2] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8*i+2]);
		t[3] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8*i+3]);
		t[4] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8*i+4]);
		t[5] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8*i+5]);
		t[6] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8*i+6]);
		t[7] = (uint8_t)(LC_DILITHIUM_ETA - a->coeffs[8*i+7]);

		r[3*i+0]  = (uint8_t)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
		r[3*i+1]  = (uint8_t)((t[2] >> 2) | (t[3] << 1) |
				      (t[4] << 4) | (t[5] << 7));
		r[3*i+2]  = (uint8_t)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
	}
}

/**
 * @param polyeta_unpack_avx
 *
 * Unpack polynomial with coefficients in [-ETA,ETA].
 *
 * @param r pointer to output polynomial
 * @param a byte array with bit-packed polynomial
 */
void polyeta_unpack_avx(poly * restrict r,
			const uint8_t a[LC_DILITHIUM_POLYETA_PACKEDBYTES])
{
	unsigned int i;

	for(i = 0; i < LC_DILITHIUM_N/8; ++i) {
		r->coeffs[8*i+0] =  (a[3*i+0] >> 0) & 7;
		r->coeffs[8*i+1] =  (a[3*i+0] >> 3) & 7;
		r->coeffs[8*i+2] = ((a[3*i+0] >> 6) | (a[3*i+1] << 2)) & 7;
		r->coeffs[8*i+3] =  (a[3*i+1] >> 1) & 7;
		r->coeffs[8*i+4] =  (a[3*i+1] >> 4) & 7;
		r->coeffs[8*i+5] = ((a[3*i+1] >> 7) | (a[3*i+2] << 1)) & 7;
		r->coeffs[8*i+6] =  (a[3*i+2] >> 2) & 7;
		r->coeffs[8*i+7] =  (a[3*i+2] >> 5) & 7;

		r->coeffs[8*i+0] = LC_DILITHIUM_ETA - r->coeffs[8*i+0];
		r->coeffs[8*i+1] = LC_DILITHIUM_ETA - r->coeffs[8*i+1];
		r->coeffs[8*i+2] = LC_DILITHIUM_ETA - r->coeffs[8*i+2];
		r->coeffs[8*i+3] = LC_DILITHIUM_ETA - r->coeffs[8*i+3];
		r->coeffs[8*i+4] = LC_DILITHIUM_ETA - r->coeffs[8*i+4];
		r->coeffs[8*i+5] = LC_DILITHIUM_ETA - r->coeffs[8*i+5];
		r->coeffs[8*i+6] = LC_DILITHIUM_ETA - r->coeffs[8*i+6];
		r->coeffs[8*i+7] = LC_DILITHIUM_ETA - r->coeffs[8*i+7];
	}
}

/**
 * @brief polyt1_pack
 *
 * Bit-pack polynomial t1 with coefficients fitting in 10 bits. Input
 * coefficients are assumed to be positive standard representatives.
 *
 * @param r pointer to output byte array with at least POLYT1_PACKEDBYTES bytes
 * @param a pointer to input polynomial
 */
void polyt1_pack_avx(uint8_t r[LC_DILITHIUM_POLYT1_PACKEDBYTES],
		     const poly * restrict a)
{
	unsigned int i;

	for(i = 0; i < LC_DILITHIUM_N / 4; ++i) {
		r[5*i+0] = (uint8_t)((a->coeffs[4*i+0] >> 0));
		r[5*i+1] = (uint8_t)((a->coeffs[4*i+0] >> 8) | (a->coeffs[4*i+1] << 2));
		r[5*i+2] = (uint8_t)((a->coeffs[4*i+1] >> 6) | (a->coeffs[4*i+2] << 4));
		r[5*i+3] = (uint8_t)((a->coeffs[4*i+2] >> 4) | (a->coeffs[4*i+3] << 6));
		r[5*i+4] = (uint8_t)((a->coeffs[4*i+3] >> 2));
	}
}

/**
 * @brief polyt1_unpack_avx
 *
 * Unpack polynomial t1 with 10-bit coefficients. Output coefficients are
 * positive standard representatives.
 *
 * @param r pointer to output polynomial
 * @param a byte array with bit-packed polynomial
 */
void polyt1_unpack_avx(poly * restrict r,
		       const uint8_t a[LC_DILITHIUM_POLYT1_PACKEDBYTES])
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N/4; ++i) {
		r->coeffs[4*i+0] = ((a[5*i+0] >> 0) |
				    ((uint32_t)a[5*i+1] << 8)) & 0x3FF;
		r->coeffs[4*i+1] = ((a[5*i+1] >> 2) |
				    ((uint32_t)a[5*i+2] << 6)) & 0x3FF;
		r->coeffs[4*i+2] = ((a[5*i+2] >> 4) |
				    ((uint32_t)a[5*i+3] << 4)) & 0x3FF;
		r->coeffs[4*i+3] = ((a[5*i+3] >> 6) |
				    ((uint32_t)a[5*i+4] << 2)) & 0x3FF;
	}
}

/**
 * @brief polyt0_pack_avx
 *
 * Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * @param r pointer to output byte array with at least POLYT0_PACKEDBYTES bytes
 * @param a pointer to input polynomial
 */
void polyt0_pack_avx(uint8_t r[LC_DILITHIUM_POLYT0_PACKEDBYTES],
		     const poly * restrict a)
{
	unsigned int i;
	uint32_t t[8];

	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		t[0] = (uint32_t)((1 << (LC_DILITHIUM_D-1)) - a->coeffs[8*i+0]);
		t[1] = (uint32_t)((1 << (LC_DILITHIUM_D-1)) - a->coeffs[8*i+1]);
		t[2] = (uint32_t)((1 << (LC_DILITHIUM_D-1)) - a->coeffs[8*i+2]);
		t[3] = (uint32_t)((1 << (LC_DILITHIUM_D-1)) - a->coeffs[8*i+3]);
		t[4] = (uint32_t)((1 << (LC_DILITHIUM_D-1)) - a->coeffs[8*i+4]);
		t[5] = (uint32_t)((1 << (LC_DILITHIUM_D-1)) - a->coeffs[8*i+5]);
		t[6] = (uint32_t)((1 << (LC_DILITHIUM_D-1)) - a->coeffs[8*i+6]);
		t[7] = (uint32_t)((1 << (LC_DILITHIUM_D-1)) - a->coeffs[8*i+7]);

		r[13*i+ 0]  =  (uint8_t)(t[0]);
		r[13*i+ 1]  =  (uint8_t)(t[0] >>  8);
		r[13*i+ 1] |=  (uint8_t)(t[1] <<  5);
		r[13*i+ 2]  =  (uint8_t)(t[1] >>  3);
		r[13*i+ 3]  =  (uint8_t)(t[1] >> 11);
		r[13*i+ 3] |=  (uint8_t)(t[2] <<  2);
		r[13*i+ 4]  =  (uint8_t)(t[2] >>  6);
		r[13*i+ 4] |=  (uint8_t)(t[3] <<  7);
		r[13*i+ 5]  =  (uint8_t)(t[3] >>  1);
		r[13*i+ 6]  =  (uint8_t)(t[3] >>  9);
		r[13*i+ 6] |=  (uint8_t)(t[4] <<  4);
		r[13*i+ 7]  =  (uint8_t)(t[4] >>  4);
		r[13*i+ 8]  =  (uint8_t)(t[4] >> 12);
		r[13*i+ 8] |=  (uint8_t)(t[5] <<  1);
		r[13*i+ 9]  =  (uint8_t)(t[5] >>  7);
		r[13*i+ 9] |=  (uint8_t)(t[6] <<  6);
		r[13*i+10]  =  (uint8_t)(t[6] >>  2);
		r[13*i+11]  =  (uint8_t)(t[6] >> 10);
		r[13*i+11] |=  (uint8_t)(t[7] <<  3);
		r[13*i+12]  =  (uint8_t)(t[7] >>  5);
	}
}

/**
 * @brief polyt0_unpack_avx
 *
 * Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
 *
 * @param r pointer to output polynomial
 * @param a byte array with bit-packed polynomial
 */
void polyt0_unpack_avx(poly * restrict r,
		       const uint8_t a[LC_DILITHIUM_POLYT0_PACKEDBYTES])
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N / 8; ++i) {
		r->coeffs[8*i+0]  = a[13*i+0];
		r->coeffs[8*i+0] |= (int32_t)a[13*i+1] << 8;
		r->coeffs[8*i+0] &= 0x1FFF;

		r->coeffs[8*i+1]  = a[13*i+1] >> 5;
		r->coeffs[8*i+1] |= (int32_t)a[13*i+2] << 3;
		r->coeffs[8*i+1] |= (int32_t)a[13*i+3] << 11;
		r->coeffs[8*i+1] &= 0x1FFF;

		r->coeffs[8*i+2]  = a[13*i+3] >> 2;
		r->coeffs[8*i+2] |= (int32_t)a[13*i+4] << 6;
		r->coeffs[8*i+2] &= 0x1FFF;

		r->coeffs[8*i+3]  = a[13*i+4] >> 7;
		r->coeffs[8*i+3] |= (int32_t)a[13*i+5] << 1;
		r->coeffs[8*i+3] |= (int32_t)a[13*i+6] << 9;
		r->coeffs[8*i+3] &= 0x1FFF;

		r->coeffs[8*i+4]  = a[13*i+6] >> 4;
		r->coeffs[8*i+4] |= (int32_t)a[13*i+7] << 4;
		r->coeffs[8*i+4] |= (int32_t)a[13*i+8] << 12;
		r->coeffs[8*i+4] &= 0x1FFF;

		r->coeffs[8*i+5]  = a[13*i+8] >> 1;
		r->coeffs[8*i+5] |= (int32_t)a[13*i+9] << 7;
		r->coeffs[8*i+5] &= 0x1FFF;

		r->coeffs[8*i+6]  = a[13*i+9] >> 6;
		r->coeffs[8*i+6] |= (int32_t)a[13*i+10] << 2;
		r->coeffs[8*i+6] |= (int32_t)a[13*i+11] << 10;
		r->coeffs[8*i+6] &= 0x1FFF;

		r->coeffs[8*i+7]  = a[13*i+11] >> 3;
		r->coeffs[8*i+7] |= (int32_t)a[13*i+12] << 5;
		r->coeffs[8*i+7] &= 0x1FFF;

		r->coeffs[8*i+0] = (1 << (LC_DILITHIUM_D-1)) - r->coeffs[8*i+0];
		r->coeffs[8*i+1] = (1 << (LC_DILITHIUM_D-1)) - r->coeffs[8*i+1];
		r->coeffs[8*i+2] = (1 << (LC_DILITHIUM_D-1)) - r->coeffs[8*i+2];
		r->coeffs[8*i+3] = (1 << (LC_DILITHIUM_D-1)) - r->coeffs[8*i+3];
		r->coeffs[8*i+4] = (1 << (LC_DILITHIUM_D-1)) - r->coeffs[8*i+4];
		r->coeffs[8*i+5] = (1 << (LC_DILITHIUM_D-1)) - r->coeffs[8*i+5];
		r->coeffs[8*i+6] = (1 << (LC_DILITHIUM_D-1)) - r->coeffs[8*i+6];
		r->coeffs[8*i+7] = (1 << (LC_DILITHIUM_D-1)) - r->coeffs[8*i+7];
	}
}

/**
 * @brief polyz_pack_avx
 *
 * Bit-pack polynomial with coefficients in [-(GAMMA1 - 1), GAMMA1].
 *
 * @param r pointer to output byte array with at least POLYZ_PACKEDBYTES bytes
 * @param a pointer to input polynomial
 */
void polyz_pack_avx(uint8_t r[LC_DILITHIUM_POLYZ_PACKEDBYTES],
		    const poly * restrict a)
{
	unsigned int i;
	uint32_t t[4];

	for (i = 0; i < LC_DILITHIUM_N / 2; ++i) {
		t[0] = (uint32_t)(LC_DILITHIUM_GAMMA1 - a->coeffs[2*i+0]);
		t[1] = (uint32_t)(LC_DILITHIUM_GAMMA1 - a->coeffs[2*i+1]);

		r[5*i+0]  = (uint8_t)(t[0]);
		r[5*i+1]  = (uint8_t)(t[0] >> 8);
		r[5*i+2]  = (uint8_t)(t[0] >> 16);
		r[5*i+2] |= (uint8_t)(t[1] << 4);
		r[5*i+3]  = (uint8_t)(t[1] >> 4);
		r[5*i+4]  = (uint8_t)(t[1] >> 12);
	}
}

/**
 * @brief polyz_unpack_avx
 *
 * Unpack polynomial z with coefficients in [-(GAMMA1 - 1), GAMMA1].
 *
 * @param r pointer to output polynomial
 * @param a byte array with bit-packed polynomial
 */
void polyz_unpack_avx(poly * restrict r, const uint8_t *a)
{
	unsigned int i;
	__m256i f;
	const __m256i shufbidx =
		_mm256_set_epi8(-1,11,10, 9,-1, 9, 8, 7,-1, 6, 5, 4,-1, 4, 3, 2,
				-1, 9, 8, 7,-1, 7, 6, 5,-1, 4, 3, 2,-1, 2, 1, 0);
	const __m256i srlvdidx = _mm256_set1_epi64x((uint64_t)4 << 32);
	const __m256i mask = _mm256_set1_epi32(0xFFFFF);
	const __m256i gamma1 = _mm256_set1_epi32(LC_DILITHIUM_GAMMA1);

	for(i = 0; i < LC_DILITHIUM_N / 8; i++) {
		f = _mm256_loadu_si256((__m256i_u *)&a[20*i]);
		f = _mm256_permute4x64_epi64(f,0x94);
		f = _mm256_shuffle_epi8(f,shufbidx);
		f = _mm256_srlv_epi32(f,srlvdidx);
		f = _mm256_and_si256(f,mask);
		f = _mm256_sub_epi32(gamma1,f);
		_mm256_store_si256(&r->vec[i],f);
	}
}

/**
 * @brief polyw1_pack_avx
 *
 * Bit-pack polynomial w1 with coefficients in [0,15] or [0,43]. Input
 * coefficients are assumed to be positive standard representatives.
 *
 * @param r pointer to output byte array with at least POLYW1_PACKEDBYTES bytes
 * @param a pointer to input polynomial
 */
void polyw1_pack_avx(uint8_t *r, const poly * restrict a)
{
	unsigned int i;
	__m256i f0, f1, f2, f3, f4, f5, f6, f7;
	const __m256i shift = _mm256_set1_epi16((16 << 8) + 1);
	const __m256i shufbidx =
		_mm256_set_epi8(15,14, 7, 6,13,12, 5, 4,11,10, 3, 2, 9, 8, 1, 0,
				15,14, 7, 6,13,12, 5, 4,11,10, 3, 2, 9, 8, 1, 0);

	for( i = 0; i < LC_DILITHIUM_N / 64; ++i) {
		f0 = _mm256_load_si256(&a->vec[8*i+0]);
		f1 = _mm256_load_si256(&a->vec[8*i+1]);
		f2 = _mm256_load_si256(&a->vec[8*i+2]);
		f3 = _mm256_load_si256(&a->vec[8*i+3]);
		f4 = _mm256_load_si256(&a->vec[8*i+4]);
		f5 = _mm256_load_si256(&a->vec[8*i+5]);
		f6 = _mm256_load_si256(&a->vec[8*i+6]);
		f7 = _mm256_load_si256(&a->vec[8*i+7]);
		f0 = _mm256_packus_epi32(f0,f1);
		f1 = _mm256_packus_epi32(f2,f3);
		f2 = _mm256_packus_epi32(f4,f5);
		f3 = _mm256_packus_epi32(f6,f7);
		f0 = _mm256_packus_epi16(f0,f1);
		f1 = _mm256_packus_epi16(f2,f3);
		f0 = _mm256_maddubs_epi16(f0,shift);
		f1 = _mm256_maddubs_epi16(f1,shift);
		f0 = _mm256_packus_epi16(f0,f1);
		f0 = _mm256_permute4x64_epi64(f0,0xD8);
		f0 = _mm256_shuffle_epi8(f0,shufbidx);
		_mm256_storeu_si256((__m256i_u *)&r[32*i], f0);
	}
}
