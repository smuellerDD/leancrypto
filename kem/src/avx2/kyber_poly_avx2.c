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
#include <string.h>

#include "kyber_align_avx2.h"
#include "kyber_poly_avx2.h"
#include "kyber_ntt_avx2.h"
#include "kyber_consts_avx2.h"
#include "kyber_reduce_avx2.h"
#include "kyber_cbd_avx2.h"
#include "kyber_kdf.h"
#include "shake_4x_avx2.h"

#if (LC_KYBER_K != 4)
#error "AVX2 support for Kyber mode 4 only"
#endif

/**
 * kyber_shake256_prf - Usage of SHAKE256 as a PRF, concatenates secret and
 *			public input and then generates outlen bytes of SHAKE256
 *			output
 *
 * @param out [out] pointer to output
 * @param outlen [in] number of requested output bytes
 * @param key [in] pointer to the key
 * @param nonce [in] single-byte nonce (public PRF input)
 */
static void
kyber_shake256_prf(uint8_t *out, size_t outlen,
		   const uint8_t key[LC_KYBER_SYMBYTES], uint8_t nonce)
{
	kyber_kdf2(key, LC_KYBER_SYMBYTES, &nonce, 1, out, outlen);
}


/**
 * @brief poly_compress
 *
 * Compression and subsequent serialization of a polynomial. The coefficients
 * of the input polynomial are assumed to lie in the invertal [0,q], i.e. the
 * polynomial must be reduced by poly_reduce().
 *
 * @param r pointer to output byte array (of length
 *	    LC_KYBER_POLYCOMPRESSEDBYTES)
 * @param a: pointer to input polynomial
 */
void poly_compress_avx(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES],
			const poly * restrict a)
{
	unsigned int i;
	__m256i f0, f1;
	__m128i t0, t1;
	const __m256i v = _mm256_load_si256(&qdata.vec[_16XV / 16]);
	const __m256i shift1 = _mm256_set1_epi16(1 << 10);
	const __m256i mask = _mm256_set1_epi16(31);
	const __m256i shift2 = _mm256_set1_epi16((32 << 8) + 1);
	const __m256i shift3 = _mm256_set1_epi32((1024 << 16) + 1);
	const __m256i sllvdidx = _mm256_set1_epi64x(12);
	const __m256i shufbidx = _mm256_set_epi8( 8,-1,-1,-1,-1,-1, 4, 3, 2, 1, 0,-1,12,11,10, 9,
						-1,12,11,10, 9, 8,-1,-1,-1,-1,-1 ,4, 3, 2, 1, 0);

	for (i = 0; i < LC_KYBER_N / 32; i++) {
		f0 = _mm256_load_si256(&a->vec[2 * i + 0]);
		f1 = _mm256_load_si256(&a->vec[2 * i + 1]);
		f0 = _mm256_mulhi_epi16(f0,v);
		f1 = _mm256_mulhi_epi16(f1,v);
		f0 = _mm256_mulhrs_epi16(f0,shift1);
		f1 = _mm256_mulhrs_epi16(f1,shift1);
		f0 = _mm256_and_si256(f0,mask);
		f1 = _mm256_and_si256(f1,mask);
		f0 = _mm256_packus_epi16(f0,f1);
		f0 = _mm256_maddubs_epi16(f0,shift2);	// a0 a1 a2 a3 b0 b1 b2 b3 a4 a5 a6 a7 b4 b5 b6 b7
		f0 = _mm256_madd_epi16(f0,shift3);		// a0 a1 b0 b1 a2 a3 b2 b3
		f0 = _mm256_sllv_epi32(f0,sllvdidx);
		f0 = _mm256_srlv_epi64(f0,sllvdidx);
		f0 = _mm256_shuffle_epi8(f0,shufbidx);
		t0 = _mm256_castsi256_si128(f0);
		t1 = _mm256_extracti128_si256(f0,1);
		t0 = _mm_blendv_epi8(t0,t1,_mm256_castsi256_si128(shufbidx));
		_mm_storeu_si128((__m128i_u *)&r[20 * i + 0], t0);
		memcpy(&r[20 * i + 16], &t1, 4);
	}
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
void poly_decompress_avx(poly * restrict r,
			  const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES])
{
	unsigned int i;
	__m128i t;
	__m256i f;
	int16_t ti;
	const __m256i q = _mm256_load_si256(&qdata.vec[_16XQ/16]);
	const __m256i shufbidx = _mm256_set_epi8(9,9,9,8,8,8,8,7,7,6,6,6,6,5,5,5,
						4,4,4,3,3,3,3,2,2,1,1,1,1,0,0,0);
	const __m256i mask = _mm256_set_epi16(248,1984,62,496,3968,124,992,31,
						248,1984,62,496,3968,124,992,31);
	const __m256i shift = _mm256_set_epi16(128,16,512,64,8,256,32,1024,
						128,16,512,64,8,256,32,1024);

	for (i = 0; i < LC_KYBER_N / 16; i++) {
		t = _mm_loadl_epi64((__m128i_u *)&a[10*i+0]);
		memcpy(&ti, &a[10 * i + 8],2);
		t = _mm_insert_epi16(t, ti, 4);
		f = _mm256_broadcastsi128_si256(t);
		f = _mm256_shuffle_epi8(f,shufbidx);
		f = _mm256_and_si256(f,mask);
		f = _mm256_mullo_epi16(f,shift);
		f = _mm256_mulhrs_epi16(f,q);
		_mm256_store_si256(&r->vec[i], f);
	}
}

/**
 * @brief poly_tobytes
 *
 * Serialization of a polynomial in NTT representation.  The coefficients of the
 * input polynomial are assumed to lie in the invertal [0,q], i.e. the
 * polynomial must be reduced by poly_reduce(). The coefficients are orderd as
 * output by poly_ntt(); the serialized output coefficients are in bitreversed
 * order.
 *
 * @param r pointer to output byte array (needs space for LC_KYBER_POLYBYTES
 *	    bytes)
 * @param a: pointer to input polynomial
 */
void poly_tobytes_avx(uint8_t r[LC_KYBER_POLYBYTES], const poly *a)
{
	ntttobytes_avx(r, a->vec, qdata.vec);
}

/**
 * @brief poly_frombytes
 *
 * De-serialization of a polynomial; inverse of poly_tobytes
 *
 * @param r pointer to output polynomial
 * @parar a pointer to input byte array (of LC_KYBER_POLYBYTES bytes)
 */
void poly_frombytes_avx(poly *r, const uint8_t a[LC_KYBER_POLYBYTES])
{
	nttfrombytes_avx(r->vec, a, qdata.vec);
}

/**
 * @brief poly_frommsg
 *
 * Convert 32-byte message to polynomial
 *
 * @param r pointer to output polynomial
 * @param msg pointer to input message
 */
void poly_frommsg_avx(poly * restrict r,
		      const uint8_t msg[LC_KYBER_INDCPA_MSGBYTES])
{
#if (LC_KYBER_INDCPA_MSGBYTES != 32)
#error "LC_KYBER_INDCPA_MSGBYTES must be equal to 32!"
#endif
	__m256i f, g0, g1, g2, g3, h0, h1, h2, h3;
	const __m256i shift = _mm256_broadcastsi128_si256(_mm_set_epi32(0,1,2,3));
	const __m256i idx = _mm256_broadcastsi128_si256(_mm_set_epi8(15,14,11,10,7,6,3,2,13,12,9,8,5,4,1,0));
	const __m256i hqs = _mm256_set1_epi16((LC_KYBER_Q+1)/2);

#define FROMMSG64(i)							\
	g3 = _mm256_shuffle_epi32(f,0x55*i);				\
	g3 = _mm256_sllv_epi32(g3,shift);				\
	g3 = _mm256_shuffle_epi8(g3,idx);				\
	g0 = _mm256_slli_epi16(g3,12);					\
	g1 = _mm256_slli_epi16(g3,8);					\
	g2 = _mm256_slli_epi16(g3,4);					\
	g0 = _mm256_srai_epi16(g0,15);					\
	g1 = _mm256_srai_epi16(g1,15);					\
	g2 = _mm256_srai_epi16(g2,15);					\
	g3 = _mm256_srai_epi16(g3,15);					\
	g0 = _mm256_and_si256(g0,hqs);  /* 19 18 17 16  3  2  1  0 */	\
	g1 = _mm256_and_si256(g1,hqs);  /* 23 22 21 20  7  6  5  4 */	\
	g2 = _mm256_and_si256(g2,hqs);  /* 27 26 25 24 11 10  9  8 */	\
	g3 = _mm256_and_si256(g3,hqs);  /* 31 30 29 28 15 14 13 12 */	\
	h0 = _mm256_unpacklo_epi64(g0,g1);				\
	h2 = _mm256_unpackhi_epi64(g0,g1);				\
	h1 = _mm256_unpacklo_epi64(g2,g3);				\
	h3 = _mm256_unpackhi_epi64(g2,g3);				\
	g0 = _mm256_permute2x128_si256(h0,h1,0x20);			\
	g2 = _mm256_permute2x128_si256(h0,h1,0x31);			\
	g1 = _mm256_permute2x128_si256(h2,h3,0x20);			\
	g3 = _mm256_permute2x128_si256(h2,h3,0x31);			\
	_mm256_store_si256(&r->vec[0+2*i+0],g0);			\
	_mm256_store_si256(&r->vec[0+2*i+1],g1);			\
	_mm256_store_si256(&r->vec[8+2*i+0],g2);			\
	_mm256_store_si256(&r->vec[8+2*i+1],g3)

	f = _mm256_loadu_si256((__m256i_u *)msg);
	FROMMSG64(0);
	FROMMSG64(1);
	FROMMSG64(2);
	FROMMSG64(3);
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
		    const poly * restrict a)
{
	unsigned int i;
	int small;
	__m256i f0, f1, g0, g1;
	const __m256i hq = _mm256_set1_epi16((LC_KYBER_Q - 1)/2);
	const __m256i hhq = _mm256_set1_epi16((LC_KYBER_Q - 1)/4);

	for (i = 0; i < LC_KYBER_N / 32; i++) {
		f0 = _mm256_load_si256(&a->vec[2 *i + 0]);
		f1 = _mm256_load_si256(&a->vec[2 *i + 1]);
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
		memcpy(&msg[4*i], &small, 4);
	}
}

/**
 * @brief poly_getnoise_eta1
 *
 * Sample a polynomial deterministically from a seed and a nonce, with output
 * polynomial close to centered binomial distribution with parameter KYBER_ETA1
 *
 * @param r pointer to output polynomial
 * @param seed: pointer to input seed (of length LC_KYBER_SYMBYTES bytes)
 * @param nonce one-byte input nonce
 */
void poly_getnoise_eta1_avx(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
			    uint8_t nonce)
{
	// +32 bytes as required by poly_cbd_eta1
	ALIGNED_UINT8(LC_KYBER_ETA1 * LC_KYBER_N / 4 + 32) buf;

	//TODO
	kyber_shake256_prf(buf.coeffs, LC_KYBER_ETA1 * LC_KYBER_N / 4,
			   seed, nonce);
	poly_cbd_eta1_avx(r, buf.vec);
}

/**
 * @brief poly_getnoise_eta2
 *
 * Sample a polynomial deterministically from a seed and a nonce, with output
 * polynomial close to centered binomial distribution with parameter KYBER_ETA2
 *
 * @param r pointer to output polynomial
 * @param seed pointer to input seed (of length LC_KYBER_SYMBYTES bytes)
 * @parm nonce one-byte input nonce
 */
void poly_getnoise_eta2_avx(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
			    uint8_t nonce)
{
	ALIGNED_UINT8(LC_KYBER_ETA2 * LC_KYBER_N / 4) buf;

	//TODO
	kyber_shake256_prf(buf.coeffs, LC_KYBER_ETA2 * LC_KYBER_N / 4,
			   seed, nonce);
	poly_cbd_eta2_avx(r, buf.vec);
}

#define NOISE_NBLOCKS 							       \
	((LC_KYBER_ETA1 * LC_KYBER_N / 4 + LC_SHAKE_256_SIZE_BLOCK - 1) /      \
	 LC_SHAKE_256_SIZE_BLOCK)
void poly_getnoise_eta1_4x(poly *r0,
			   poly *r1,
			   poly *r2,
			   poly *r3,
			   const uint8_t seed[32],
			   uint8_t nonce0,
			   uint8_t nonce1,
			   uint8_t nonce2,
			   uint8_t nonce3)
{
	ALIGNED_UINT8(NOISE_NBLOCKS * LC_SHAKE_256_SIZE_BLOCK) buf[4];
	__m256i f;
	keccakx4_state state;

	f = _mm256_loadu_si256((__m256i_u *)seed);
	_mm256_store_si256(buf[0].vec, f);
	_mm256_store_si256(buf[1].vec, f);
	_mm256_store_si256(buf[2].vec, f);
	_mm256_store_si256(buf[3].vec, f);

	buf[0].coeffs[32] = nonce0;
	buf[1].coeffs[32] = nonce1;
	buf[2].coeffs[32] = nonce2;
	buf[3].coeffs[32] = nonce3;

	shake256x4_absorb_once(&state,
			       buf[0].coeffs, buf[1].coeffs,
			       buf[2].coeffs, buf[3].coeffs, 33);
	shake256x4_squeezeblocks(buf[0].coeffs, buf[1].coeffs,
				 buf[2].coeffs, buf[3].coeffs,
				 NOISE_NBLOCKS, &state);

	poly_cbd_eta1_avx(r0, buf[0].vec);
	poly_cbd_eta1_avx(r1, buf[1].vec);
	poly_cbd_eta1_avx(r2, buf[2].vec);
	poly_cbd_eta1_avx(r3, buf[3].vec);

	memset_secure(&state, 0, sizeof(state));
}

/**
 * @brief poly_ntt
 *
 * Computes negacyclic number-theoretic transform (NTT) of a polynomial in
 * place. Input coefficients assumed to be in normal order, output coefficients
 * are in special order that is natural for the vectorization. Input
 * coefficients are assumed to be bounded by q in absolute value, output
 * coefficients are bounded by 16118 in absolute value.
 *
 * @param r pointer to in/output polynomial
 */
void poly_ntt_avx(poly *r)
{
	ntt_avx(r->vec, qdata.vec);
}

/**
 * poly_invntt_tomont
 *
 * Computes inverse of negacyclic number-theoretic transform (NTT) of a
 * polynomial in place;
 * Input coefficients assumed to be in special order from vectorized forward
 * ntt, output in normal order. Input coefficients can be arbitrary 16-bit
 * integers, output coefficients are bounded by 14870 in absolute value.
 *
 * @param a pointer to in/output polynomial
 */
void poly_invntt_tomont_avx(poly *r)
{
	invntt_avx(r->vec, qdata.vec);
}

void poly_nttunpack_avx(poly *r)
{
	nttunpack_avx(r->vec, qdata.vec);
}

/**
 * @brief poly_basemul_montgomery
 *
 * Multiplication of two polynomials in NTT domain. One of the input polynomials
 * needs to have coefficients bounded by q, the other polynomial can have
 * arbitrary coefficients. Output coefficients are bounded by 6656.
 *
 * @param r pointer to output polynomial
 * @param a pointer to first input polynomial
 * @param b pointer to second input polynomial
 */
void poly_basemul_montgomery_avx(poly *r, const poly *a, const poly *b)
{
	basemul_avx(r->vec, a->vec, b->vec, qdata.vec);
}

/**
 * @brief poly_tomont
 *
 * Inplace conversion of all coefficients of a polynomial from normal domain to
 * Montgomery domain
 *
 * @param r pointer to input/output polynomial
 */
void poly_tomont_avx(poly *r)
{
	tomont_avx(r->vec, qdata.vec);
}

/**
 * @brief poly_reduce
 *
 * Applies Barrett reduction to all coefficients of a polynomial for details of
 * the Barrett reduction see comments in reduce.c
 *
 * @param r pointer to input/output polynomial
 */
void poly_reduce_avx(poly *r)
{
	reduce_avx(r->vec, qdata.vec);
}

/**
 * @brief poly_add
 *
 * Add two polynomials. No modular reduction is performed.
 *
 * @param r pointer to output polynomial
 * @param a pointer to first input polynomial
 * @param b pointer to second input polynomial
 */
void poly_add_avx(poly *r, const poly *a, const poly *b)
{
	unsigned int i;
	__m256i f0, f1;

	for (i = 0; i < LC_KYBER_N / 16; i++) {
		f0 = _mm256_load_si256(&a->vec[i]);
		f1 = _mm256_load_si256(&b->vec[i]);
		f0 = _mm256_add_epi16(f0, f1);
		_mm256_store_si256(&r->vec[i], f0);
	}
}

/**
 * @brief poly_sub
 *
 * Subtract two polynomials. No modular reduction is performed.
 *
 * @param r pointer to output polynomial
 * @param a pointer to first input polynomial
 * @param b pointer to second input polynomial
 */
void poly_sub_avx(poly *r, const poly *a, const poly *b)
{
	unsigned int i;
	__m256i f0, f1;

	for (i = 0; i < LC_KYBER_N / 16; i++) {
		f0 = _mm256_load_si256(&a->vec[i]);
		f1 = _mm256_load_si256(&b->vec[i]);
		f0 = _mm256_sub_epi16(f0, f1);
		_mm256_store_si256(&r->vec[i], f0);
	}
}
