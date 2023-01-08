/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef KYBER_POLY_AVX2_H
#define KYBER_POLY_AVX2_H

#include "alignment_x86.h"
#include "kyber_consts_avx2.h"
#include "kyber_kdf.h"
#include "kyber_ntt_avx2.h"
#include "kyber_reduce_avx2.h"
#include "lc_kyber.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef BUF_ALIGNED_INT16_M256I(LC_KYBER_N) poly;

void poly_compress_avx(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES], const poly *a);
void poly_decompress_avx(poly *r,
			 const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES]);
void poly_frommsg_avx(poly * restrict r,
		      const uint8_t msg[LC_KYBER_INDCPA_MSGBYTES]);
void poly_tomsg_avx(uint8_t msg[LC_KYBER_INDCPA_MSGBYTES],
		    const poly * restrict a);

void kyber_poly_add_avx(poly *r, const poly *a, const poly *b);
void kyber_poly_sub_avx(poly *r, const poly *a, const poly *b);

void cbd2(poly * restrict r, const __m256i buf[2 * LC_KYBER_N / 128]);

/* buf 32 bytes longer for cbd3 */
static inline void
poly_cbd_eta1_avx(poly *r,
		  const __m256i buf[LC_KYBER_ETA1 * LC_KYBER_N / 128 + 1])
{
#if LC_KYBER_ETA1 == 2
	cbd2(r, buf);
#else
#error "This implementation requires eta1 in {2}"
#endif
}

static inline void
poly_cbd_eta2_avx(poly *r,
		  const __m256i buf[LC_KYBER_ETA2 * LC_KYBER_N / 128])
{
#if LC_KYBER_ETA2 == 2
	cbd2(r, buf);
#else
#error "This implementation requires eta2 = 2"
#endif
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
static inline void
poly_tobytes_avx(uint8_t r[LC_KYBER_POLYBYTES], const poly *a)
{
	LC_FPU_ENABLE;
	kyber_ntttobytes_avx(r, a->vec, kyber_qdata.vec);
	LC_FPU_DISABLE;
}

/**
 * @brief poly_frombytes
 *
 * De-serialization of a polynomial; inverse of poly_tobytes
 *
 * @param r pointer to output polynomial
 * @parar a pointer to input byte array (of LC_KYBER_POLYBYTES bytes)
 */
static inline void
poly_frombytes_avx(poly *r, const uint8_t a[LC_KYBER_POLYBYTES])
{
	LC_FPU_ENABLE;
	kyber_nttfrombytes_avx(r->vec, a, kyber_qdata.vec);
	LC_FPU_DISABLE;
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
static inline void
poly_getnoise_eta1_avx(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
		       uint8_t nonce)
{
	// +32 bytes as required by poly_cbd_eta1
	BUF_ALIGNED_UINT8_M256I(LC_KYBER_ETA1 * LC_KYBER_N / 4 + 32) buf;

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
static inline void
poly_getnoise_eta2_avx(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
		       uint8_t nonce)
{
	BUF_ALIGNED_UINT8_M256I(LC_KYBER_ETA2 * LC_KYBER_N / 4) buf;

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
			   uint8_t nonce3,
			   void *ws_buf,
			   void *ws_keccak);


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
static inline void poly_ntt_avx(poly *r)
{
	LC_FPU_ENABLE;
	kyber_ntt_avx(r->vec, kyber_qdata.vec);
	LC_FPU_DISABLE;
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
static inline void poly_invntt_tomont_avx(poly *r)
{
	LC_FPU_ENABLE;
	kyber_invntt_avx(r->vec, kyber_qdata.vec);
	LC_FPU_DISABLE;
}

static inline void poly_nttunpack_avx(poly *r)
{
	LC_FPU_ENABLE;
	kyber_nttunpack_avx(r->vec, kyber_qdata.vec);
	LC_FPU_DISABLE;
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
static inline void poly_basemul_montgomery_avx(poly *r, const poly *a, const poly *b)
{
	LC_FPU_ENABLE;
	kyber_basemul_avx(r->vec, a->vec, b->vec, kyber_qdata.vec);
	LC_FPU_DISABLE;
}

/**
 * @brief poly_tomont
 *
 * Inplace conversion of all coefficients of a polynomial from normal domain to
 * Montgomery domain
 *
 * @param r pointer to input/output polynomial
 */
static inline void poly_tomont_avx(poly *r)
{
	LC_FPU_ENABLE;
	tomont_avx(r->vec, kyber_qdata.vec);
	LC_FPU_DISABLE;
}

/**
 * @brief poly_reduce
 *
 * Applies Barrett reduction to all coefficients of a polynomial for details of
 * the Barrett reduction see comments in reduce.c
 *
 * @param r pointer to input/output polynomial
 */
static inline void poly_reduce_avx(poly *r)
{
	LC_FPU_ENABLE;
	reduce_avx(r->vec, kyber_qdata.vec);
	LC_FPU_DISABLE;
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_AVX2_H */
