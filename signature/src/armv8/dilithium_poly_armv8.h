/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef DILITHIUM_POLY_ARMV8_H
#define DILITHIUM_POLY_ARMV8_H

#include "lc_dilithium.h"

#include "NTT_params.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LC_DILITHIUM_QINV
#define LC_DILITHIUM_QINV 58728449 // q^(-1) mod 2^32
#endif

static const int32_t montgomery_const[2] = { LC_DILITHIUM_Q,
					     LC_DILITHIUM_QINV };

void poly_uniformx2(poly *a0, poly *a1,
		    const uint8_t seed[LC_DILITHIUM_SEEDBYTES], uint16_t nonce0,
		    uint16_t nonce1);
void poly_uniform_etax2(poly *a0, poly *a1,
			const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			uint16_t nonce0, uint16_t nonce1);
void poly_uniform_gamma1x2(poly *a0, poly *a1,
			   const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			   uint16_t nonce0, uint16_t nonce1);

extern void poly_reduce_armv8(int32_t *, const int32_t *);
/**
 * @brief poly_reduce - Inplace reduction of all coefficients of polynomial to
 *			representative in [-6283009,6283007].
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_reduce(poly *a)
{
	poly_reduce_armv8(a->coeffs, montgomery_const);
}

extern void poly_caddq_armv8(int32_t *, const int32_t *);
/**
 * @brief poly_caddq - For all coefficients of in/out polynomial add Q if
 *		       coefficient is negative.
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_caddq(poly *a)
{
	poly_caddq_armv8(a->coeffs, montgomery_const);
}

extern void poly_pointwise_montgomery_armv8(int32_t *des, const int32_t *src1,
					    const int32_t *src2,
					    const int32_t *table);
/**
 * @brief poly_pointwise_montgomery - Pointwise multiplication of polynomials in
 *				      NTT domain representation and
 *				      multiplication of resulting polynomial
 *				      by 2^{-32}.
 *
 * @param [out] c pointer to output polynomial
 * @param [in] a pointer to first input polynomial
 * @param [in] b pointer to second input polynomial
 */
static inline void poly_pointwise_montgomery(poly *c, const poly *a,
					     const poly *b)
{
	poly_pointwise_montgomery_armv8(c->coeffs, a->coeffs, b->coeffs,
					montgomery_const);
}

extern void poly_power2round_armv8(int32_t *, int32_t *, const int32_t *);
/**
 * @brief poly_power2round - For all coefficients c of the input polynomial,
 *			     compute c0, c1 such that c mod Q = c1*2^D + c0
 *			     with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients
 *			     to be standard representatives.
 *
 * @param [out] a1 pointer to output polynomial with coefficients c1
 * @param [out] a0 pointer to output polynomial with coefficients c0
 * @param [in] a pointer to input polynomial
 */
static inline void poly_power2round(poly *a1, poly *a0, const poly *a)
{
	poly_power2round_armv8(a1->coeffs, a0->coeffs, a->coeffs);
}

extern void armv8_10_to_32(int32_t *, const uint8_t *);
/**
 * @brief polyt1_unpack - Unpack polynomial t1 with 10-bit coefficients.
 *			  Output coefficients are standard representatives.
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a byte array with bit-packed polynomial
 */
static inline void polyt1_unpack(poly *r, const uint8_t *a)
{
	armv8_10_to_32(r->coeffs, a);
}

extern void ntt_SIMD_top_armv8(int *des, const int *table,
			       const int *_constants);
extern void ntt_SIMD_bot_armv8(int *des, const int *table,
			       const int *_constants);
/**
 * @brief poly_ntt - Inplace forward NTT. Coefficients can grow by
 *		     8*Q in absolute value.
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_ntt(poly *a)
{
	ntt_SIMD_top_armv8(a->coeffs,
			   streamlined_CT_negacyclic_table_Q1_extended,
			   constants);
	ntt_SIMD_bot_armv8(a->coeffs,
			   streamlined_CT_negacyclic_table_Q1_extended,
			   constants);
}

extern void intt_SIMD_top_armv8(int *des, const int *table,
				const int *_constants);
extern void intt_SIMD_bot_armv8(int *des, const int *table,
				const int *_constants);
/**
 * @brief poly_invntt_tomont - Inplace inverse NTT and multiplication by 2^{32}.
 *			       Input coefficients need to be less than Q in
 *			       absolute value and output coefficients are again
 *			       bounded by Q.
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_invntt_tomont(poly *a)
{
	intt_SIMD_bot_armv8(a->coeffs, streamlined_inv_CT_table_Q1_extended,
			    constants);
	intt_SIMD_top_armv8(a->coeffs, streamlined_inv_CT_table_Q1_extended,
			    constants);
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLY_ARMV8_H */
