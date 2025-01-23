/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef DILITHIUM_POLY_ARMV7_H
#define DILITHIUM_POLY_ARMV7_H

#include "dilithium_type.h"
#include "dilithium_ntt_consts.h"

#ifdef __cplusplus
extern "C" {
#endif

void poly_uniform_armv7(poly *a, const uint8_t seed[LC_DILITHIUM_SEEDBYTES],
			uint16_t nonce, void *ws_buf);

extern void armv7_poly_reduce_asm(int32_t a[LC_DILITHIUM_N]);
/**
 * @brief poly_reduce - Inplace reduction of all coefficients of polynomial to
 *			representative in [-6283009,6283007].
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_reduce(poly *a)
{
#if 0
	armv7_poly_reduce_asm(a->coeffs);
#else
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		a->coeffs[i] = reduce32(a->coeffs[i]);
#endif
}

/**
 * @brief poly_caddq - For all coefficients of in/out polynomial add Q if
 *		       coefficient is negative.
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_caddq(poly *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		a->coeffs[i] = caddq(a->coeffs[i]);
}

extern void
armv7_poly_pointwise_invmontgomery_asm_smull(int32_t c[LC_DILITHIUM_N],
					     const int32_t a[LC_DILITHIUM_N],
					     const int32_t b[LC_DILITHIUM_N]);
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
	armv7_poly_pointwise_invmontgomery_asm_smull(c->coeffs, a->coeffs,
						     b->coeffs);
}

extern void armv7_poly_pointwise_acc_invmontgomery_asm_smull(
	int32_t c[LC_DILITHIUM_N], const int32_t a[LC_DILITHIUM_N],
	const int32_t b[LC_DILITHIUM_N]);
static inline void poly_pointwise_acc_montgomery(poly *c, const poly *a,
						 const poly *b)
{
	armv7_poly_pointwise_acc_invmontgomery_asm_smull(c->coeffs, a->coeffs,
							 b->coeffs);
}

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
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
}

/**
 * @brief polyt1_unpack - Unpack polynomial t1 with 10-bit coefficients.
 *			  Output coefficients are standard representatives.
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a byte array with bit-packed polynomial
 */
static inline void polyt1_unpack(poly *r, const uint8_t *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N / 4; ++i) {
		r->coeffs[4 * i + 0] =
			((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) &
			0x3FF;
		r->coeffs[4 * i + 1] =
			((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) &
			0x3FF;
		r->coeffs[4 * i + 2] =
			((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) &
			0x3FF;
		r->coeffs[4 * i + 3] =
			((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) &
			0x3FF;
	}
}

extern void armv7_ntt_asm_smull(int32_t p[LC_DILITHIUM_N],
				const uint32_t zetas_asm[LC_DILITHIUM_N]);
/**
 * @brief poly_ntt - Inplace forward NTT. Coefficients can grow by
 *		     8*Q in absolute value.
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_ntt(poly *a)
{
	armv7_ntt_asm_smull(a->coeffs, zetas_interleaved_asm);
}

extern void
armv7_inv_ntt_asm_smull(int32_t p[LC_DILITHIUM_N],
			const uint32_t zetas_inv_asm[LC_DILITHIUM_N]);
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
	armv7_inv_ntt_asm_smull(a->coeffs, zetas_interleaved_inv_asm);
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLY_ARMV7_H */
