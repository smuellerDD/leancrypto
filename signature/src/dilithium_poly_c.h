/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef DILITHIUM_POLY_C_H
#define DILITHIUM_POLY_C_H

#include "dilithium_ntt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief poly_reduce - Inplace reduction of all coefficients of polynomial to
 *			representative in [-6283009,6283007].
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_reduce(poly *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		a->coeffs[i] = reduce32(a->coeffs[i]);
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
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		c->coeffs[i] =
			montgomery_reduce((int64_t)a->coeffs[i] * b->coeffs[i]);
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
 * @param r [out] pointer to output polynomial
 * @param a [in] byte array with bit-packed polynomial
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

/**
 * @brief poly_ntt - Inplace forward NTT. Coefficients can grow by
 *		     8*Q in absolute value.
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_ntt(poly *a)
{
	ntt(a->coeffs);
}

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
	invntt_tomont(a->coeffs);
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLY_C_H */
