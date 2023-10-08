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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_POLY_ARMV7_H
#define KYBER_POLY_ARMV7_H

#include "kyber_armv7.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief poly_reduce - Applies Barrett reduction to all coefficients of a
 *			polynomial for details of the Barrett reduction see
 *			comments in kyber_reduce.c
 *
 * @param [in,out] r pointer to input/output polynomial
 */
static inline void poly_reduce(poly *r)
{
	kyber_barrett_reduce_armv7(r->coeffs);
}

/**
 * @brief poly_add - Add two polynomials; no modular reduction is performed
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a pointer to first input polynomial
 * @param [in] b pointer to second input polynomial
 */
static inline void poly_add(poly *r, const poly *a, const poly *b)
{
	kyber_poly_add_armv7(r->coeffs, a->coeffs, b->coeffs);
}

/**
 * @brief poly_sub - Subtract two polynomials; no modular reduction is performed
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a pointer to first input polynomial
 * @param [in] b pointer to second input polynomial
 */
static inline void poly_sub(poly *r, const poly *a, const poly *b)
{
	kyber_poly_sub_armv7(r->coeffs, a->coeffs, b->coeffs);
}

/**
 * @brief poly_basemul_montgomery - Multiplication of two polynomials in NTT
 *				    domain
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a pointer to first input polynomial
 * @param [in] b pointer to second input polynomial
 */
static inline void poly_basemul_montgomery(poly *r, const poly *a,
					   const poly *b)
{
	kyber_basemul_armv7(r->coeffs, a->coeffs, b->coeffs, zetas_armv7);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_ARMV7_H */
