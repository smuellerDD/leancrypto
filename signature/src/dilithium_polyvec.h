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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef DILITHIUM_POLYVEC_H
#define DILITHIUM_POLYVEC_H

#include "conv_be_le.h"
#include "dilithium_poly.h"
#include "lc_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	poly vec[LC_DILITHIUM_L];
} polyvecl;

/* Vectors of polynomials of length K */
typedef struct {
	poly vec[LC_DILITHIUM_K];
} polyveck;

/**************************************************************/
/************ Vectors of polynomials of length L **************/
/**************************************************************/

static inline void polyvecl_reduce(polyvecl *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_L
	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_reduce(&v->vec[i]);
}

/**
 * @brief polyvecl_add - Add vectors of polynomials of length L.
 *			 No modular reduction is performed.
 *
 * @param [out] w pointer to output vector
 * @param [in] u pointer to first summand
 * @param [in] v pointer to second summand
 */
static inline void polyvecl_add(polyvecl *w, const polyvecl *u,
				const polyvecl *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_L
	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/**
 * @brief polyvecl_ntt - Forward NTT of all polynomials in vector of length L.
 *			 Output coefficients can be up to 16*Q larger than input
 *			 coefficients.
 *
 * @param [in,out] v pointer to input/output vector
 */
static inline void polyvecl_ntt(polyvecl *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_L
	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_ntt(&v->vec[i]);
}

static inline void polyvecl_invntt_tomont(polyvecl *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_L
	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_invntt_tomont(&v->vec[i]);
}

static inline void polyvecl_pointwise_poly_montgomery(polyvecl *r,
						      const poly *a,
						      const polyvecl *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_L
	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/**
 * @brief polyvecl_chknorm - Check infinity norm of polynomials in vector of
 *			     length L. Assumes input polyvecl to be reduced by
 *			     polyvecl_reduce().
 *
 * @param [in] v pointer to vector
 * @param [in] B norm bound
 *
 * @return 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
 * and 1 otherwise.
 */
static inline int polyvecl_chknorm(const polyvecl *v, int32_t bound)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_L
	for (i = 0; i < LC_DILITHIUM_L; ++i)
		if (poly_chknorm(&v->vec[i], bound))
			return 1;

	return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

/**
 * @brief polyveck_reduce - Reduce coefficients of polynomials in vector of
 *			    length LC_DILITHIUM_K to representatives in
 *			    [-6283009,6283007].
 *
 * @param [in,out] v pointer to input/output vector
 */
static inline void polyveck_reduce(polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_reduce(&v->vec[i]);
}

/**
 * @brief polyveck_caddq - For all coefficients of polynomials in vector of
 * 			   length LC_DILITHIUM_K add LC_DILITHIUM_Q if
 *			   coefficient is negative.
 *
 * @param [in,out] v pointer to input/output vector
 */
static inline void polyveck_caddq(polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_caddq(&v->vec[i]);
}

/**
 * @brief polyveck_add - Add vectors of polynomials of length LC_DILITHIUM_K.
 *			 No modular reduction is performed.
 *
 * @param [out] w pointer to output vector
 * @param [in] u pointer to first summand
 * @param [in] v pointer to second summand
 */
static inline void polyveck_add(polyveck *w, const polyveck *u,
				const polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/**
 * @brief olyveck_sub - Subtract vectors of polynomials of length
 *			LC_DILITHIUM_K. No modular reduction is performed.
 *
 * @param [out] w pointer to output vector
 * @param [in] u pointer to first input vector
 * @param [in] v pointer to second input vector to be subtracted from first
 *		 input vector
 */
static inline void polyveck_sub(polyveck *w, const polyveck *u,
				const polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/**
 * @brief polyveck_shiftl - Multiply vector of polynomials of Length K by
 *			    2^D without modular reduction. Assumes input
 *			    coefficients to be less than 2^{31-D}.
 *
 * @param [in,out] v pointer to input/output vector
 */
static inline void polyveck_shiftl(polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_shiftl(&v->vec[i]);
}

/**
 * @brief polyveck_ntt - Forward NTT of all polynomials in vector of length K.
 *			 Output coefficients can be up to 16*Q larger than input
 *			 coefficients.
 *
 * @param [in,out] v pointer to input/output vector
 */
static inline void polyveck_ntt(polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_ntt(&v->vec[i]);
}

/**
 * @brief polyveck_invntt_tomont - Inverse NTT and multiplication by 2^{32} of
 *				   polynomials in vector of length K. Input
 *				   coefficients need to be less than 2*Q.
 *
 * @param [in,out] v pointer to input/output vector
 */
static inline void polyveck_invntt_tomont(polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_invntt_tomont(&v->vec[i]);
}

static inline void polyveck_pointwise_poly_montgomery(polyveck *r,
						      const poly *a,
						      const polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
}

/**
 * @brief polyveck_chknorm - Check infinity norm of polynomials in vector of
 *			     length K. Assumes input polyveck to be reduced by
 *			     polyveck_reduce().
 *
 * @param [in] v pointer to vector
 * @param [in] B norm bound
 *
 * @return 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
 * and 1 otherwise.
 */
static inline int polyveck_chknorm(const polyveck *v, int32_t bound)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		if (poly_chknorm(&v->vec[i], bound))
			return 1;

	return 0;
}

/**
 * @brief polyveck_power2round - For all coefficients a of polynomials in vector
 *				 of length K, compute a0, a1 such that
 *				 a mod^+ Q = a1*2^D + a0 with
 *				 -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients
 *				 to be standard representatives.
 *
 * @param [out] v1 pointer to output vector of polynomials with coefficients a1
 * @param [in] v0 pointer to output vector of polynomials with coefficients a0
 * @param [in] v pointer to input vector
 */
static inline void polyveck_power2round(polyveck *v1, polyveck *v0,
					const polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_power2round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/**
 * @brief polyveck_decompose - For all coefficients a of polynomials in vector
 *			       of length K, compute high and low bits a0, a1
 *			       such a mod^+ Q = a1*ALPHA + a0 with
 *			       -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA
 *			       where we set a1 = 0 and
 *			       -ALPHA/2 <= a0 = a mod Q - Q < 0. Assumes
 *			       coefficients to be standard representatives.
 *
 * @param [out] v1 pointer to output vector of polynomials with coefficients a1
 * @param [in] v0 pointer to output vector of polynomials with coefficients a0
 * @param [in] v pointer to input vector
 */
static inline void polyveck_decompose(polyveck *v1, polyveck *v0,
				      const polyveck *v)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/**
 * @brief polyveck_make_hint - Compute hint vector.
 *
 * @param [out] h pointer to output vector
 * @param [in] v0 pointer to low part of input vector
 * @param [in] v1 pointer to high part of input vector
 *
 * @return number of 1 bits.
 */
static inline unsigned int polyveck_make_hint(polyveck *h, const polyveck *v0,
					      const polyveck *v1)
{
	unsigned int i, s = 0;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

	return s;
}

/**
 * @brief polyveck_use_hint - Use hint vector to correct the high bits of input
 *			      vector.
 *
 * @param [out] w pointer to output vector of polynomials with corrected high
 *		  bits
 * @param [in] u pointer to input vector
 * @param [in] h pointer to input hint vector
 */
static inline void polyveck_use_hint(polyveck *w, const polyveck *u,
				     const polyveck *h)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
}

static inline void
polyveck_pack_w1(uint8_t r[LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES],
		 const polyveck *w1)
{
	unsigned int i;

#pragma GCC unroll LC_DILITHIUM_K
	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyw1_pack(&r[i * LC_DILITHIUM_POLYW1_PACKEDBYTES],
			    &w1->vec[i]);
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLYVEC_H */
