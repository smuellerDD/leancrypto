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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef DILITHIUM_POLYVEC_H
#define DILITHIUM_POLYVEC_H

#include "conv_be_le.h"
#include "dilithium_type.h"
#include "dilithium_poly.h"

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

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_ntt(&v->vec[i]);
}

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

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

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_ntt(&v->vec[i]);
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

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);

	return s;
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLYVEC_H */
