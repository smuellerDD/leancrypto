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

#ifndef DILITHIUM_POLYVEC_ARMV8_H
#define DILITHIUM_POLYVEC_ARMV8_H

#include "lc_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LC_DILITHIUM_QINV
#define LC_DILITHIUM_QINV 58728449 // q^(-1) mod 2^32
#endif

static const int32_t l_montgomery_const[2] = { LC_DILITHIUM_Q,
					       LC_DILITHIUM_QINV };

/**
 * @brief expand_mat - Implementation of ExpandA. Generates matrix A with
 *		       uniformly random coefficients a_{i,j} by performing
 *		       rejection sampling on the output stream of
 *		       SHAKE128(rho|j|i).
 *
 * @param [out] mat output matrix
 * @param [in] rho byte array containing seed rho
 */
static inline void
polyvec_matrix_expand(polyvecl mat[LC_DILITHIUM_K],
		      const uint8_t rho[LC_DILITHIUM_SEEDBYTES], void *ws_buf)
{
	unsigned int i, j;

	(void)ws_buf;

	for (j = 0; j < LC_DILITHIUM_L; ++j) {
		for (i = 0; i < LC_DILITHIUM_K; i += 2) {
			poly_uniformx2(&mat[i + 0].vec[j], &mat[i + 1].vec[j],
				       rho, (uint16_t)((i << 8) + j),
				       (uint16_t)(((i + 1) << 8) + j));
		}
	}
}

static inline void
polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			uint16_t nonce, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L - 1; i += 2) {
		poly_uniform_gamma1x2(
			&v->vec[i + 0], &v->vec[i + 1], seed,
			(uint16_t)(LC_DILITHIUM_L * nonce + i + 0),
			(uint16_t)(LC_DILITHIUM_L * nonce + i + 1));
	}
	if (LC_DILITHIUM_L & 1) {
		poly_uniform_gamma1(
			&v->vec[i], seed,
			(uint16_t)(LC_DILITHIUM_L * nonce + LC_DILITHIUM_L - 1),
			ws_buf);
	}
}

extern void polyvecl_pointwise_acc_montgomery_armv8(int32_t *, const int32_t *,
						    const int32_t *,
						    const int32_t *);
/**
 * @brief polyvecl_pointwise_acc_montgomery -
 *	  Pointwise multiply vectors of polynomials of length L, multiply
 *	  resulting vector by 2^{-32} and add (accumulate) polynomials
 *	  in it. Input/output vectors are in NTT domain representation.
 *
 * @param [out] w output polynomial
 * @param [in] u pointer to first input vector
 * @param [in] v pointer to second input vector
 */
static inline void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u,
						     const polyvecl *v,
						     void *ws_buf)
{
	(void)ws_buf;

	polyvecl_pointwise_acc_montgomery_armv8(w->coeffs, u->vec[0].coeffs,
						v->vec[0].coeffs,
						l_montgomery_const);
}

static inline void
polyvec_matrix_pointwise_montgomery(polyveck *t,
				    const polyvecl mat[LC_DILITHIUM_K],
				    const polyvecl *v, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v,
						  ws_buf);
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLYVEC_ARMV8_H */
