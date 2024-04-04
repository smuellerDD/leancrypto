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

#ifndef DILITHIUM_POLYVEC_C_H
#define DILITHIUM_POLYVEC_C_H

#ifdef __cplusplus
extern "C" {
#endif

static inline void
polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
		     uint16_t nonce, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_uniform_eta(&v->vec[i], seed, le_bswap16(nonce++), ws_buf);
}

static inline void
polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			uint16_t nonce, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_uniform_gamma1(
			&v->vec[i], seed,
			le_bswap16((uint16_t)(LC_DILITHIUM_L * nonce + i)),
			ws_buf);
}

static inline void
polyveck_uniform_eta(polyveck *v, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
		     uint16_t nonce, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_uniform_eta(&v->vec[i], seed, le_bswap16(nonce++), ws_buf);
}

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

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		for (j = 0; j < LC_DILITHIUM_L; ++j)
			poly_uniform(
				&mat[i].vec[j], rho,
				le_bswap16((uint16_t)(i << 8) + (uint16_t)j),
				ws_buf);
}

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
	unsigned int i;
	poly *t = ws_buf;

	poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
	for (i = 1; i < LC_DILITHIUM_L; ++i) {
		poly_pointwise_montgomery(t, &u->vec[i], &v->vec[i]);
		poly_add(w, w, t);
	}
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

#endif /* DILITHIUM_POLYVEC_C_H */
