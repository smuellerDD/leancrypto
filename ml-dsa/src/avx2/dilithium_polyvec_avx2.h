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

#ifndef DILITHIUM_POLYVEC_AVX2_H
#define DILITHIUM_POLYVEC_AVX2_H

#include "dilithium_type.h"
#include "dilithium_poly_avx2.h"

#ifdef __cplusplus
extern "C" {
#endif

/**************************************************************/
/************ Vectors of polynomials of length L **************/
/**************************************************************/

/* Vectors of polynomials of length L */
typedef struct {
	poly vec[LC_DILITHIUM_L];
} polyvecl;

/**
 * @brief polyvecl_add_avx
 *
 * Add vectors of polynomials of length L. No modular reduction is performed.
 *
 * @param w pointer to output vector
 * @param u pointer to first summand
 * @param v pointer to second summand
 */
static inline void polyvecl_add_avx(polyvecl *w, const polyvecl *u,
				    const polyvecl *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_add_avx(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/**
 * @brief polyvecl_ntt_avx
 *
 * Forward NTT of all polynomials in vector of length L. Output coefficients
 * can be up to 16*Q larger than input coefficients.
 *
 * @param v pointer to input/output vector
 */
static inline void polyvecl_ntt_avx(polyvecl *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_ntt_avx(&v->vec[i]);
}

static inline void polyvecl_invntt_tomont_avx(polyvecl *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_invntt_tomont_avx(&v->vec[i]);
}

static inline void polyvecl_pointwise_poly_montgomery_avx(polyvecl *r,
							  const poly *a,
							  const polyvecl *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_pointwise_montgomery_avx(&r->vec[i], a, &v->vec[i]);
}

/**
 * @brief polyvecl_pointwise_acc_montgomery_avx
 *
 * Pointwise multiply vectors of polynomials of length L, multiply resulting
 * vector by 2^{-32} and add (accumulate) polynomials in it. Input/output
 * vectors are in NTT domain representation.
 *
 * @param w output polynomial
 * @param u pointer to first input vector
 * @param v pointer to second input vector
 */
static inline void polyvecl_pointwise_acc_montgomery_avx(poly *w,
							 const polyvecl *u,
							 const polyvecl *v)
{
	LC_FPU_ENABLE;
	dilithium_pointwise_acc_avx(w->vec, u->vec->vec, v->vec->vec,
				    dilithium_qdata.vec);
	LC_FPU_DISABLE;
}

/**
 * @brief polyvecl_chknorm_avx
 *
 * Check infinity norm of polynomials in vector of length L. Assumes input
 * polyvecl to be reduced by polyvecl_reduce().
 *
 * @param v pointer to vector
 * @param bound norm bound
 *
 * @return 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
 * and 1 otherwise.
 **************************************************/
static inline int polyvecl_chknorm_avx(const polyvecl *v, int32_t bound)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		if (poly_chknorm_avx(&v->vec[i], bound))
			return 1;

	return 0;
}

/**************************************************************/
/************ Vectors of polynomials of length K **************/
/**************************************************************/

/* Vectors of polynomials of length K */
typedef struct {
	poly vec[LC_DILITHIUM_K];
} polyveck;

/**
 * @brief polyveck_reduce_avx
 *
 * Reduce coefficients of polynomials in vector of length K to representatives
 * in [-6283009,6283007].
 *
 * @param v pointer to input/output vector
 */
static inline void polyveck_reduce_avx(polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_reduce_avx(&v->vec[i]);
}

/**
 * @brief polyveck_caddq_avx
 *
 * For all coefficients of polynomials in vector of length K add Q if
 * coefficient is negative.
 *
 * @param v pointer to input/output vector
 */
static inline void polyveck_caddq_avx(polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_caddq_avx(&v->vec[i]);
}

/**
 * @brief polyveck_add_avx
 *
 * Add vectors of polynomials of length K. No modular reduction is performed.
 *
 * @param w pointer to output vector
 * @param u pointer to first summand
 * @param v pointer to second summand
 */
static inline void polyveck_add_avx(polyveck *w, const polyveck *u,
				    const polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_add_avx(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/**
 * @brief polyveck_sub_avx
 *
 * Subtract vectors of polynomials of length K. No modular reduction is
 * performed.
 *
 * @param w pointer to output vector
 * @param u pointer to first input vector
 * @param v pointer to second input vector to be subtracted from first input
 * vector
 */
static inline void polyveck_sub_avx(polyveck *w, const polyveck *u,
				    const polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_sub_avx(&w->vec[i], &u->vec[i], &v->vec[i]);
}

/**
 * @brief polyveck_shiftl_avx
 *
 * Multiply vector of polynomials of Length K by 2^D without modular reduction.
 * Assumes input coefficients to be less than 2^{31-D}.
 *
 * @param v pointer to input/output vector
 */
static inline void polyveck_shiftl_avx(polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_shiftl_avx(&v->vec[i]);
}

/**
 * @brief polyveck_ntt_avx
 *
 * Forward NTT of all polynomials in vector of length K. Output coefficients
 * can be up to 16*Q larger than input coefficients.
 *
 * @param v pointer to input/output vector
 */
static inline void polyveck_ntt_avx(polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_ntt_avx(&v->vec[i]);
}

/**
 * @brief polyveck_invntt_tomont_avx
 *
 * Inverse NTT and multiplication by 2^{32} of polynomials in vector of length
 * K. Input coefficients need to be less than 2*Q.
 *
 * @param v pointer to input/output vector
 */
static inline void polyveck_invntt_tomont_avx(polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_invntt_tomont_avx(&v->vec[i]);
}

static inline void polyveck_pointwise_poly_montgomery_avx(polyveck *r,
							  const poly *a,
							  const polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_pointwise_montgomery_avx(&r->vec[i], a, &v->vec[i]);
}

/**
 * @brief polyveck_chknorm_avx
 *
 * Check infinity norm of polynomials in vector of length K. Assumes input
 * polyveck to be reduced by polyveck_reduce().
 *
 * @param v pointer to vector
 * @param bound norm bound
 *
 * @return 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
 * and 1 otherwise.
 */
static inline int polyveck_chknorm_avx(const polyveck *v, int32_t bound)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		if (poly_chknorm_avx(&v->vec[i], bound))
			return 1;

	return 0;
}

/**
 * @brief polyveck_power2round_avx
 *
 * For all coefficients a of polynomials in vector of length K, compute a0, a1
 * such that a mod^+ Q = a1*2^D + a0 with -2^{D-1} < a0 <= 2^{D-1}. Assumes
 * coefficients to be standard representatives.
 *
 * @param v1 pointer to output vector of polynomials with coefficients a1
 * @param v0 pointer to output vector of polynomials with coefficients a0
 * @param v pointer to input vector
 */
static inline void polyveck_power2round_avx(polyveck *v1, polyveck *v0,
					    const polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_power2round_avx(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/**
 * @brief polyveck_decompose_avx
 *
 * For all coefficients a of polynomials in vector of length K, compute high
 * and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0 with
 * -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we set a1 = 0 and
 * -ALPHA/2 <= a0 = a mod Q - Q < 0. Assumes coefficients to be standard
 * representatives.
 *
 * @param v1 pointer to output vector of polynomials with coefficients a1
 * @param v0 pointer to output vector of polynomials with coefficients a0
 * @param v pointer to input vector
 */
static inline void polyveck_decompose_avx(polyveck *v1, polyveck *v0,
					  const polyveck *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_decompose_avx(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

/**
 * @brief polyveck_make_hint_avx
 *
 * Compute hint vector.
 *
 * @param hint pointer to output hint array
 * @param v0 pointer to low part of input vector
 * @param v1 pointer to high part of input vector
 *
 * @return number of 1 bits.
 */
static inline unsigned int
polyveck_make_hint_avx(uint8_t *hint, const polyveck *v0, const polyveck *v1)
{
	unsigned int i, n = 0;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		n += poly_make_hint_avx(&hint[n], &v0->vec[i], &v1->vec[i]);

	return n;
}

/**
 * @brief polyveck_use_hint_avx
 *
 * Use hint vector to correct the high bits of input vector.
 *
 * @param w pointer to output vector of polynomials with corrected high bits
 * @param u pointer to input vector
 * @param h pointer to input hint vector
 */
static inline void polyveck_use_hint_avx(polyveck *w, const polyveck *u,
					 const polyveck *h)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_use_hint_avx(&w->vec[i], &u->vec[i], &h->vec[i]);
}

static inline void polyveck_pack_w1_avx(
	uint8_t r[LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES],
	const polyveck *w1)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyw1_pack_avx(&r[i * LC_DILITHIUM_POLYW1_PACKEDBYTES],
				&w1->vec[i]);
}

static inline void polyvec_matrix_pointwise_montgomery_avx(
	polyveck *t, const polyvecl mat[LC_DILITHIUM_K], const polyvecl *v)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyvecl_pointwise_acc_montgomery_avx(&t->vec[i], &mat[i], v);
}

void polyvec_matrix_expand(polyvecl mat[LC_DILITHIUM_K],
			   const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
			   void *ws_buf, void *ws_keccak, polyvecl *tmp);

void polyvec_matrix_expand_row0(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf, void *ws_keccak);
void polyvec_matrix_expand_row1(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf, void *ws_keccak);
void polyvec_matrix_expand_row2(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf, void *ws_keccak);
void polyvec_matrix_expand_row3(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf, void *ws_keccak);
void polyvec_matrix_expand_row4(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf, void *ws_keccak);
void polyvec_matrix_expand_row5(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf, void *ws_keccak);
void polyvec_matrix_expand_row6(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf, void *ws_keccak);
void polyvec_matrix_expand_row7(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf, void *ws_keccak);

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLYVEC_AVX2_H */
