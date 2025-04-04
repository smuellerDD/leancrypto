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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_POLYVEC_H
#define KYBER_POLYVEC_H

#include "kyber_type.h"
#include "kyber_poly_avx2.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	poly vec[LC_KYBER_K];
} polyvec;

/**
 * @brief polyvec_compress - Compress and serialize vector of polynomials
 *
 * @param [out] r pointer to output byte array
 * @param [in] a pointer to input vector of polynomials
 */
void polyvec_compress(uint8_t r[LC_KYBER_POLYVECCOMPRESSEDBYTES],
		      const polyvec *a);

/**
 * @brief polyvec_decompress - De-serialize and decompress vector of
 *			       polynomials; approximate inverse of
 *			       polyvec_compress
 *
 * @param [out] r pointer to output vector of polynomials
 * @param [in] a pointer to input byte array
 */
void polyvec_decompress(polyvec *r,
			const uint8_t a[LC_KYBER_POLYVECCOMPRESSEDBYTES]);

/**
 * @brief polyvec_tobytes - Serialize vector of polynomials
 *
 * @param [out] r pointer to output byte array
 * @param [in] a pointer to input vector of polynomials
 */
static inline void polyvec_tobytes(uint8_t r[LC_KYBER_POLYVECBYTES],
				   const polyvec *a)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		poly_tobytes_avx(r + i * LC_KYBER_POLYBYTES, &a->vec[i]);
}

/**
 * @brief polyvec_frombytes - De-serialize vector of polynomials;
 *			      inverse of polyvec_tobytes
 *
 * @param [out] r pointer to output byte array
 * @param [in] a pointer to input vector of polynomials
 */
static inline void polyvec_frombytes(polyvec *r,
				     const uint8_t a[LC_KYBER_POLYVECBYTES])
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		poly_frombytes_avx(&r->vec[i], a + i * LC_KYBER_POLYBYTES);
}

/**
 * @brief polyvec_ntt - Apply forward NTT to all elements of a vector of
 *			polynomials
 *
 * @param [in,out] r pointer to in/output vector of polynomials
 */
static inline void polyvec_ntt(polyvec *r)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		poly_ntt_avx(&r->vec[i]);
}

/**
 * @brief polyvec_invntt_tomont - Apply inverse NTT to all elements of a vector
 *				  of polynomials and multiply by Montgomery
 *				  factor 2^16
 *
 * @param [in,out] r pointer to in/output vector of polynomials
 */
static inline void polyvec_invntt_tomont(polyvec *r)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		poly_invntt_tomont_avx(&r->vec[i]);
}

/**
 * @brief polyvec_basemul_acc_montgomery - Multiply elements of a and b in NTT
 *					   domain, accumulate into r,
 *					   and multiply by 2^-16.
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a pointer to first input vector of polynomials
 * @param [in] b pointer to second input vector of polynomials
 */
static inline void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a,
						  const polyvec *b,
						  void *ws_buf)
{
	unsigned int i;
	poly *t = (poly *)ws_buf;

	poly_basemul_montgomery_avx(r, &a->vec[0], &b->vec[0]);
	for (i = 1; i < LC_KYBER_K; i++) {
		poly_basemul_montgomery_avx(t, &a->vec[i], &b->vec[i]);
		kyber_poly_add_avx(r, r, t);
	}

	poly_reduce_avx(r);
}

/**
 * @brief polyvec_reduce - Applies Barrett reduction to each coefficient
 *			   of each element of a vector of polynomials;
 *			   for details of the Barrett reduction see comments in
 *			   kyber_reduce.c
 *
 * @param [in,out] r pointer to input/output polynomial
 */
static inline void polyvec_reduce(polyvec *r)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		poly_reduce_avx(&r->vec[i]);
}

/**
 * @brief polyvec_add - Add vectors of polynomials
 *
 * @param [out] r pointer to output vector of polynomials
 * @param [in] a pointer to first input vector of polynomials
 * @param [in] b pointer to second input vector of polynomials
 */
static inline void polyvec_add(polyvec *r, const polyvec *a, const polyvec *b)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		kyber_poly_add_avx(&r->vec[i], &a->vec[i], &b->vec[i]);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLYVEC_H */
