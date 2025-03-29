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
 * https://github.com/psanal2018/kyber-arm64
 *
 * That code is released under MIT license.
 */

#ifndef KYBER_POLYVEC_ARMV8_H
#define KYBER_POLYVEC_ARMV8_H

#include "kyber_type.h"

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

#include "common/kyber_polyvec_tobytes.h"
#include "common/kyber_polyvec_frombytes.h"
#include "common/kyber_polyvec_ntt.h"
#include "common/kyber_polyvec_invntt.h"
#include "common/kyber_polyvec_reduce.h"
#include "common/kyber_polyvec_add.h"

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
						  const polyvec *b)
{
	unsigned int i;
	poly t;

	poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
	for (i = 1; i < LC_KYBER_K; i++) {
		poly_basemul_montgomery(&t, &a->vec[i], &b->vec[i]);
		poly_add(r, r, &t);
	}

	poly_reduce(r);
}

/**
 * @brief polyvec_add_reduce - Combination of
 *				polyvec_add(r, a, b);
 *				polyvec_reduce(r);
 *
 * @param [out] r pointer to output vector of polynomials
 * @param [in] a pointer to first input vector of polynomials
 * @param [in] b pointer to second input vector of polynomials
 */
static inline void polyvec_add_reduce(polyvec *r, const polyvec *a,
				      const polyvec *b)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_K; i++)
		poly_add_reduce(&r->vec[i], &a->vec[i], &b->vec[i]);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLYVEC_ARMV8_H */
