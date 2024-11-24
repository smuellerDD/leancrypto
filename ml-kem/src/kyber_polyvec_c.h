/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef KYBER_POLYVEC_C_H
#define KYBER_POLYVEC_C_H

#include "kyber_type.h"

#ifdef __cplusplus
extern "C" {
#endif

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

	poly_basemul_montgomery(r, &a->vec[0], &b->vec[0]);
	for (i = 1; i < LC_KYBER_K; i++) {
		poly_basemul_montgomery(t, &a->vec[i], &b->vec[i]);
		poly_add(r, r, t);
	}

	poly_reduce(r);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLYVEC_C_H */
