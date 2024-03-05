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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef DILITHIUM_POLY_H
#define DILITHIUM_POLY_H

#include "dilithium_reduce.h"
#include "dilithium_rounding.h"
#include "ext_headers.h"

#include "lc_dilithium.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int32_t coeffs[LC_DILITHIUM_N];
} poly;

/**
 * @brief poly_add - Add polynomials. No modular reduction is performed.
 *
 * @param [out] c pointer to output polynomial
 * @param [in] a pointer to first summand
 * @param [in] b pointer to second summand
 */
static inline void poly_add(poly *c, const poly *a, const poly *b)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
}

/**
 * @brief poly_sub - Subtract polynomials. No modular reduction is
 *		     performed.
 *
 * @param [out] c pointer to output polynomial
 * @param [in] a pointer to first input polynomial
 * @param [in] b pointer to second input polynomial to be subtraced from first
 *		 input polynomial
 */
static inline void poly_sub(poly *c, const poly *a, const poly *b)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/**
 * @brief poly_shiftl - Multiply polynomial by 2^D without modular reduction.
 *			Assumes input coefficients to be less than 2^{31-D} in
 *			absolute value.
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_shiftl(poly *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		a->coeffs[i] <<= LC_DILITHIUM_D;
}

/**
 * @brief poly_decompose - For all coefficients c of the input polynomial,
 *			   compute high and low bits c0, c1 such
 *			   c mod Q = c1*ALPHA + c0 with
 *			   -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA
 *			   where we set c1 = 0 and
 *			   -ALPHA/2 <= c0 = c mod Q - Q < 0.
 *			   Assumes coefficients to be standard representatives.
 *
 * @param [out] a1 pointer to output polynomial with coefficients c1
 * @param [out] a0 pointer to output polynomial with coefficients c0
 * @param [in] a pointer to input polynomial
 */
static inline void poly_decompose(poly *a1, poly *a0, const poly *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
}

/**
 * @param poly_make_hint - Compute hint polynomial. The coefficients of which
 *			   indicate whether the low bits of the corresponding
 *			   coefficient of the input polynomial overflow into the
 *			   high bits.
 *
 * @param [out] h pointer to output hint polynomial
 * @param [in] a0 pointer to low part of input polynomial
 * @param [in] a1 pointer to high part of input polynomial
 *
 * @return number of 1 bits.
 */
static inline unsigned int poly_make_hint(poly *h, const poly *a0,
					  const poly *a1)
{
	unsigned int i, s = 0;

	for (i = 0; i < LC_DILITHIUM_N; ++i) {
		h->coeffs[i] = make_hint(a0->coeffs[i], a1->coeffs[i]);
		s += (unsigned int)h->coeffs[i];
	}

	return s;
}

/**
 * @brief poly_use_hint - Use hint polynomial to correct the high bits of a
 *			  polynomial.
 *
 * @param [out] b pointer to output polynomial with corrected high bits
 * @param [in] a pointer to input polynomial
 * @param [in] h pointer to input hint polynomial
 */
static inline void poly_use_hint(poly *b, const poly *a, const poly *h)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		b->coeffs[i] = use_hint(a->coeffs[i], h->coeffs[i]);
}

int poly_chknorm(const poly *a, int32_t B);

#define POLY_UNIFORM_NBLOCKS                                                   \
	((768 + LC_SHAKE_128_SIZE_BLOCK - 1) / LC_SHAKE_128_SIZE_BLOCK)
void poly_uniform(poly *a, const uint8_t seed[LC_DILITHIUM_SEEDBYTES],
		  uint16_t nonce, void *ws_buf);

#if LC_DILITHIUM_ETA == 2
#define POLY_UNIFORM_ETA_NBLOCKS                                               \
	((136 + LC_SHAKE_256_SIZE_BLOCK - 1) / LC_SHAKE_256_SIZE_BLOCK)
#elif LC_DILITHIUM_ETA == 4
#define POLY_UNIFORM_ETA_NBLOCKS                                               \
	((227 + LC_SHAKE_256_SIZE_BLOCK - 1) / LC_SHAKE_256_SIZE_BLOCK)
#else
#error "Undefined LC_DILITHIUM_ETA"
#endif
#define POLY_UNIFORM_ETA_BYTES POLY_UNIFORM_ETA_NBLOCKS *LC_SHAKE_256_SIZE_BLOCK
void poly_uniform_eta(poly *a, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
		      uint16_t nonce, void *ws_buf);

#define POLY_UNIFORM_GAMMA1_NBLOCKS                                            \
	((LC_DILITHIUM_POLYZ_PACKEDBYTES + LC_SHAKE_256_SIZE_BLOCK - 1) /      \
	 LC_SHAKE_256_SIZE_BLOCK)
#define POLY_UNIFORM_GAMMA1_BYTES                                              \
	POLY_UNIFORM_GAMMA1_NBLOCKS *LC_SHAKE_256_SIZE_BLOCK
void poly_uniform_gamma1(poly *a, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			 uint16_t nonce, void *ws_buf);

#define POLY_CHALLENGE_BYTES LC_SHAKE_256_SIZE_BLOCK
void poly_challenge(poly *c, const uint8_t seed[LC_DILITHIUM_SEEDBYTES],
		    void *ws_buf);

void polyeta_pack(uint8_t *r, const poly *a);
void polyeta_unpack(poly *r, const uint8_t *a);

void polyt1_pack(uint8_t *r, const poly *a);

void polyt0_pack(uint8_t *r, const poly *a);
void polyt0_unpack(poly *r, const uint8_t *a);

void polyz_pack(uint8_t *r, const poly *a);
void polyz_unpack(poly *r, const uint8_t *a);

void polyw1_pack(uint8_t *r, const poly *a);

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLY_H */
