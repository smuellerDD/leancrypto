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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include "kyber_ntt.h"
#include "kyber_reduce.h"

#include "lc_kyber.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct {
	int16_t coeffs[LC_KYBER_N];
} poly;

/**
 * @brief poly_reduce - Applies Barrett reduction to all coefficients of a
 *			polynomial for details of the Barrett reduction see
 *			comments in kyber_reduce.c
 *
 * @param r [in/out] pointer to input/output polynomial
 */
static inline void poly_reduce(poly *r)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_N; i++)
		r->coeffs[i] = barrett_reduce(r->coeffs[i]);
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
	unsigned int i;

	for (i = 0; i < LC_KYBER_N; i++)
		r->coeffs[i] = a->coeffs[i] + b->coeffs[i];
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
	unsigned int i;

	for (i = 0; i < LC_KYBER_N; i++)
		r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/**
 * @brief poly_compress - Compression and subsequent serialization of a
 *			  polynomial
 *
 * @param [out] r pointer to output byte array
 * @param [in] a pointer to input polynomial
 */
void poly_compress(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES], const poly *a);

/**
 * @brief poly_decompress - De-serialization and subsequent decompression of a
 *			    polynomial;
 *			    approximate inverse of poly_compress
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a pointer to input byte array
 */
void poly_decompress(poly *r, const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES]);

/**
 * @brief poly_tobytes - Serialization of a polynomial
 *
 * @param [out] r pointer to output byte array
 * @param [in] a pointer to input polynomial
 */
void poly_tobytes(uint8_t r[LC_KYBER_POLYBYTES], const poly *a);

/**
 * @brief poly_frombytes - De-serialization of a polynomial;
 *			   inverse of poly_tobytes
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a pointer to input byte array
 */
static inline void poly_frombytes(poly *r, const uint8_t a[LC_KYBER_POLYBYTES])
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_N / 2; i++) {
		r->coeffs[2 * i] =
			((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) &
			0xFFF;
		r->coeffs[2 * i + 1] =
			((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) &
			0xFFF;
	}
}

/**
 * @brief poly_frommsg - Convert 32-byte message to polynomial
 *
 * @param [out] r pointer to output polynomial
 * @param [in] msg pointer to input message
 */
static inline void poly_frommsg(poly *r,
				const uint8_t msg[LC_KYBER_INDCPA_MSGBYTES])
{
	unsigned int i, j;
	int16_t mask;

#if (LC_KYBER_INDCPA_MSGBYTES != LC_KYBER_N / 8)
#error "LC_KYBER_INDCPA_MSGBYTES must be equal to LC_KYBER_N/8 bytes!"
#endif

	for (i = 0; i < LC_KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++) {
			mask = -(int16_t)((msg[i] >> j) & 1);
			r->coeffs[8 * i + j] = mask & ((LC_KYBER_Q + 1) / 2);
		}
	}
}

/**
 * @brief poly_tomsg - Convert polynomial to 32-byte message
 *
 * @param [out] msg pointer to output message
 * @param [in] a pointer to input polynomial
 */
static inline void poly_tomsg(uint8_t msg[LC_KYBER_INDCPA_MSGBYTES],
			      const poly *a)
{
	unsigned int i, j;
	uint16_t t;

	for (i = 0; i < LC_KYBER_N / 8; i++) {
		msg[i] = 0;
		for (j = 0; j < 8; j++) {
			t = (uint16_t)a->coeffs[8 * i + j];
			t += ((int16_t)t >> 15) & LC_KYBER_Q;
			t = (((t << 1) + LC_KYBER_Q / 2) / LC_KYBER_Q) & 1;
			msg[i] |= (uint8_t)(t << j);
		}
	}
}

/**
 * @brief poly_getnoise_eta1 - Sample a polynomial deterministically from a seed
 *			       and a nonce, with output polynomial close to
 *			       centered binomial distribution with parameter
 *			       LC_KYBER_ETA1
 *
 * @param [out] r pointer to output polynomial
 * @param [in] seed pointer to input seed
 * @param [in] nonce one-byte input nonce
 */
#define POLY_GETNOISE_ETA1_BUFSIZE (LC_KYBER_ETA1 * LC_KYBER_N / 4)
void poly_getnoise_eta1(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
			uint8_t nonce, void *ws_buf);

/**
 * @brief poly_getnoise_eta2 - Sample a polynomial deterministically from a seed
 *			       and a nonce, with output polynomial close to
 *			       centered binomial distribution with parameter
 *			       LC_KYBER_ETA2
 *
 * @param [out] r pointer to output polynomial
 * @param [in] seed pointer to input seed
 * @param [in] nonce one-byte input nonce
 */
#define POLY_GETNOISE_ETA2_BUFSIZE (LC_KYBER_ETA2 * LC_KYBER_N / 4)
void poly_getnoise_eta2(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
			uint8_t nonce, void *ws_buf);

/**
 * @brief poly_ntt - Computes negacyclic number-theoretic transform (NTT) of
 *		     a polynomial in place; inputs assumed to be in normal
 *		     order, output in bitreversed order
 *
 * @param r [in/out] pointer to in/output polynomial
 */
static inline void poly_ntt(poly *r)
{
	kyber_ntt(r->coeffs);
	poly_reduce(r);
}

/**
 * @brief poly_invntt_tomont - Computes inverse of negacyclic number-theoretic
 *			       transform (NTT) of a polynomial in place;
 *			       inputs assumed to be in bitreversed order, output
 *			       in normal order
 *
 * @param r [in/out] pointer to in/output polynomial
 */
static inline void poly_invntt_tomont(poly *r)
{
	kyber_invntt(r->coeffs);
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
	unsigned int i;

	for (i = 0; i < LC_KYBER_N / 4; i++) {
		basemul(&r->coeffs[4 * i], &a->coeffs[4 * i], &b->coeffs[4 * i],
			zetas[64 + i]);
		basemul(&r->coeffs[4 * i + 2], &a->coeffs[4 * i + 2],
			&b->coeffs[4 * i + 2], -zetas[64 + i]);
	}
}

/**
 * @brief poly_tomont - Inplace conversion of all coefficients of a polynomial
 *			from normal domain to Montgomery domain
 *
 * @param r [in/out] pointer to input/output polynomial
 */
static inline void poly_tomont(poly *r)
{
	unsigned int i;
	const int16_t f = (1ULL << 32) % LC_KYBER_Q;

	for (i = 0; i < LC_KYBER_N; i++)
		r->coeffs[i] = montgomery_reduce((int32_t)r->coeffs[i] * f);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_H */
