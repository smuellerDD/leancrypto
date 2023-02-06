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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/psanal2018/kyber-arm64
 *
 * That code is released under MIT license.
 */

#ifndef KYBER_POLY_ARMV8_H
#define KYBER_POLY_ARMV8_H

#include "kyber_cbd_armv8.h"
#include "kyber_kdf.h"
#include "kyber_ntt_armv8.h"
#include "kyber_reduce_armv8.h"

#include "lc_kyber.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * Elements of R_q = Z_q[X]/(X^n + 1). Represents polynomial
 * coeffs[0] + X*coeffs[1] + X^2*coeffs[2] + ... + X^{n-1}*coeffs[n-1]
 */
typedef struct{
	int16_t coeffs[LC_KYBER_N];
} poly;

void kyber_add_armv8(int16_t *r, const int16_t *a, const int16_t *b);

/*
 * TODO: remove this code once poly_reduce has been fixed
 */
#include "kyber_reduce.h"
static inline void poly_reduce_c_bugfix(poly *r)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_N; i++)
		r->coeffs[i] = barrett_reduce(r->coeffs[i]);
}

/**
 * @brief poly_reduce - Applies Barrett reduction to all coefficients of a
 *			polynomial for details of the Barrett reduction see
 *			comments in kyber_reduce.c
 *
 * @param r [in/out] pointer to input/output polynomial
 */
static inline void poly_reduce(poly *r)
{
	kyber_barret_red_armv8(r->coeffs);
	kyber_barret_red_armv8(r->coeffs + 128);
}

/**
 * @brief poly_add - Add two polynomials; no modular reduction is performed
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] pointer to first input polynomial
 * @param b [in] pointer to second input polynomial
 */
static inline void poly_add(poly *r, const poly *a, const poly *b)
{
	kyber_add_armv8(r->coeffs, a->coeffs, b->coeffs);
}

/**
 * @brief poly_sub - Subtract two polynomials; no modular reduction is performed
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] pointer to first input polynomial
 * @param b [in] pointer to second input polynomial
 */
static inline void poly_sub(poly *r, const poly *a, const poly *b)
{
	unsigned int i;

	for (i = 0; i < LC_KYBER_N; i++)
		r->coeffs[i] = a->coeffs[i] - b->coeffs[i];
}

/**
 * @brief poly_sub_reduce - Combination of
 *				poly_sub(r, a, b);
 *				poly_reduce(r);
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] pointer to first input polynomial
 * @param b [in] pointer to second input polynomial
 */
static inline void poly_sub_reduce(poly *r, const poly *a, const poly *b)
{
	kyber_sub_reduce_armv8(r->coeffs, a->coeffs, b->coeffs);
	kyber_sub_reduce_armv8(r->coeffs + 128, a->coeffs + 128,
			       b->coeffs + 128);
}


/**
 * @brief poly_add_reduce - Combination of
 *				poly_add(r, a, b);
 *				poly_reduce(r);
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] pointer to first input polynomial
 * @param b [in] pointer to second input polynomial
 */
static inline void poly_add_reduce(poly *r, const poly *a, const poly *b)
{
	kyber_add_reduce_armv8(r->coeffs, a->coeffs, b->coeffs);
	kyber_add_reduce_armv8(r->coeffs + 128, a->coeffs + 128,
			       b->coeffs + 128);
}

/**
 * @brief poly_add_add_reduce - Combination of
 *				poly_add(r, a, b);
 *				poly_add(r, r, c);
 *				poly_reduce(r);
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] pointer to first input polynomial
 * @param b [in] pointer to second input polynomial
 * @param c [in] pointer to third input polynomial
 */
static inline void
poly_add_add_reduce(poly *r, const poly *a, const poly *b, const poly *c)
{
	kyber_add_add_reduce_armv8(r->coeffs, a->coeffs, b->coeffs, c->coeffs);
	kyber_add_add_reduce_armv8(r->coeffs + 128, a->coeffs + 128,
				   b->coeffs + 128, c->coeffs + 128);
}

/**
 * @brief poly_compress_armv8 - Compression and subsequent serialization of a
 *			 	polynomial
 *
 * @param r [out] pointer to output byte array
 * @param a [in] pointer to input polynomial
 */
void poly_compress_armv8(uint8_t r[LC_KYBER_POLYCOMPRESSEDBYTES],
			 const poly *a);

/**
 * @brief poly_decompress_armv8 - De-serialization and subsequent decompression
 *				  of a polynomial;
 *			    	  approximate inverse of poly_compress
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] pointer to input byte array
 */
void poly_decompress_armv8(poly *r,
			   const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES]);

void kyber_poly_tobytes_armv8(uint8_t r[LC_KYBER_POLYBYTES], const poly *a);
void kyber_poly_frombytes_armv8(poly *r, const uint8_t a[LC_KYBER_POLYBYTES]);

/**
 * @brief poly_tobytes - Serialization of a polynomial
 *
 * @param r [out] pointer to output byte array
 * @param a [in] pointer to input polynomial
 */
static inline void poly_tobytes(uint8_t r[LC_KYBER_POLYBYTES], const poly *a)
{
	kyber_poly_tobytes_armv8(r, a);
}

/**
 * @brief poly_frombytes - De-serialization of a polynomial;
 *			   inverse of poly_tobytes
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] pointer to input byte array
 */
static inline void poly_frombytes(poly *r, const uint8_t a[LC_KYBER_POLYBYTES])
{
	kyber_poly_frombytes_armv8(r, a);
}

/**
 * @brief poly_frommsg - Convert 32-byte message to polynomial
 *
 * @param r [out] pointer to output polynomial
 * @param msg [in] pointer to input message
 */
static inline void poly_frommsg(poly *r,
				const uint8_t msg[LC_KYBER_INDCPA_MSGBYTES])
{
	unsigned int i,j;
	int16_t mask;

#if (LC_KYBER_INDCPA_MSGBYTES != LC_KYBER_N / 8)
#error "LC_KYBER_INDCPA_MSGBYTES must be equal to LC_KYBER_N/8 bytes!"
#endif

	for (i = 0; i < LC_KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++) {
			mask = -(int16_t)((msg[i] >> j) & 1);
			r->coeffs[8*i+j] = mask & ((LC_KYBER_Q + 1) / 2);
		}
	}
}

/**
 * @brief poly_tomsg - Convert polynomial to 32-byte message
 *
 * @param msg [out] pointer to output message
 * @param a [in] pointer to input polynomial
 */
static inline void poly_tomsg(uint8_t msg[LC_KYBER_INDCPA_MSGBYTES],
			      const poly *a)
{
	unsigned int i,j;
	uint16_t t;

	for (i = 0; i < LC_KYBER_N / 8; i++) {
		msg[i] = 0;
		for (j = 0;j < 8; j++) {
			t  = (uint16_t)a->coeffs[8*i+j];
			t += ((int16_t)t >> 15) & LC_KYBER_Q;
			t  = (((t << 1) + LC_KYBER_Q / 2) / LC_KYBER_Q) & 1;
			msg[i] |= (uint8_t)(t << j);
		}
	}
}

#define POLY_GETNOISE_ETA1_BUFSIZE	(LC_KYBER_ETA1 * LC_KYBER_N / 4)
static inline void
kyber_poly_cbd_eta1_armv8(poly *r,
			  const uint8_t buf[POLY_GETNOISE_ETA1_BUFSIZE])
{
#if LC_KYBER_ETA1 == 2
	kyber_cbd2_armv8(r->coeffs, buf);
#elif LC_KYBER_ETA1 == 3
	kyber_cbd3_armv8(r->coeffs, buf);
#else
#error "This implementation requires eta1 in {2,3}"
#endif
}

/**
 * @brief poly_getnoise_eta1 - Sample a polynomial deterministically from a seed
 *			       and a nonce, with output polynomial close to
 *			       centered binomial distribution with parameter
 *			       LC_KYBER_ETA1
 *
 * @param r [out] pointer to output polynomial
 * @param seed [in] pointer to input seed
 * @param nonce [in] one-byte input nonce
 */
static inline void
poly_getnoise_eta1_armv8(poly *r,
			 const uint8_t seed[LC_KYBER_SYMBYTES], uint8_t nonce,
			 void *ws_buf)
{
	uint8_t *buf = ws_buf;

	kyber_shake256_prf(buf, POLY_GETNOISE_ETA1_BUFSIZE, seed, nonce);
	kyber_poly_cbd_eta1_armv8(r, buf);
}

static inline void
kyber_poly_cbd_eta2_armv8(poly *r,
			  const uint8_t buf[LC_KYBER_ETA2 * LC_KYBER_N / 4])
{
#if LC_KYBER_ETA2 == 2
	kyber_cbd2_armv8(r->coeffs, buf);
#else
#error "This implementation requires eta2 = 2"
#endif
}

/**
 * @brief poly_getnoise_eta2 - Sample a polynomial deterministically from a seed
 *			       and a nonce, with output polynomial close to
 *			       centered binomial distribution with parameter
 *			       LC_KYBER_ETA2
 *
 * @param r [out] pointer to output polynomial
 * @param seed [in] pointer to input seed
 * @param nonce [in] one-byte input nonce
 */
#define POLY_GETNOISE_ETA2_BUFSIZE	(LC_KYBER_ETA2 * LC_KYBER_N / 4)
static inline void
poly_getnoise_eta2_armv8(poly *r,
			 const uint8_t seed[LC_KYBER_SYMBYTES], uint8_t nonce,
			 void *ws_buf)
{
	uint8_t *buf = ws_buf;

	kyber_shake256_prf(buf, POLY_GETNOISE_ETA2_BUFSIZE, seed, nonce);
	kyber_poly_cbd_eta2_armv8(r, buf);
}

/**
 * @brief poly_ntt - Computes negacyclic number-theoretic transform (NTT) of
 *		     a polynomial in place; inputs assumed to be in normal
 *		     order, output in bitreversed order
 *
 * @param r [in/out] pointer to in/output polynomial
 */
static inline void poly_ntt(poly *r)
{
	kyber_ntt_armv8(r->coeffs, kyber_zetas_armv8);

	/*
	 * TODO: the poly_reduce() here somehow calculates a different
	 * result compared to the poly_reduce() from kyber_poly.h (i.e. the
	 * C implementation). This leads sometimes to a different SK (e.g.
	 * test vector 21 in tests/kyber_kem_tester_armv8.c shows that the
	 * 1087th and 1088th byte is different compared to the expected result).
	 * Yet, the calculated ciphertext or shared secret are identical to
	 * the expected values, even with the different SK. Strange.
	 *
	 * Yet, we cannot use the ARMv8 poly_reduce() until this has been
	 * corrected. Instead we simply use the C implementation from
	 * kyber_poly.h for the time being.
	 */
	//poly_reduce(r);
	poly_reduce_c_bugfix(r);

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
	kyber_inv_ntt_armv8(r->coeffs, kyber_zetas_inv_armv8);
}

/**
 * @brief poly_basemul_montgomery - Multiplication of two polynomials in NTT
 *				    domain
 *
 * @param r [out] pointer to output polynomial
 * @param a [in] pointer to first input polynomial
 * @param b [in] pointer to second input polynomial
 */
static inline void poly_basemul_montgomery(poly *r, const poly *a,
					   const poly *b)
{
	kyber_basemul_armv8(r->coeffs, a->coeffs, b->coeffs, zetas_armv8);
}

/**
 * @brief poly_tomont - Inplace conversion of all coefficients of a polynomial
 *			from normal domain to Montgomery domain
 *
 * @param r [in/out] pointer to input/output polynomial
 */
static inline void poly_tomont(poly *r)
{
	kyber_tomont_armv8(r->coeffs);
	kyber_tomont_armv8(r->coeffs + 128);
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_ARMV8_H */
