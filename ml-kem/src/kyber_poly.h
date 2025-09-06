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

#ifndef KYBER_POLY_H
#define KYBER_POLY_H

#include "kyber_type.h"
#include "kyber_ntt.h"
#include "kyber_reduce.h"
#include "null_buffer.h"

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
 * @brief basemul - Multiplication of polynomials in Zq[X]/(X^2-zeta)
 *		    used for multiplication of elements in Rq in NTT domain
 *
 * @param [out] r pointer to the output polynomial
 * @param [in] a pointer to the first factor
 * @param [in] b  pointer to the second factor
 * @param [in] zeta integer defining the reduction polynomial
 */
void basemul(int16_t r[2], const int16_t a[2], const int16_t b[2],
	     int16_t zeta);

#ifdef LC_HOST_ARM32_NEON
#include "armv7/kyber_poly_armv7.h"
#elif (!defined(LC_KYBER_POLY_C_NOT_INCLUDE))
#include "kyber_poly_c.h"
#endif

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
static inline void poly_tobytes(uint8_t r[LC_KYBER_POLYBYTES], const poly *a)
{
	unsigned int i;
	uint16_t t0, t1;

	for (i = 0; i < LC_KYBER_N / 2; i++) {
		// map to positive standard representatives
		t0 = (uint16_t)a->coeffs[2 * i];
		t0 += ((int16_t)t0 >> 15) & LC_KYBER_Q;
		t1 = (uint16_t)a->coeffs[2 * i + 1];
		t1 += ((int16_t)t1 >> 15) & LC_KYBER_Q;
		r[3 * i + 0] = (uint8_t)(t0 >> 0);
		r[3 * i + 1] = (uint8_t)((t0 >> 8) | (t1 << 4));
		r[3 * i + 2] = (uint8_t)(t1 >> 4);
	}
}

#include "common/kyber_poly_frommsg.h"
#include "common/kyber_poly_tomsg.h"

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
int poly_getnoise_eta1(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
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
int poly_getnoise_eta2(poly *r, const uint8_t seed[LC_KYBER_SYMBYTES],
		       uint8_t nonce, void *ws_buf);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_H */
