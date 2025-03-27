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
static inline void
poly_decompress(poly *r, const uint8_t a[LC_KYBER_POLYCOMPRESSEDBYTES])
{
	unsigned int i;

#if (LC_KYBER_POLYCOMPRESSEDBYTES == 128)
	for (i = 0; i < LC_KYBER_N / 2; i++) {
		r->coeffs[2 * i + 0] =
			(int16_t)((((uint16_t)(a[0] & 15) * LC_KYBER_Q) + 8) >>
				  4);
		r->coeffs[2 * i + 1] =
			(int16_t)((((uint16_t)(a[0] >> 4) * LC_KYBER_Q) + 8) >>
				  4);
		a += 1;
	}
#elif (LC_KYBER_POLYCOMPRESSEDBYTES == 160)
	unsigned int j;
	uint8_t t[8];
	for (i = 0; i < LC_KYBER_N / 8; i++) {
		t[0] = (uint8_t)(a[0] >> 0);
		t[1] = (uint8_t)((a[0] >> 5) | (a[1] << 3));
		t[2] = (uint8_t)(a[1] >> 2);
		t[3] = (uint8_t)((a[1] >> 7) | (a[2] << 1));
		t[4] = (uint8_t)((a[2] >> 4) | (a[3] << 4));
		t[5] = (uint8_t)(a[3] >> 1);
		t[6] = (uint8_t)((a[3] >> 6) | (a[4] << 2));
		t[7] = (uint8_t)(a[4] >> 3);
		a += 5;

		for (j = 0; j < 8; j++)
			r->coeffs[8 * i + j] =
				(int16_t)(((uint32_t)(t[j] & 31) * LC_KYBER_Q +
					   16) >>
					  5);
	}
#else
#error "LC_KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}"
#endif
}

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
	int16_t mask, opt_blocker;

	/*
	 * Goal: copy variable only depending on a given condition without
	 * the use of a branching operation which alters the timing behavior
	 * depending on the condition. As the condition here depends on
	 * secret data (the msg variable), the code has to ensure that no
	 * branching is used to have time-invariant code. This solution
	 * below also shall ensure that the compiler cannot optimize this code
	 * such that it brings back the branching.
	 *
	 * An exploit of the timing channel that would be present with a
	 * branching operation is available at
	 * https://github.com/antoonpurnal/clangover which reportedly
	 * needs <10 minutes for ML-KEM 512 key recovery. More details about
	 * the exploit is given in https://pqshield.com/pqshield-plugs-timing-leaks-in-kyber-ml-kem-to-improve-pqc-implementation-maturity/
	 *
	 * (mask ^ opt_blocker) can be any value at run-time to the compiler,
	 * making it impossible to skip the computation (except the compiler
	 * would care to create a branch for opt_blocker to be either
	 * 0 or -1, which would be extremely unlikely). Yet the volatile
	 * variable has to be loaded only once at the beginning of the function
	 * call.
	 */
	opt_blocker = optimization_blocker_int16;

#if (LC_KYBER_INDCPA_MSGBYTES != LC_KYBER_N / 8)
#error "LC_KYBER_INDCPA_MSGBYTES must be equal to LC_KYBER_N/8 bytes!"
#endif

	for (i = 0; i < LC_KYBER_N / 8; i++) {
		for (j = 0; j < 8; j++) {
			/*
			 * Calculate condition when a variable shall be
			 * copied. This depends on the secret msg. The mask is
			 * either zero or all bits are 1.
			 */
			mask = -(int16_t)((msg[i] >> j) & 1);

			/*
			 * XOR the mask with a zero value which is obtained from
			 * a volatile variable to ensure the compiler cannot
			 * turn this into a branching operation. This does not
			 * alter the mask, but is intended to prevent the
			 * compiler to be clever and add a branching instruction
			 * instead.
			 *
			 * See https://microblog.cr.yp.to/1713627640/ for
			 * an analysis.
			 */
			r->coeffs[8 * i + j] =
				(mask ^ opt_blocker) & ((LC_KYBER_Q + 1) / 2);
		}
	}
}

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

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_H */
