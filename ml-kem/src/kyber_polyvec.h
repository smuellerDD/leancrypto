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

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLYVEC_H */
