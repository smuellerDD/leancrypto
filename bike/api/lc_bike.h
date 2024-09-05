/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/awslabs/bike-kem
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#ifndef LC_BIKE_H
#define LC_BIKE_H

#include "alignment.h"
#include "ext_headers.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT

/*******************************************************************************
 *             BIKE Parameters
 ******************************************************************************/
#define LC_BIKE_N0 2

#if !defined(LC_BIKE_LEVEL)
#define LC_BIKE_LEVEL 5
#endif

#if (LC_BIKE_LEVEL == 1)
// 64-bits of post-quantum security parameters (BIKE spec):
#define LC_BIKE_R_BITS 12323
#define LC_BIKE_D 71
#define LC_BIKE_T 134

#define LC_BIKE_THRESHOLD_COEFF0 1353000000ULL
#define LC_BIKE_THRESHOLD_COEFF1 697220ULL
#define LC_BIKE_THRESHOLD_MUL_CONST 12379400392853802749ULL
#define LC_BIKE_THRESHOLD_SHR_CONST 26
#define LC_BIKE_THRESHOLD_MIN 36

/*
 * When generating an error vector we can't use rejection sampling because of
 * constant-time requirements so we generate always the maximum number
 * of indices and then use only the first T valid indices, as explained in:
 * https://github.com/awslabs/bike-kem/blob/master/BIKE_Rejection_Sampling.pdf
 */
#define LC_BIKE_MAX_RAND_INDICES_T 271

// The gf2x code is optimized to a block in this case:
#define LC_BIKE_BLOCK_BITS 16384

#elif (LC_BIKE_LEVEL == 3)
#define LC_BIKE_R_BITS 24659
#define LC_BIKE_D 103
#define LC_BIKE_T 199

#define LC_BIKE_THRESHOLD_COEFF0 1525880000ULL
#define LC_BIKE_THRESHOLD_COEFF1 526500ULL
#define LC_BIKE_THRESHOLD_MUL_CONST 12379400392853802749ULL
#define LC_BIKE_THRESHOLD_SHR_CONST 26
#define LC_BIKE_THRESHOLD_MIN 52

#define LC_BIKE_MAX_RAND_INDICES_T 373

// The gf2m code is optimized to a block in this case:
#define LC_BIKE_BLOCK_BITS 32768

#elif (LC_BIKE_LEVEL == 5)
#define LC_BIKE_R_BITS 40973
#define LC_BIKE_D 137
#define LC_BIKE_T 264

#define LC_BIKE_THRESHOLD_COEFF0 1787850000ULL
#define LC_BIKE_THRESHOLD_COEFF1 402312ULL
#define LC_BIKE_THRESHOLD_MUL_CONST 12379400392853802749ULL
#define LC_BIKE_THRESHOLD_SHR_CONST 26
#define LC_BIKE_THRESHOLD_MIN 69

#define LC_BIKE_MAX_RAND_INDICES_T 605

#define LC_BIKE_BLOCK_BITS 65536
#else
#error "Bad level, choose one of 1/3/5"
#endif

// Round the size to the nearest byte.
#define LC_BIKE_DIVIDE_AND_CEIL(x, divider) (((x) + (divider) - 1) / (divider))
#define LC_BIKE_N_BITS (LC_BIKE_R_BITS * LC_BIKE_N0)
#define LC_BIKE_R_BYTES LC_BIKE_DIVIDE_AND_CEIL(LC_BIKE_R_BITS, 8)

#define LC_BIKE_M_BITS 256
#define LC_BIKE_M_BYTES (LC_BIKE_M_BITS / 8)

#define LC_BIKE_SS_BITS 256
#define LC_BIKE_SS_BYTES (LC_BIKE_SS_BITS / 8)

typedef uint32_t idx_t;

typedef struct compressed_idx_d_s {
	idx_t val[LC_BIKE_D];
} compressed_idx_d_t;

typedef compressed_idx_d_t compressed_idx_d_ar_t[LC_BIKE_N0];

typedef struct m_s {
	uint8_t raw[LC_BIKE_M_BYTES];
} m_t;

typedef struct r_s {
	uint8_t raw[LC_BIKE_R_BYTES];
} r_t;

/// \endcond

/**
 * @brief Bike public key
 */
struct lc_bike_pk {
	r_t pk;
};

/**
 * @brief Bike secret key
 */
struct lc_bike_sk {
	compressed_idx_d_ar_t wlist;
	r_t bin[LC_BIKE_N0];
	r_t pk;
	m_t sigma;
};

/**
 * @brief Bike ciphertext
 */
struct lc_bike_ct {
	r_t c0;
	m_t c1;
};

/**
 * @brief Bike shared secret
 */
struct lc_bike_ss {
	uint8_t ss[LC_BIKE_SS_BYTES];
};

/**
 * @brief Generates public and private key for IND-CCA2-secure BIKE key
 *	  encapsulation mechanism
 *
 * @param [out] pk pointer to already allocated output public key
 * @param [out] sk pointer to already allocated output private key
 * @param [in] rng_ctx pointer to seeded random number generator context
 *
 * @return 0 (success) or < 0 on error
 */
int lc_bike_keypair(struct lc_bike_pk *pk, struct lc_bike_sk *sk,
		    struct lc_rng_ctx *rng_ctx);

/**
 * @brief BIKE Key encapsulation
 *
 * Generates cipher text and shared secret for given public key.
 *
 * @param [out] ct pointer to output cipher text to used for decapsulation
 * @param [out] ss pointer to output shared secret that will be also produced
 *		   during decapsulation
 * @param [in] pk pointer to input public key
 *
 * Returns 0 (success) or < 0 on error
 */
int lc_bike_enc(struct lc_bike_ct *ct, struct lc_bike_ss *ss,
		const struct lc_bike_pk *pk);

/**
 * @brief BIKE Key decapsulation
 *
 * Generates shared secret for given cipher text and private key
 *
 * @param [out] ss pointer to output shared secret that is the same as produced
 *		   during encapsulation
 * @param [in] ct pointer to input cipher text generated during encapsulation
 * @param [in] sk pointer to input private key
 *
 * @return 0
 *
 * On failure, ss will contain a pseudo-random value.
 */
int lc_bike_dec(struct lc_bike_ss *ss, const struct lc_bike_ct *ct,
		const struct lc_bike_sk *sk);

#ifdef __cplusplus
}
#endif

#endif /* LC_BIKE_H */
