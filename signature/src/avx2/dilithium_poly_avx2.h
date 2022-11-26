/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#ifndef DILITHIUM_POLY_AVX2_H
#define DILITHIUM_POLY_AVX2_H

#include <stdint.h>

#include "alignment_x86.h"
#include "dilithium_consts_avx2.h"
#include "dilithium_ntt_avx2.h"
#include "dilithium_rejsample_avx2.h"
#include "dilithium_rounding_avx2.h"
#include "lc_dilithium.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef BUF_ALIGNED_INT32_M256I(LC_DILITHIUM_N) poly;

#define POLY_UNIFORM_GAMMA1_NBLOCKS					       \
	((LC_DILITHIUM_POLYZ_PACKEDBYTES + LC_SHAKE_256_SIZE_BLOCK - 1) /      \
	 LC_SHAKE_256_SIZE_BLOCK)

/**
 * @brief poly_ntt_avx
 *
 * Inplace forward NTT. Coefficients can grow by up to 8*Q in absolute value.
 *
 * @brief a pointer to input/output polynomial
 */
static inline void poly_ntt_avx(poly *a)
{
	dilithium_ntt_avx(a->vec, dilithium_qdata.vec);
}

/**
 * @brief poly_invntt_tomont_avx
 *
 * Inplace inverse NTT and multiplication by 2^{32}. Input coefficients need to
 * be less than Q in absolute value and output coefficients are again bounded
 * by Q.
 *
 * @brief a pointer to input/output polynomial
 */
static inline void poly_invntt_tomont_avx(poly *a)
{
	dilithium_invntt_avx(a->vec, dilithium_qdata.vec);
}

static inline void poly_nttunpack_avx(poly *a)
{
	dilithium_nttunpack_avx(a->vec);
}

/**
 * @brief poly_pointwise_montgomery_avx
 *
 * Pointwise multiplication of polynomials in NTT domain representation and
 * multiplication of resulting polynomial by 2^{-32}.
 *
 * @param c pointer to output polynomial
 * @param a pointer to first input polynomial
 * @param b pointer to second input polynomial
 */
static inline void
poly_pointwise_montgomery_avx(poly *c, const poly *a, const poly *b)
{
	dilithium_pointwise_avx(c->vec, a->vec, b->vec, dilithium_qdata.vec);
}


/**
 * @brief poly_power2round_avx
 *
 * For all coefficients c of the input polynomial, compute c0, c1 such that c
 * mod^+ Q = c1*2^D + c0 with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to
 * be positive standard representatives.
 *
 * @param a1 pointer to output polynomial with coefficients c1
 * @param a0 pointer to output polynomial with coefficients c0
 * @param a pointer to input polynomial
 */
static inline void
poly_power2round_avx(poly *a1, poly *a0, const poly *a)
{
	power2round_avx(a1->vec, a0->vec, a->vec);
}

/**
 * @brief poly_decompose_avx
 *
 * For all coefficients c of the input polynomial, compute high and low bits c0,
 * c1 such c mod^+ Q = c1*ALPHA + c0 with -ALPHA/2 < c0 <= ALPHA/2 except if
 * c1 = (Q-1)/ALPHA where we set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
 * Assumes coefficients to be positive standard representatives.
 *
 * @param a1 pointer to output polynomial with coefficients c1
 * @param a0 pointer to output polynomial with coefficients c0
 * @param a pointer to input polynomial
 */
static inline void
poly_decompose_avx(poly *a1, poly *a0, const poly *a)
{
	decompose_avx(a1->vec, a0->vec, a->vec);
}

/**
 * @brief poly_make_hint_avx
 *
 * Compute hint array. The coefficients of which are the indices of the
 * coefficients of the input polynomial whose low bits overflow into the high
 * bits.
 *
 * @param h pointer to output hint array (preallocated of length N)
 * @param a0 pointer to low part of input polynomial
 * @param a1 pointer to high part of input polynomial
 *
 * @return number of hints, i.e. length of hint array.
 **************************************************/
static inline unsigned int
poly_make_hint_avx(uint8_t hint[LC_DILITHIUM_N], const poly *a0, const poly *a1)
{
	return make_hint_avx(hint, a0->vec, a1->vec);
}

/**
 * @param poly_use_hint_avx
 *
 * Use hint polynomial to correct the high bits of a polynomial.
 *
 * @param b pointer to output polynomial with corrected high bits
 * @param a pointer to input polynomial
 * @param h pointer to input hint polynomial
 */
static inline void poly_use_hint_avx(poly *b, const poly *a, const poly *h)
{
	use_hint_avx(b->vec, a->vec, h->vec);
}


void poly_reduce_avx(poly *a);
void poly_caddq_avx(poly *a);

void poly_add_avx(poly *c, const poly *a, const poly *b);
void poly_sub_avx(poly *c, const poly *a, const poly *b);
void poly_shiftl_avx(poly *a);

int poly_chknorm_avx(const poly *a, int32_t B);
void poly_challenge_avx(poly *c, const uint8_t seed[LC_DILITHIUM_SEEDBYTES]);

void poly_uniform_4x_avx(poly *a0,
			 poly *a1,
			 poly *a2,
			 poly *a3,
			 const uint8_t seed[32],
			 uint16_t nonce0,
			 uint16_t nonce1,
			 uint16_t nonce2,
			 uint16_t nonce3,
			 void *ws_buf,
			 void *ws_keccak);
void poly_uniform_eta_4x_avx(poly *a0,
			     poly *a1,
			     poly *a2,
			     poly *a3,
			     const uint8_t seed[64],
			     uint16_t nonce0,
			     uint16_t nonce1,
			     uint16_t nonce2,
			     uint16_t nonce3,
			     void *ws_buf,
			     void *ws_keccak);
void poly_uniform_gamma1_4x_avx(poly *a0,
				poly *a1,
				poly *a2,
				poly *a3,
				const uint8_t seed[64],
				uint16_t nonce0,
				uint16_t nonce1,
				uint16_t nonce2,
				uint16_t nonce3,
				void *ws_buf,
				void *ws_keccak);

void polyeta_pack_avx(uint8_t r[LC_DILITHIUM_POLYETA_PACKEDBYTES],
		      const poly *a);
void polyeta_unpack_avx(poly *r,
			const uint8_t a[LC_DILITHIUM_POLYETA_PACKEDBYTES]);

void polyt1_pack_avx(uint8_t r[LC_DILITHIUM_POLYT1_PACKEDBYTES],
		     const poly *a);

void polyt1_unpack_avx(poly *r,
		       const uint8_t a[LC_DILITHIUM_POLYT1_PACKEDBYTES]);

void polyt0_pack_avx(uint8_t r[LC_DILITHIUM_POLYT0_PACKEDBYTES], const poly *a);
void polyt0_unpack_avx(poly *r,
		       const uint8_t a[LC_DILITHIUM_POLYT0_PACKEDBYTES]);

void polyz_pack_avx(uint8_t r[LC_DILITHIUM_POLYZ_PACKEDBYTES], const poly *a);
void polyz_unpack_avx(poly *r, const uint8_t *a);

void polyw1_pack_avx(uint8_t *r, const poly *a);


#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLY_AVX2_H */
