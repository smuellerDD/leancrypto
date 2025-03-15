/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * This file is derived from https://github.com/Ji-Peng/PQRV which uses the
 * following license.
 *
 * The MIT license, the text of which is below, applies to PQRV in general.
 *
 * Copyright (c) 2024 - 2025 Jipeng Zhang (jp-zhang@outlook.com)
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef KYBER_POLY_RVV_H
#define KYBER_POLY_RVV_H

#include "ext_headers_riscv.h"
#include "kyber_kdf.h"

/* Do not include kyber_poly_c.h */
#define LC_KYBER_POLY_C_NOT_INCLUDE
#include "kyber_poly.h"

#include "kyber_cbd_rvv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int16_t coeffs[LC_KYBER_N >> 1];
} poly_half;

static inline void
LC_KYBER_RVV_TYPE(poly_getnoise_eta1_rvv)(poly *r,
					  const uint8_t seed[LC_KYBER_SYMBYTES],
					  uint8_t nonce, void *ws_buf)
{
	uint8_t *buf = ws_buf;

	kyber_shake256_prf(buf, POLY_GETNOISE_ETA1_BUFSIZE, seed, nonce);
	LC_KYBER_RVV_TYPE(poly_cbd_eta1_rvv)(r, buf);
}

static inline void
LC_KYBER_RVV_TYPE(poly_getnoise_eta2_rvv)(poly *r,
					  const uint8_t seed[LC_KYBER_SYMBYTES],
					  uint8_t nonce, void *ws_buf)
{
	uint8_t *buf = ws_buf;

	kyber_shake256_prf(buf, POLY_GETNOISE_ETA2_BUFSIZE, seed, nonce);
	LC_KYBER_RVV_TYPE(poly_cbd_eta2_rvv)(r, buf);
}

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
		r->coeffs[2 * i] %= LC_KYBER_Q;
		r->coeffs[2 * i + 1] =
			((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) &
			0xFFF;
		r->coeffs[2 * i + 1] %= LC_KYBER_Q;
	}

	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_normal2ntt_order_rvv)(
		r->coeffs, LC_KYBER_RVV_TYPE(kyber_qdata_rvv));
	LC_VECTOR_DISABLE;
}

static inline void poly_basemul(poly *r, const poly *a, const poly *b)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(
		kyber_poly_basemul_rvv)(r->coeffs, a->coeffs, b->coeffs,
					LC_KYBER_RVV_TYPE(kyber_qdata_rvv));
	LC_VECTOR_DISABLE;
}

static inline void poly_basemul_acc(poly *r, const poly *a, const poly *b)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(
		kyber_poly_basemul_acc_rvv)(r->coeffs, a->coeffs, b->coeffs,
					    LC_KYBER_RVV_TYPE(kyber_qdata_rvv));
	LC_VECTOR_DISABLE;
}

static inline void poly_basemul_cache_init(poly *r, const poly *a,
					   const poly *b, poly_half *b_cache)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_poly_basemul_cache_init_rvv)(
		r->coeffs, a->coeffs, b->coeffs,
		LC_KYBER_RVV_TYPE(kyber_qdata_rvv), b_cache->coeffs);
	LC_VECTOR_DISABLE;
}

static inline void poly_basemul_acc_cache_init(poly *r, const poly *a,
					       const poly *b,
					       poly_half *b_cache)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_poly_basemul_acc_cache_init_rvv)(
		r->coeffs, a->coeffs, b->coeffs,
		LC_KYBER_RVV_TYPE(kyber_qdata_rvv), b_cache->coeffs);
	LC_VECTOR_DISABLE;
}

static inline void poly_basemul_cached(poly *r, const poly *a, const poly *b,
				       poly_half *b_cache)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_poly_basemul_cached_rvv)(
		r->coeffs, a->coeffs, b->coeffs,
		LC_KYBER_RVV_TYPE(kyber_qdata_rvv), b_cache->coeffs);
	LC_VECTOR_DISABLE;
}

static inline void poly_basemul_acc_cached(poly *r, const poly *a,
					   const poly *b, poly_half *b_cache)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_poly_basemul_acc_cached_rvv)(
		r->coeffs, a->coeffs, b->coeffs,
		LC_KYBER_RVV_TYPE(kyber_qdata_rvv), b_cache->coeffs);
	LC_VECTOR_DISABLE;
}

static inline void poly_tomont(poly *r)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_poly_tomont_rvv)(r->coeffs);
	LC_VECTOR_DISABLE;
}

static inline void poly_reduce(poly *r)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_poly_reduce_rvv)(r->coeffs);
	LC_VECTOR_DISABLE;
}

/**
 * @brief poly_ntt - Computes negacyclic number-theoretic transform (NTT) of
 *		     a polynomial in place; inputs assumed to be in normal
 *		     order, output in bitreversed order
 *
 * @param [in,out] r pointer to in/output polynomial
 */
static inline void poly_ntt(poly *r)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_ntt_rvv)(r->coeffs,
					 LC_KYBER_RVV_TYPE(kyber_qdata_rvv));
	LC_VECTOR_DISABLE;
}

/**
 * @brief poly_invntt_tomont - Computes inverse of negacyclic number-theoretic
 *			       transform (NTT) of a polynomial in place;
 *			       inputs assumed to be in bitreversed order, output
 *			       in normal order
 *
 * @param [in,out] r pointer to in/output polynomial
 */
static inline void poly_invntt_tomont(poly *r)
{
	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_intt_rvv)(r->coeffs,
					  LC_KYBER_RVV_TYPE(kyber_qdata_rvv));
	LC_VECTOR_DISABLE;
}

#include "common/kyber_poly_add.h"
#include "common/kyber_poly_sub.h"

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_RVV_H */
