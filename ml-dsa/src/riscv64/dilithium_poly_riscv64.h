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
 * This file is derived from https://github.com/Ji-Peng/PQRV which uses the
 * following license.
 *
 * The MIT license, the text of which is below, applies to PQRV in general.
 *
 * Copyright (c) 2024 Jipeng Zhang (jp-zhang@outlook.com)
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

#ifndef DILITHIUM_POLY_RISCV64_H
#define DILITHIUM_POLY_RISCV64_H

#include "dilithium_type.h"
#include "dilithium_ntt_rv64im.h"
#include "dilithium_ntt_rvv.h"
#include "dilithium_zetas_riscv64.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int32_t coeffs[(LC_DILITHIUM_N >> 2) * 3];
} poly_cache;

typedef struct {
	int64_t coeffs[LC_DILITHIUM_N];
} poly_double;

static inline void poly_reduce(poly *a)
{
#ifdef LC_DILITHIUM_RISCV64_RVV
	dilithium_poly_reduce_rvv(a->coeffs);
#else
	dilithium_poly_reduce_rv64im(a->coeffs);
#endif
}

static inline void poly_basemul_init(poly_double *r, const poly *a,
				     const poly *b)
{
	dilithium_poly_basemul_8l_init_rv64im(r->coeffs, a->coeffs, b->coeffs);
}

static inline void poly_basemul_acc(poly_double *r, const poly *a,
				    const poly *b)
{
	dilithium_poly_basemul_8l_acc_rv64im(r->coeffs, a->coeffs, b->coeffs);
}

static inline void poly_basemul_acc_end(poly *r, const poly *a, const poly *b,
					poly_double *r_double)
{
	dilithium_poly_basemul_8l_acc_end_rv64im(r->coeffs, a->coeffs,
						 b->coeffs, r_double->coeffs);
}

static inline void poly_basemul_acc_rvv(poly *c, const poly *a, const poly *b)
{
	dilithium_poly_basemul_acc_8l_rvv(c->coeffs, a->coeffs, b->coeffs);
}

static inline void poly_pointwise_montgomery(poly *c, const poly *a,
					     const poly *b)
{
#ifdef LC_DILITHIUM_RISCV64_RVV
	dilithium_poly_basemul_8l_rvv(c->coeffs, a->coeffs, b->coeffs);
#else
	dilithium_poly_basemul_8l_rv64im(c->coeffs, a->coeffs, b->coeffs);
#endif
}

static inline void poly_ntt(poly *a)
{
#ifdef LC_DILITHIUM_RISCV64_RVV
	dilithium_ntt_8l_rvv(a->coeffs, dilithium_qdata_rvv);
#else
	dilithium_ntt_8l_rv64im(a->coeffs, zetas_ntt_8l_rv64im);
#endif
}

static inline void poly_invntt_tomont(poly *a)
{
#ifdef LC_DILITHIUM_RISCV64_RVV
	dilithium_intt_8l_rvv(a->coeffs, dilithium_qdata_rvv);
#else
	dilithium_intt_8l_rv64im(a->coeffs, zetas_intt_8l_rv64im);
#endif
}

/**
 * @brief poly_power2round - For all coefficients c of the input polynomial,
 *			     compute c0, c1 such that c mod Q = c1*2^D + c0
 *			     with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients
 *			     to be standard representatives.
 *
 * @param [out] a1 pointer to output polynomial with coefficients c1
 * @param [out] a0 pointer to output polynomial with coefficients c0
 * @param [in] a pointer to input polynomial
 */
static inline void poly_power2round(poly *a1, poly *a0, const poly *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
}

/**
 * @brief poly_caddq - For all coefficients of in/out polynomial add Q if
 *		       coefficient is negative.
 *
 * @param [in,out] a pointer to input/output polynomial
 */
static inline void poly_caddq(poly *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N; ++i)
		a->coeffs[i] = caddq(a->coeffs[i]);
}

/**
 * @brief polyt1_unpack - Unpack polynomial t1 with 10-bit coefficients.
 *			  Output coefficients are standard representatives.
 *
 * @param [out] r pointer to output polynomial
 * @param [in] a byte array with bit-packed polynomial
 */
static inline void polyt1_unpack(poly *r, const uint8_t *a)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_N / 4; ++i) {
		r->coeffs[4 * i + 0] =
			((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) &
			0x3FF;
		r->coeffs[4 * i + 1] =
			((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) &
			0x3FF;
		r->coeffs[4 * i + 2] =
			((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) &
			0x3FF;
		r->coeffs[4 * i + 3] =
			((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) &
			0x3FF;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLY_RISCV64_H */
