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

#ifndef KYBER_POLY_RISCV_H
#define KYBER_POLY_RISCV_H

#include "kyber_ntt_rv64im.h"
#include "kyber_poly.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int16_t coeffs[LC_KYBER_N >> 1];
} poly_half;

typedef struct {
	int32_t coeffs[LC_KYBER_N];
} poly_double;

static inline void kyber_poly_basemul_cache_init(poly_double *r, const poly *a,
						 const poly *b,
						 poly_half *b_cache)
{
	kyber_poly_basemul_cache_init_rv64im(r->coeffs, a->coeffs, b->coeffs,
					     b_cache->coeffs,
					     kyber_zetas_basemul_rv64im);
}

static inline void kyber_poly_basemul_acc_cache_init(poly_double *r,
						     const poly *a,
						     const poly *b,
						     poly_half *b_cache)
{
	kyber_poly_basemul_acc_cache_init_rv64im(r->coeffs, a->coeffs,
						 b->coeffs, b_cache->coeffs,
						 kyber_zetas_basemul_rv64im);
}

static inline void kyber_poly_basemul_acc_cache_init_end(poly *r, const poly *a,
							 const poly *b,
							 poly_half *b_cache,
							 poly_double *r_double)
{
	kyber_poly_basemul_acc_cache_init_end_rv64im(r->coeffs, a->coeffs,
						     b->coeffs, b_cache->coeffs,
						     kyber_zetas_basemul_rv64im,
						     r_double->coeffs);
}

static inline void kyber_poly_basemul_acc_cached(poly_double *r, const poly *a,
						 const poly *b,
						 poly_half *b_cache)
{
	kyber_poly_basemul_acc_cached_rv64im(r->coeffs, a->coeffs, b->coeffs,
					     b_cache->coeffs);
}

static inline void kyber_poly_basemul_acc_cache_end(poly *r, const poly *a,
						    const poly *b,
						    poly_half *b_cache,
						    poly_double *r_double)
{
	kyber_poly_basemul_acc_cache_end_rv64im(r->coeffs, a->coeffs, b->coeffs,
						b_cache->coeffs,
						r_double->coeffs);
}

static inline void kyber_poly_basemul_acc(poly_double *r, const poly *a,
					  const poly *b)
{
	kyber_poly_basemul_acc_rv64im(r->coeffs, a->coeffs, b->coeffs,
				      kyber_zetas_basemul_rv64im);
}

static inline void kyber_poly_basemul_acc_end(poly *r, const poly *a,
					      const poly *b,
					      poly_double *r_double)
{
	kyber_poly_basemul_acc_end_rv64im(r->coeffs, a->coeffs, b->coeffs,
					  kyber_zetas_basemul_rv64im,
					  r_double->coeffs);
}

static inline void kyber_poly_toplant(poly *r)
{
	kyber_poly_toplant_rv64im(r->coeffs);
}

// TODO
static inline void kyber_poly_reduce(poly *r)
{
	kyber_poly_plantard_rdc_rv64im(r->coeffs);
}

// void poly_reduce(poly *r)
// {
//     unsigned int i;
//     for (i = 0; i < KYBER_N; i++)
//         r->coeffs[i] = barrett_reduce(r->coeffs[i]);
// }

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLY_RISCV_H */
