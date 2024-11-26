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

#ifndef KYBER_POLYVEC_RISCV_H
#define KYBER_POLYVEC_RISCV_H

#include "kyber_poly_riscv.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	poly_half vec[LC_KYBER_K];
} polyvec_half;

static inline void polyvec_basemul_acc_cache_init(poly *r, const polyvec *a,
						  const polyvec *b,
						  polyvec_half *b_cache)
{
	unsigned int i;
	poly_double r_double;

	kyber_poly_basemul_cache_init(&r_double, &a->vec[0], &b->vec[0],
				      &b_cache->vec[0]);
	for (i = 1; i < LC_KYBER_K - 1; i++) {
		kyber_poly_basemul_acc_cache_init(&r_double, &a->vec[i],
						  &b->vec[i], &b_cache->vec[i]);
	}
	kyber_poly_basemul_acc_cache_init_end(r, &a->vec[i], &b->vec[i],
					      &b_cache->vec[i], &r_double);
}

static inline void polyvec_basemul_acc_cached(poly *r, const polyvec *a,
					      const polyvec *b,
					      polyvec_half *b_cache)
{
	unsigned int i;
	poly_double r_double = { 0 };

	for (i = 0; i < LC_KYBER_K - 1; i++) {
		kyber_poly_basemul_acc_cached(&r_double, &a->vec[i], &b->vec[i],
					      &b_cache->vec[i]);
	}
	kyber_poly_basemul_acc_cache_end(r, &a->vec[i], &b->vec[i],
					 &b_cache->vec[i], &r_double);
}

static inline void polyvec_basemul_acc_montgomery(poly *r, const polyvec *a,
						  const polyvec *b,
						  void *ws_buf)
{
	unsigned int i;
	poly_double r_double = { 0 };

	(void)ws_buf;

	for (i = 0; i < LC_KYBER_K - 1; i++) {
		kyber_poly_basemul_acc(&r_double, &a->vec[i], &b->vec[i]);
	}
	kyber_poly_basemul_acc_end(r, &a->vec[i], &b->vec[i], &r_double);
	lc_memset_secure(&r_double, 0, sizeof(r_double));
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_POLYVEC_RISCV_H */
