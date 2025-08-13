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

#ifndef NTT_RVV_VLEN128_H
#define NTT_RVV_VLEN128_H

#include "ext_headers_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const int16_t kyber_qdata_rvv_vlen128[684];
void kyber_ntt_rvv_vlen128(int16_t *r, const int16_t *table);
void kyber_intt_rvv_vlen128(int16_t *r, const int16_t *table);

void kyber_poly_basemul_rvv_vlen128(int16_t *r, const int16_t *a,
				    const int16_t *b, const int16_t *table);
void kyber_poly_basemul_acc_rvv_vlen128(int16_t *r, const int16_t *a,
					const int16_t *b, const int16_t *table);
void kyber_poly_basemul_cache_init_rvv_vlen128(int16_t *r, const int16_t *a,
					       const int16_t *b,
					       const int16_t *table,
					       int16_t *b_cache);
void kyber_poly_basemul_acc_cache_init_rvv_vlen128(int16_t *r, const int16_t *a,
						   const int16_t *b,
						   const int16_t *table,
						   int16_t *b_cache);
void kyber_poly_basemul_cached_rvv_vlen128(int16_t *r, const int16_t *a,
					   const int16_t *b,
					   const int16_t *table,
					   int16_t *b_cache);
void kyber_poly_basemul_acc_cached_rvv_vlen128(int16_t *r, const int16_t *a,
					       const int16_t *b,
					       const int16_t *table,
					       int16_t *b_cache);
void kyber_poly_reduce_rvv_vlen128(int16_t *r);
void kyber_poly_tomont_rvv_vlen128(int16_t *r);

void kyber_ntt2normal_order_rvv_vlen128(int16_t *r, const int16_t *table);
void kyber_normal2ntt_order_rvv_vlen128(int16_t *r, const int16_t *table);
void kyber_rej_uniform_rvv_vlen128(int16_t *r, const uint8_t *buf,
				   const int16_t *table, uint32_t *ctr_p,
				   uint32_t *pos_p);
void kyber_cbd2_rvv_vlen128(int16_t *r, const uint8_t *buf,
			    const int16_t *table);
void kyber_cbd3_rvv_vlen128(int16_t *r, const uint8_t *buf,
			    const int16_t *table);

#ifdef __cplusplus
}
#endif

#endif /* NTT_RVV_VLEN128_H */
