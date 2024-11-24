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

#ifndef KYBER_INDCPA_RISCV_H
#define KYBER_INDCPA_RISCV_H

#include "kyber_polyvec_riscv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KYBER_INDCPA_KEYGEN_MATRIX_VECTOR_MULTIPLICATION                       \
	{                                                                      \
		polyvec_half skpv_cache;                                       \
		polyvec_basemul_acc_cache_init(&ws->pkpv.vec[0],               \
					       &ws->tmp.a[0], &ws->skpv,       \
					       &skpv_cache);                   \
		kyber_poly_toplant(&ws->pkpv.vec[0]);                          \
		for (i = 1; i < LC_KYBER_K; i++) {                             \
			polyvec_basemul_acc_cached(&ws->pkpv.vec[i],           \
						   &ws->tmp.a[i], &ws->skpv,   \
						   &skpv_cache);               \
			kyber_poly_toplant(&ws->pkpv.vec[i]);                  \
		}                                                              \
	}

#define KYBER_INDCPA_ENC_MATRIX_VECTOR_MULTIPLICATION                          \
	{                                                                      \
		polyvec_half sp_cache;                                         \
		polyvec_basemul_acc_cache_init(&ws->b.vec[0], &ws->at[0],      \
					       &ws->sp, &sp_cache);            \
		for (i = 1; i < LC_KYBER_K; i++)                               \
			polyvec_basemul_acc_cached(&ws->b.vec[i], &ws->at[i],  \
						   &ws->sp, &sp_cache);        \
		polyvec_basemul_acc_cached(&ws->v, &ws->pkpv, &ws->sp,         \
					   &sp_cache);                         \
	}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_INDCPA_RISCV_H */
