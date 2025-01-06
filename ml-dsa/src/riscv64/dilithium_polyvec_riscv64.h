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

#ifndef DILITHIUM_POLYVEC_RISCV64_H
#define DILITHIUM_POLYVEC_RISCV64_H

#include "dilithium_poly_riscv64.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void
polyvecl_uniform_eta(polyvecl *v, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
		     uint16_t nonce, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_uniform_eta(&v->vec[i], seed, le_bswap16(nonce++), ws_buf);
}

static inline void
polyvecl_uniform_gamma1(polyvecl *v, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
			uint16_t nonce, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		poly_uniform_gamma1(
			&v->vec[i], seed,
			le_bswap16((uint16_t)(LC_DILITHIUM_L * nonce + i)),
			ws_buf);
}

static inline void
polyveck_uniform_eta(polyveck *v, const uint8_t seed[LC_DILITHIUM_CRHBYTES],
		     uint16_t nonce, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		poly_uniform_eta(&v->vec[i], seed, le_bswap16(nonce++), ws_buf);
}

/**
 * @brief expand_mat - Implementation of ExpandA. Generates matrix A with
 *		       uniformly random coefficients a_{i,j} by performing
 *		       rejection sampling on the output stream of
 *		       SHAKE128(rho|j|i).
 *
 * @param [out] mat output matrix
 * @param [in] rho byte array containing seed rho
 */
static inline void
polyvec_matrix_expand(polyvecl mat[LC_DILITHIUM_K],
		      const uint8_t rho[LC_DILITHIUM_SEEDBYTES], void *ws_buf)
{
	unsigned int i, j;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		for (j = 0; j < LC_DILITHIUM_L; ++j) {
			poly_uniform(
				&mat[i].vec[j], rho,
				le_bswap16((uint16_t)(i << 8) + (uint16_t)j),
				ws_buf);
#ifdef LC_DILITHIUM_RISCV64_RVV
			dilithium_normal2ntt_order_8l_rvv(mat[i].vec[j].coeffs,
							  dilithium_qdata_rvv);
#endif
		}
}

#ifdef LC_DILITHIUM_RISCV64_RVV

static inline void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u,
						     const polyvecl *v,
						     void *ws_buf)
{
	unsigned int i;

	(void)ws_buf;

	poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
	for (i = 1; i < LC_DILITHIUM_L; ++i) {
		poly_basemul_acc_rvv(w, &u->vec[i], &v->vec[i]);
	}
}

#else /* LC_DILITHIUM_RISCV64_RVV */

static inline void polyvecl_pointwise_acc_montgomery(poly *w, const polyvecl *u,
						     const polyvecl *v,
						     void *ws_buf)
{
	unsigned int i;
	poly_double w_double;

	(void)ws_buf;

	poly_basemul_init(&w_double, &u->vec[0], &v->vec[0]);
	for (i = 1; i < LC_DILITHIUM_L - 1; ++i)
		poly_basemul_acc(&w_double, &u->vec[i], &v->vec[i]);
	poly_basemul_acc_end(w, &u->vec[i], &v->vec[i], &w_double);
	lc_memset_secure(&w_double, 0, sizeof(w_double));
}

#endif /* LC_DILITHIUM_RISCV64_RVV */

static inline void
polyvec_matrix_pointwise_montgomery(polyveck *t,
				    const polyvecl mat[LC_DILITHIUM_K],
				    const polyvecl *v, void *ws_buf)
{
	unsigned int i;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyvecl_pointwise_acc_montgomery(&t->vec[i], &mat[i], v,
						  ws_buf);
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_POLYVEC_RISCV64_H */
