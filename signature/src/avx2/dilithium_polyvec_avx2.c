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

#include <stdint.h>

#include "dilithium_consts_avx2.h"
#include "dilithium_ntt_avx2.h"
#include "dilithium_poly_avx2.h"
#include "dilithium_polyvec_avx2.h"
#include "lc_dilithium.h"

#if LC_DILITHIUM_MODE != 5
#error
#endif

/**
 * @brief polyvec_matrix_expand
 *
 * Implementation of ExpandA. Generates matrix A with uniformly random
 * coefficients a_{i,j} by performing rejection sampling on the output stream
 * of SHAKE128(rho|j|i) or AES256CTR(rho,j|i).
 *
 * @param mat[K] output matrix
 * @param rho[] byte array containing seed rho
 */

void polyvec_matrix_expand(polyvecl mat[LC_DILITHIUM_K],
			   const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
			   void *ws_buf)
{
	polyvec_matrix_expand_row0(&mat[0], &mat[1], rho, ws_buf);
	polyvec_matrix_expand_row1(&mat[1], &mat[2], rho, ws_buf);
	polyvec_matrix_expand_row2(&mat[2], &mat[3], rho, ws_buf);
	polyvec_matrix_expand_row3(&mat[3], NULL, rho, ws_buf);
	polyvec_matrix_expand_row4(&mat[4], &mat[5], rho, ws_buf);
	polyvec_matrix_expand_row5(&mat[5], &mat[6], rho, ws_buf);
	polyvec_matrix_expand_row6(&mat[6], &mat[7], rho, ws_buf);
	polyvec_matrix_expand_row7(&mat[7], NULL, rho, ws_buf);
}

void polyvec_matrix_expand_row0(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf)
{
	poly_uniform_4x_avx(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2],
			     &rowa->vec[3], rho, 0, 1, 2, 3, ws_buf);
	poly_uniform_4x_avx(&rowa->vec[4], &rowa->vec[5], &rowa->vec[6],
			    &rowb->vec[0], rho, 4, 5, 6, 256, ws_buf);
	poly_nttunpack_avx(&rowa->vec[0]);
	poly_nttunpack_avx(&rowa->vec[1]);
	poly_nttunpack_avx(&rowa->vec[2]);
	poly_nttunpack_avx(&rowa->vec[3]);
	poly_nttunpack_avx(&rowa->vec[4]);
	poly_nttunpack_avx(&rowa->vec[5]);
	poly_nttunpack_avx(&rowa->vec[6]);
	poly_nttunpack_avx(&rowb->vec[0]);
}

void polyvec_matrix_expand_row1(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf)
{
	poly_uniform_4x_avx(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3],
			    &rowa->vec[4], rho, 257, 258, 259, 260, ws_buf);
	poly_uniform_4x_avx(&rowa->vec[5], &rowa->vec[6], &rowb->vec[0],
			    &rowb->vec[1], rho, 261, 262, 512, 513, ws_buf);
	poly_nttunpack_avx(&rowa->vec[1]);
	poly_nttunpack_avx(&rowa->vec[2]);
	poly_nttunpack_avx(&rowa->vec[3]);
	poly_nttunpack_avx(&rowa->vec[4]);
	poly_nttunpack_avx(&rowa->vec[5]);
	poly_nttunpack_avx(&rowa->vec[6]);
	poly_nttunpack_avx(&rowb->vec[0]);
	poly_nttunpack_avx(&rowb->vec[1]);
}

void polyvec_matrix_expand_row2(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf)
{
	poly_uniform_4x_avx(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4],
			    &rowa->vec[5], rho, 514, 515, 516, 517, ws_buf);
	poly_uniform_4x_avx(&rowa->vec[6], &rowb->vec[0], &rowb->vec[1],
			    &rowb->vec[2], rho, 518, 768, 769, 770, ws_buf);
	poly_nttunpack_avx(&rowa->vec[2]);
	poly_nttunpack_avx(&rowa->vec[3]);
	poly_nttunpack_avx(&rowa->vec[4]);
	poly_nttunpack_avx(&rowa->vec[5]);
	poly_nttunpack_avx(&rowa->vec[6]);
	poly_nttunpack_avx(&rowb->vec[0]);
	poly_nttunpack_avx(&rowb->vec[1]);
	poly_nttunpack_avx(&rowb->vec[2]);
}

void polyvec_matrix_expand_row3(polyvecl *rowa,
				__attribute__((unused)) polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf)
{
	poly_uniform_4x_avx(&rowa->vec[3], &rowa->vec[4], &rowa->vec[5],
			    &rowa->vec[6], rho, 771, 772, 773, 774, ws_buf);
	poly_nttunpack_avx(&rowa->vec[3]);
	poly_nttunpack_avx(&rowa->vec[4]);
	poly_nttunpack_avx(&rowa->vec[5]);
	poly_nttunpack_avx(&rowa->vec[6]);
}

void polyvec_matrix_expand_row4(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf)
{
	poly_uniform_4x_avx(&rowa->vec[0], &rowa->vec[1], &rowa->vec[2],
			    &rowa->vec[3], rho, 1024, 1025, 1026, 1027, ws_buf);
	poly_uniform_4x_avx(&rowa->vec[4], &rowa->vec[5], &rowa->vec[6],
			    &rowb->vec[0], rho, 1028, 1029, 1030, 1280, ws_buf);
	poly_nttunpack_avx(&rowa->vec[0]);
	poly_nttunpack_avx(&rowa->vec[1]);
	poly_nttunpack_avx(&rowa->vec[2]);
	poly_nttunpack_avx(&rowa->vec[3]);
	poly_nttunpack_avx(&rowa->vec[4]);
	poly_nttunpack_avx(&rowa->vec[5]);
	poly_nttunpack_avx(&rowa->vec[6]);
	poly_nttunpack_avx(&rowb->vec[0]);
}

void polyvec_matrix_expand_row5(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf)
{
	poly_uniform_4x_avx(&rowa->vec[1], &rowa->vec[2], &rowa->vec[3],
			    &rowa->vec[4], rho, 1281, 1282, 1283, 1284, ws_buf);
	poly_uniform_4x_avx(&rowa->vec[5], &rowa->vec[6], &rowb->vec[0],
			    &rowb->vec[1], rho, 1285, 1286, 1536, 1537, ws_buf);
	poly_nttunpack_avx(&rowa->vec[1]);
	poly_nttunpack_avx(&rowa->vec[2]);
	poly_nttunpack_avx(&rowa->vec[3]);
	poly_nttunpack_avx(&rowa->vec[4]);
	poly_nttunpack_avx(&rowa->vec[5]);
	poly_nttunpack_avx(&rowa->vec[6]);
	poly_nttunpack_avx(&rowb->vec[0]);
	poly_nttunpack_avx(&rowb->vec[1]);
}

void polyvec_matrix_expand_row6(polyvecl *rowa, polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf)
{
	poly_uniform_4x_avx(&rowa->vec[2], &rowa->vec[3], &rowa->vec[4],
			    &rowa->vec[5], rho, 1538, 1539, 1540, 1541, ws_buf);
	poly_uniform_4x_avx(&rowa->vec[6], &rowb->vec[0], &rowb->vec[1],
			    &rowb->vec[2], rho, 1542, 1792, 1793, 1794, ws_buf);
	poly_nttunpack_avx(&rowa->vec[2]);
	poly_nttunpack_avx(&rowa->vec[3]);
	poly_nttunpack_avx(&rowa->vec[4]);
	poly_nttunpack_avx(&rowa->vec[5]);
	poly_nttunpack_avx(&rowa->vec[6]);
	poly_nttunpack_avx(&rowb->vec[0]);
	poly_nttunpack_avx(&rowb->vec[1]);
	poly_nttunpack_avx(&rowb->vec[2]);
}

void polyvec_matrix_expand_row7(polyvecl *rowa,
				__attribute__((unused)) polyvecl *rowb,
				const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
				void *ws_buf)
{
	poly_uniform_4x_avx(&rowa->vec[3], &rowa->vec[4], &rowa->vec[5],
			    &rowa->vec[6], rho, 1795, 1796, 1797, 1798, ws_buf);
	poly_nttunpack_avx(&rowa->vec[3]);
	poly_nttunpack_avx(&rowa->vec[4]);
	poly_nttunpack_avx(&rowa->vec[5]);
	poly_nttunpack_avx(&rowa->vec[6]);
}
