/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef KYBER_INDCPA_C_H
#define KYBER_INDCPA_C_H

#include "kyber_polyvec_c.h"
#include "kyber_polyvec.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KYBER_INDCPA_KEYGEN_MATRIX_VECTOR_MULTIPLICATION                       \
	for (i = 0; i < LC_KYBER_K; i++) {                                     \
		polyvec_basemul_acc_montgomery(&ws->pkpv.vec[i],               \
					       &ws->tmp.a[i], &ws->skpv,       \
					       &ws->tmp.a);                    \
		poly_tomont(&ws->pkpv.vec[i]);                                 \
	}

#define KYBER_INDCPA_ENC_MATRIX_VECTOR_MULTIPLICATION                          \
	for (i = 0; i < LC_KYBER_K; i++)                                       \
		polyvec_basemul_acc_montgomery(&ws->b.vec[i], &ws->at[i],      \
					       &ws->sp, &ws->v);               \
	kyber_print_polyvec(&ws->b, "K-PKE Encrypt: u = BHat * rHat");         \
                                                                               \
	BUILD_BUG_ON(sizeof(poly) > sizeof(ws->at));                           \
	polyvec_basemul_acc_montgomery(&ws->v, &ws->pkpv, &ws->sp, ws->at);    \
	kyber_print_poly(&ws->v, "K-PKE Encrypt: v = tHat^T * rHat");

#ifdef __cplusplus
}
#endif

#endif /* KYBER_INDCPA_C_H */
