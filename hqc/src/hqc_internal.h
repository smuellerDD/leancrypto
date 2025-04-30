/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef HQC_INTERNAL_H
#define HQC_INTERNAL_H

#include "hqc_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 * Data structures to support small stack implementation
 ******************************************************************************/

struct reed_solomon_decode_ws {
	uint16_t syndromes[2 * LC_HQC_PARAM_DELTA];
	uint16_t sigma[1 << LC_HQC_PARAM_FFT];
	uint8_t error[1 << LC_HQC_PARAM_M];
	uint16_t z[LC_HQC_PARAM_N1];
	uint16_t error_values[LC_HQC_PARAM_N1];

	uint16_t compute_roots_w[1 << LC_HQC_PARAM_M];

	uint8_t code_decode_tmp[LC_HQC_VEC_N1_SIZE_BYTES];
};

struct vect_mul_ws {
	uint64_t stack[LC_HQC_VEC_N_SIZE_64 << 3];
	uint64_t o_karat[LC_HQC_VEC_N_SIZE_64 << 1];
};

struct vect_set_random_fixed_weight_ws {
	/* to be interpreted as LC_HQC_PARAM_OMEGA_R 32-bit unsigned ints */
	uint8_t rand_bytes[4 * LC_HQC_PARAM_OMEGA_R];
	uint32_t support[LC_HQC_PARAM_OMEGA_R];
	uint32_t index_tab[LC_HQC_PARAM_OMEGA_R];
	uint64_t bit_tab[LC_HQC_PARAM_OMEGA_R];
};

struct vect_set_random_ws {
	uint8_t rand_bytes[LC_HQC_VEC_N_SIZE_BYTES];
};

struct hqc_pke_encrypt_ws {
	uint64_t h[LC_HQC_VEC_N_SIZE_64];
	uint64_t s[LC_HQC_VEC_N_SIZE_64];
	uint64_t r1[LC_HQC_VEC_N_SIZE_64];
	uint64_t r2[LC_HQC_VEC_N_SIZE_64];
	uint64_t e[LC_HQC_VEC_N_SIZE_64];
	uint64_t tmp1[LC_HQC_VEC_N_SIZE_64];
	uint64_t tmp2[LC_HQC_VEC_N_SIZE_64];
	union {
		struct vect_set_random_fixed_weight_ws vect_set_f_ws;
		struct vect_set_random_ws vect_set_r_ws;
		struct vect_mul_ws vect_mul_ws;
	} wsu;
};

struct hqc_pke_decrypt_ws {
	uint64_t y[LC_HQC_VEC_N_SIZE_64];
	uint8_t pk[LC_HQC_PUBLIC_KEY_BYTES];
	uint64_t tmp1[LC_HQC_VEC_N_SIZE_64];
	uint64_t tmp2[LC_HQC_VEC_N_SIZE_64];
	union {
		struct vect_set_random_fixed_weight_ws vect_set_f_ws;
		struct vect_mul_ws vect_mul_ws;
		struct reed_solomon_decode_ws reed_solomon_decode_ws;
	} wsu;
};

int lc_hqc_enc_internal(struct lc_hqc_ct *ct, struct lc_hqc_ss *ss,
			const struct lc_hqc_pk *pk, struct lc_rng_ctx *rng_ctx);

#ifdef __cplusplus
}
#endif

#endif /* HQC_INTERNAL_H */
