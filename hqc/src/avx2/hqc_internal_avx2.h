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

#ifndef HQC_INTERNAL_AVX2_H
#define HQC_INTERNAL_AVX2_H

#include "ext_headers_x86.h"
#include "hqc_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************
 * Data structures to support small stack implementation
 ******************************************************************************/

// codeword is 128 bits, seen multiple ways
typedef union {
	__mmask16 mask[8];
	uint16_t u16[8];
	uint32_t u32[4];
} codeword;

typedef union {
	__m256i mm;
	uint16_t u16[16];
} vector;

// Expanded codeword is 16*128 bits, seen multiple ways
typedef union {
	__m256i mm[8];
	int16_t i16[128];
} expandedCodeword;

struct reed_decode_ws {
	union {
		struct reed_solomon_decode_ws {
			__m256i syndromes256[LC_HQC_SYND_SIZE_256];
			uint16_t sigma[1 << LC_HQC_PARAM_FFT];
			uint16_t z[LC_HQC_PARAM_N1];
			uint16_t error_values[LC_HQC_PARAM_N1];
			uint8_t cdw_bytes[LC_HQC_PARAM_N1];
			uint8_t error[1 << LC_HQC_PARAM_M];
		} reed_solomon_decode_ws;
		struct reed_muller_decode_ws {
			expandedCodeword expanded, transform;
			__m256i res, tmp, bitmap, abs_rows[8], bound,
				active_row, max_abs_rows, vect_mask;
			vector peak_mask;
		} reed_muller_decode_ws;
	} u;
	uint64_t code_decode_tmp[LC_HQC_VEC_N1_SIZE_64];
};

/* The number of needed vectors to store PARAM_N bits */
#if (LC_HQC_TYPE == 128) || (LC_HQC_TYPE == 192)
#define LC_HQC_VEC_N_ARRAY_SIZE_VEC LC_HQC_CEIL_DIVIDE(LC_HQC_PARAM_N_MULT, 256)
#elif (LC_HQC_TYPE == 256)
#define LC_HQC_VEC_N_ARRAY_SIZE_VEC LC_HQC_CEIL_DIVIDE(LC_HQC_PARAM_N, 256)
#endif

#define LC_HQC_WORD 64
#define LC_HQC_LAST64 (LC_HQC_PARAM_N >> 6)

//Parameters for Toom-Cook and UB_Karatsuba
#if (LC_HQC_TYPE == 128)
#define LC_HQC_T_3W 2048
#elif (LC_HQC_TYPE == 192)
#define LC_HQC_T_3W 4096
#endif
#define LC_HQC_T_3W_256 (LC_HQC_T_3W >> 8)
#define LC_HQC_T2_3W_256 (2 * LC_HQC_T_3W_256)
#define LC_HQC_T2REC_3W_256 (6 * LC_HQC_T_3W_256)

#define LC_HQC_T_TM3R_3W (LC_HQC_PARAM_N_MULT / 3)
#define LC_HQC_T_TM3R (LC_HQC_PARAM_N_MULT + 384)
#define LC_HQC_tTM3R ((LC_HQC_T_TM3R) / LC_HQC_WORD)
#define LC_HQC_T_TM3R_3W_256 ((LC_HQC_T_TM3R_3W + 128) / (4 * LC_HQC_WORD))
#define LC_HQC_T_TM3R_3W_64 (LC_HQC_T_TM3R_3W_256 << 2)
#define LC_HQC_T_5W 4096
#define LC_HQC_T_5W_256 (LC_HQC_T_5W >> 8)
#define LC_HQC_T2_5W_256 (2 * LC_HQC_T_5W_256)
#define LC_HQC_t5 (5 * LC_HQC_T_5W / LC_HQC_WORD)

struct vect_mul_ws {
	__m256i a1_times_a2[LC_HQC_VEC_N_256_SIZE_64 >> 1];

#if (LC_HQC_TYPE == 128) || (LC_HQC_TYPE == 192)
	struct karat_mult_3 {
		__m256i aa01[LC_HQC_T_3W_256], bb01[LC_HQC_T_3W_256],
			aa02[LC_HQC_T_3W_256], bb02[LC_HQC_T_3W_256],
			aa12[LC_HQC_T_3W_256], bb12[LC_HQC_T_3W_256];
		__m256i D0[LC_HQC_T2_3W_256], D1[LC_HQC_T2_3W_256],
			D2[LC_HQC_T2_3W_256], D3[LC_HQC_T2_3W_256],
			D4[LC_HQC_T2_3W_256], D5[LC_HQC_T2_3W_256];
		__m256i ro256[3 * LC_HQC_T2_3W_256], middle0;
	} karat_mult_3;
#elif (LC_HQC_TYPE == 256)
	struct karat_mult_5 {
		__m256i aa01[LC_HQC_T_5W_256], bb01[LC_HQC_T_5W_256],
			aa02[LC_HQC_T_5W_256], bb02[LC_HQC_T_5W_256],
			aa03[LC_HQC_T_5W_256], bb03[LC_HQC_T_5W_256],
			aa04[LC_HQC_T_5W_256], bb04[LC_HQC_T_5W_256],
			aa12[LC_HQC_T_5W_256], bb12[LC_HQC_T_5W_256],
			aa13[LC_HQC_T_5W_256], bb13[LC_HQC_T_5W_256],
			aa14[LC_HQC_T_5W_256], bb14[LC_HQC_T_5W_256],
			aa23[LC_HQC_T_5W_256], bb23[LC_HQC_T_5W_256],
			aa24[LC_HQC_T_5W_256], bb24[LC_HQC_T_5W_256],
			aa34[LC_HQC_T_5W_256], bb34[LC_HQC_T_5W_256];

		__m256i D0[LC_HQC_T2_5W_256], D1[LC_HQC_T2_5W_256],
			D2[LC_HQC_T2_5W_256], D3[LC_HQC_T2_5W_256],
			D4[LC_HQC_T2_5W_256], D01[LC_HQC_T2_5W_256],
			D02[LC_HQC_T2_5W_256], D03[LC_HQC_T2_5W_256],
			D04[LC_HQC_T2_5W_256], D12[LC_HQC_T2_5W_256],
			D13[LC_HQC_T2_5W_256], D14[LC_HQC_T2_5W_256],
			D23[LC_HQC_T2_5W_256], D24[LC_HQC_T2_5W_256],
			D34[LC_HQC_T2_5W_256];

		__m256i ro256[LC_HQC_t5 >> 1];
	} karat_mult_5;
#endif
#if (LC_HQC_TYPE == 128) || (LC_HQC_TYPE == 192)
	struct toom_3_mult {
		__m256i U0[LC_HQC_T_TM3R_3W_256], V0[LC_HQC_T_TM3R_3W_256],
			U1[LC_HQC_T_TM3R_3W_256], V1[LC_HQC_T_TM3R_3W_256],
			U2[LC_HQC_T_TM3R_3W_256], V2[LC_HQC_T_TM3R_3W_256];
		__m256i W0[2 * (LC_HQC_T_TM3R_3W_256)],
			W1[2 * (LC_HQC_T_TM3R_3W_256)],
			W2[2 * (LC_HQC_T_TM3R_3W_256)],
			W3[2 * (LC_HQC_T_TM3R_3W_256)],
			W4[2 * (LC_HQC_T_TM3R_3W_256)];
		__m256i tmp[4 * (LC_HQC_T_TM3R_3W_256)];
		__m256i ro256[6 * (LC_HQC_T_TM3R_3W_256)];
	} toom_3_mult;
#elif (LC_HQC_TYPE == 256)
	struct toom_3_mult {
		__m256i U0[LC_HQC_T_TM3R_3W_256 + 2],
			V0[LC_HQC_T_TM3R_3W_256 + 2],
			U1[LC_HQC_T_TM3R_3W_256 + 2],
			V1[LC_HQC_T_TM3R_3W_256 + 2],
			U2[LC_HQC_T_TM3R_3W_256 + 2],
			V2[LC_HQC_T_TM3R_3W_256 + 2];
		__m256i W0[2 * (LC_HQC_T_TM3R_3W_256 + 2)],
			W1[2 * (LC_HQC_T_TM3R_3W_256 + 2)],
			W2[2 * (LC_HQC_T_TM3R_3W_256 + 2)],
			W3[2 * (LC_HQC_T_TM3R_3W_256 + 2)],
			W4[2 * (LC_HQC_T_TM3R_3W_256 + 2)];
		__m256i tmp[2 * (LC_HQC_T_TM3R_3W_256 + 2) + 3];
		__m256i ro256[LC_HQC_tTM3R / 2];
	} toom_3_mult;
#endif
	struct karat_mult_16 {
		__m256i D0[16], D1[16], D2[16], SAA[8], SBB[8], middle;
	} karat_mult_16;
	struct karat_mult_8 {
		__m256i D0[8], D1[8], D2[8], SAA[4], SBB[4], middle;
	} karat_mult_8;
	struct karat_mult_4 {
		__m256i D0[4], D1[4], D2[4], SAA[2], SBB[2], middle0, middle1;
	} karat_mult_4;
	struct karat_mult_2 {
		__m256i D0[2], D1[2], D2[2], SAA, SBB, middle;
	} karat_mult_2;
	struct karat_mult_1 {
		__m128i D1[2], D0[2], D2[2], Al, Ah, Bl, Bh, DD0, DD2, AAlpAAh,
			BBlpBBh, DD1, AlpAh, BlpBh, middle;
	} karat_mult_1;
};

struct vect_set_random_fixed_weight_ws {
	__m256i bit256[LC_HQC_PARAM_OMEGA_R];
	__m256i bloc256[LC_HQC_PARAM_OMEGA_R];
	uint32_t rand_u32[LC_HQC_PARAM_OMEGA_R];
	uint32_t tmp[LC_HQC_PARAM_OMEGA_R];
	uint8_t sk_seed[LC_HQC_SEED_BYTES];
};

struct vect_set_random_ws {
	uint8_t rand_bytes[LC_HQC_VEC_N_SIZE_BYTES];
	uint8_t pk_seed[LC_HQC_SEED_BYTES];
};

struct hqc_pke_encrypt_ws {
	__m256i h_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	__m256i s_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	__m256i r2_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	__m256i r1_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	__m256i e_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	__m256i tmp1_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	__m256i tmp2_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	__m256i tmp3_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	union {
		struct vect_set_random_fixed_weight_ws vect_set_f_ws;
		struct vect_set_random_ws vect_set_r_ws;
		struct vect_mul_ws vect_mul_ws;
	} wsu;
	uint64_t tmp4[LC_HQC_VEC_N_256_SIZE_64];
};

struct hqc_pke_decrypt_ws {
	__m256i y_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	__m256i tmp3_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
	union {
		struct vect_set_random_fixed_weight_ws vect_set_f_ws;
		struct vect_mul_ws vect_mul_ws;
		struct reed_decode_ws reed_decode_ws;
	} wsu;
	uint64_t tmp1[LC_HQC_VEC_N_256_SIZE_64];
	uint64_t tmp2[LC_HQC_VEC_N_256_SIZE_64];
	uint8_t pk[LC_HQC_PUBLIC_KEY_BYTES];
};

int lc_hqc_enc_internal(struct lc_hqc_ct *ct, struct lc_hqc_ss *ss,
			const struct lc_hqc_pk *pk, struct lc_rng_ctx *rng_ctx);

#ifdef __cplusplus
}
#endif

#endif /* HQC_INTERNAL_AVX2_H */
