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

#ifndef BIKE_INTERNAL_H
#define BIKE_INTERNAL_H

#include "bike_type.h"
#include "lc_rng.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LC_BIKE_NUM_OF_SEEDS 2

#define LC_BIKE_BYTES_IN_QWORD 0x8
#define LC_BIKE_BYTES_IN_XMM 0x10
#define LC_BIKE_BYTES_IN_YMM 0x20
#define LC_BIKE_BYTES_IN_ZMM 0x40

// Copied from (Kaz answer)
// https://stackoverflow.com/questions/466204/rounding-up-to-next-power-of-2
#define LC_BIKE_UPTOPOW2_0(v) ((v) - 1)
#define LC_BIKE_UPTOPOW2_1(v)                                                  \
	(LC_BIKE_UPTOPOW2_0(v) | (LC_BIKE_UPTOPOW2_0(v) >> 1))
#define LC_BIKE_UPTOPOW2_2(v)                                                  \
	(LC_BIKE_UPTOPOW2_1(v) | (LC_BIKE_UPTOPOW2_1(v) >> 2))
#define LC_BIKE_UPTOPOW2_3(v)                                                  \
	(LC_BIKE_UPTOPOW2_2(v) | (LC_BIKE_UPTOPOW2_2(v) >> 4))
#define LC_BIKE_UPTOPOW2_4(v)                                                  \
	(LC_BIKE_UPTOPOW2_3(v) | (LC_BIKE_UPTOPOW2_3(v) >> 8))
#define LC_BIKE_UPTOPOW2_5(v)                                                  \
	(LC_BIKE_UPTOPOW2_4(v) | (LC_BIKE_UPTOPOW2_4(v) >> 16))

#define LC_BIKE_UPTOPOW2(v) (LC_BIKE_UPTOPOW2_5(v) + 1)

#define LC_BIKE_R_QWORDS                                                       \
	LC_BIKE_DIVIDE_AND_CEIL(LC_BIKE_R_BITS, 8 * LC_BIKE_BYTES_IN_QWORD)
#define LC_BIKE_R_XMM                                                          \
	LC_BIKE_DIVIDE_AND_CEIL(LC_BIKE_R_BITS, 8 * LC_BIKE_BYTES_IN_XMM)
#define LC_BIKE_R_YMM                                                          \
	LC_BIKE_DIVIDE_AND_CEIL(LC_BIKE_R_BITS, 8 * LC_BIKE_BYTES_IN_YMM)
#define LC_BIKE_R_ZMM                                                          \
	LC_BIKE_DIVIDE_AND_CEIL(LC_BIKE_R_BITS, 8 * LC_BIKE_BYTES_IN_ZMM)

#define LC_BIKE_R_BLOCKS                                                       \
	LC_BIKE_DIVIDE_AND_CEIL(LC_BIKE_R_BITS, LC_BIKE_BLOCK_BITS)
#define LC_BIKE_R_PADDED (LC_BIKE_R_BLOCKS * LC_BIKE_BLOCK_BITS)
#define LC_BIKE_R_PADDED_BYTES (LC_BIKE_R_PADDED / 8)
#define LC_BIKE_R_PADDED_QWORDS (LC_BIKE_R_PADDED / 64)

#define LC_BIKE_BIT(len) (1ULL << (len))
#define LC_BIKE_MASK(len) (LC_BIKE_BIT(len) - 1)
#define LC_BIKE_LAST_R_QWORD_LEAD (LC_BIKE_R_BITS & LC_BIKE_MASK(6))
#define LC_BIKE_LAST_R_QWORD_TRAIL (64 - LC_BIKE_LAST_R_QWORD_LEAD)
#define LC_BIKE_LAST_R_QWORD_MASK LC_BIKE_MASK(LC_BIKE_LAST_R_QWORD_LEAD)

#define LC_BIKE_LAST_R_BYTE_LEAD (LC_BIKE_R_BITS & LC_BIKE_MASK(3))
#define LC_BIKE_LAST_R_BYTE_TRAIL (8 - LC_BIKE_LAST_R_BYTE_LEAD)
#define LC_BIKE_LAST_R_BYTE_MASK LC_BIKE_MASK(LC_BIKE_LAST_R_BYTE_LEAD)

// Data alignement
#define LC_BIKE_ALIGN_BYTES (LC_BIKE_BYTES_IN_ZMM)

#define LC_BIKE_SEED_BYTES (256 / 8)

/*******************************************************************************
 * Parameters for the BGF decoder.
 ******************************************************************************/

// Works only for 0 < v < 512
#define LC_BIKE_LOG2_MSB(v)                                                                  \
	((v) == 0 ?                                                                          \
		 0 :                                                                         \
		 ((v) < 2 ?                                                                  \
			  1 :                                                                \
			  ((v) < 4 ?                                                         \
				   2 :                                                       \
				   ((v) < 8 ?                                                \
					    3 :                                              \
					    ((v) < 16 ?                                      \
						     4 :                                     \
						     ((v) < 32 ?                             \
							      5 :                            \
							      ((v) < 64 ?                    \
								       6 :                   \
								       ((v) < 128 ?          \
										7 :          \
										((v) < 256 ? \
											 8 : \
											 9)))))))))

#define LC_BIKE_BGF_DECODER
#define LC_BIKE_DELTA 3
#define LC_BIKE_SLICES (LC_BIKE_LOG2_MSB(LC_BIKE_D) + 1)

/*******************************************************************************
 * Internal data types
 ******************************************************************************/

typedef struct uint128_s {
	union {
		uint8_t bytes[16]; // NOLINT
		uint32_t dw[4]; // NOLINT
		uint64_t qw[2]; // NOLINT
	} u;
} uint128_t;

typedef struct seed_s {
	uint8_t raw[LC_BIKE_SEED_BYTES];
} seed_t;

typedef struct seeds_s {
	seed_t seed[LC_BIKE_NUM_OF_SEEDS];
} seeds_t;

typedef struct e_s {
	r_t val[LC_BIKE_N0];
} e_t;

// Pad r to the next Block
typedef struct pad_r_s {
	r_t val;
	uint8_t pad[LC_BIKE_R_PADDED_BYTES - sizeof(r_t)];
} __align(LC_BIKE_ALIGN_BYTES) pad_r_t;

// Double padded r, required for multiplication and squaring
typedef struct dbl_pad_r_s {
	uint8_t raw[2 * LC_BIKE_R_PADDED_BYTES];
} __align(LC_BIKE_ALIGN_BYTES) dbl_pad_r_t;

typedef struct pad_e_s {
	pad_r_t val[LC_BIKE_N0];
} __align(LC_BIKE_ALIGN_BYTES) pad_e_t;

#define PE0_RAW(e) ((e)->val[0].val.raw)
#define PE1_RAW(e) ((e)->val[1].val.raw)

typedef struct func_k_s {
	m_t m;
	r_t c0;
	m_t c1;
} func_k_t;

// For a faster rotate we triplicate the syndrome (into 3 copies)
typedef struct syndrome_s {
	uint64_t qw[3 * LC_BIKE_R_QWORDS];
} __align(LC_BIKE_ALIGN_BYTES) syndrome_t;

typedef struct upc_slice_s {
	union {
		pad_r_t r;
		uint64_t qw[sizeof(pad_r_t) / sizeof(uint64_t)];
	} __align(LC_BIKE_ALIGN_BYTES) u;
} __align(LC_BIKE_ALIGN_BYTES) upc_slice_t;

typedef struct upc_s {
	upc_slice_t slice[LC_BIKE_SLICES];
} upc_t;

int lc_bike_enc_internal(struct lc_bike_ct *ct, struct lc_bike_ss *ss,
			 const struct lc_bike_pk *pk,
			 struct lc_rng_ctx *rng_ctx);

#ifdef __cplusplus
}
#endif

#endif /* BIKE_INTERNAL_H */
