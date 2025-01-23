/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/awslabs/bike-kem
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#ifndef BIKE_DECODE_INTERNAL_H
#define BIKE_DECODE_INTERNAL_H

#include "bike_internal.h"
#include "cpufeatures.h"

#ifdef __cplusplus
extern "C" {
#endif

// Rotate right the first R_BITS of a syndrome.
// At input, the syndrome is stored as three R_BITS triplicate.
// (this makes rotation easier to implement)
// For the output: the output syndrome has only one R_BITS rotation, the remaining
// (2 * R_BITS) bits are undefined.
void rotate_right_port(syndrome_t *out, const syndrome_t *in,
		       uint32_t bitscount);
void dup_port(syndrome_t *s);
void bit_sliced_adder_port(upc_t *upc, syndrome_t *rotated_syndrome,
			   const size_t num_of_slices);
int bit_slice_full_subtract_port(upc_t *upc, uint8_t val);

#if defined(X86_64)
void rotate_right_avx2(syndrome_t *out, const syndrome_t *in,
		       uint32_t bitscount);
void rotate_right_avx512(syndrome_t *out, const syndrome_t *in,
			 uint32_t bitscount);
void dup_avx2(syndrome_t *s);
void dup_avx512(syndrome_t *s);

void bit_sliced_adder_avx2(upc_t *upc, syndrome_t *rotated_syndrome,
			   const size_t num_of_slices);
void bit_sliced_adder_avx512(upc_t *upc, syndrome_t *rotated_syndrome,
			     const size_t num_of_slices);

int bit_slice_full_subtract_avx2(upc_t *upc, uint8_t val);
int bit_slice_full_subtract_avx512(upc_t *upc, uint8_t val);
#endif

// Decode methods struct
typedef struct decode_ctx_st {
	void (*rotate_right)(syndrome_t *out, const syndrome_t *in,
			     uint32_t bitscount);
	void (*dup)(syndrome_t *s);
	void (*bit_sliced_adder)(upc_t *upc, syndrome_t *rotated_syndrom,
				 const size_t num_of_slices);
	int (*bit_slice_full_subtract)(upc_t *upc, uint8_t val);
} decode_ctx;

static inline void decode_ctx_init(decode_ctx *ctx)
{
#if defined(X86_64)
	enum lc_cpu_features feat = lc_cpu_feature_available();

	if (feat & LC_CPU_FEATURE_INTEL_AVX512) {
		ctx->rotate_right = rotate_right_avx512;
		ctx->dup = dup_avx512;
		ctx->bit_sliced_adder = bit_sliced_adder_avx512;
		ctx->bit_slice_full_subtract = bit_slice_full_subtract_avx512;
	} else if (feat & LC_CPU_FEATURE_INTEL_AVX2) {
		//TODO recheck and fix
#ifdef LINUX_KERNEL
		ctx->rotate_right = rotate_right_port;
#else
		ctx->rotate_right = rotate_right_avx2;
#endif
		ctx->dup = dup_avx2;
		ctx->bit_sliced_adder = bit_sliced_adder_avx2;
		ctx->bit_slice_full_subtract = bit_slice_full_subtract_avx2;
	} else
#endif
	{
		ctx->rotate_right = rotate_right_port;
		ctx->dup = dup_port;
		ctx->bit_sliced_adder = bit_sliced_adder_port;
		ctx->bit_slice_full_subtract = bit_slice_full_subtract_port;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* BIKE_DECODE_INTERNAL_H */
