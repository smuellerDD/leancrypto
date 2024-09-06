/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#ifndef BIKE_SAMPLING_INTERNAL_H
#define BIKE_SAMPLING_INTERNAL_H

#include "bike_internal.h"
#include "cpufeatures.h"
#include "lc_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

// Value used to denote an invalid index for ther error vector.
#define IDX_INVALID_VAL (0xffffffff)

void secure_set_bits_port(pad_r_t *r, uint32_t first_pos, const idx_t *wlist,
			  uint32_t w_size);

#if defined(UNIFORM_SAMPLING)
void sample_error_vec_indices_port(idx_t *out, struct lc_hash_ctx *prf_state);
#endif

#if defined(X86_64)
void secure_set_bits_avx2(pad_r_t *r, uint32_t first_pos, const idx_t *wlist,
			  uint32_t w_size);

void secure_set_bits_avx512(pad_r_t *r, uint32_t first_pos, const idx_t *wlist,
			    uint32_t w_size);

#if defined(UNIFORM_SAMPLING)
void sample_error_vec_indices_avx2(idx_t *out, struct lc_hash_ctx *prf_state);
void sample_error_vec_indices_avx512(idx_t *out, struct lc_hash_ctx *prf_state);
#endif
#endif

typedef struct sampling_ctx_st {
	void (*secure_set_bits)(pad_r_t *r, uint32_t first_pos,
				const idx_t *wlist, uint32_t w_size);

#if defined(UNIFORM_SAMPLING)
	void (*sample_error_vec_indices)(idx_t *out,
					 struct lc_hash_ctx *prf_state);
#endif
} sampling_ctx;

static inline void sampling_ctx_init(sampling_ctx *ctx)
{
#if defined(X86_64)
	enum lc_cpu_features feat = lc_cpu_feature_available();

	if (feat & LC_CPU_FEATURE_INTEL_AVX512) {
		ctx->secure_set_bits = secure_set_bits_avx512;
#if defined(UNIFORM_SAMPLING)
		ctx->sample_error_vec_indices = sample_error_vec_indices_avx512;
#endif
	} else if (feat & LC_CPU_FEATURE_INTEL_AVX2) {
		ctx->secure_set_bits = secure_set_bits_avx2;
#if defined(UNIFORM_SAMPLING)
		ctx->sample_error_vec_indices = sample_error_vec_indices_avx2;
#endif
	} else
#endif
	{
		ctx->secure_set_bits = secure_set_bits_port;
#if defined(UNIFORM_SAMPLING)
		ctx->sample_error_vec_indices = sample_error_vec_indices_port;
#endif
	}
}

#ifdef __cplusplus
}
#endif

#endif /* BIKE_SAMPLING_INTERNAL_H */
