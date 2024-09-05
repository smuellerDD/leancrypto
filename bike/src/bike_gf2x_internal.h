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

#ifndef BIKE_GF2X_INTERNAL_H
#define BIKE_GF2X_INTERNAL_H

#include "bike_internal.h"
#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

// The size in quadwords of the operands in the gf2x_mul_base function
// for different implementations.
#define GF2X_PORT_BASE_QWORDS (1)
#define GF2X_PCLMUL_BASE_QWORDS (8)
#define GF2X_VPCLMUL_BASE_QWORDS (16)

// ------------------ FUNCTIONS NEEDED FOR GF2X MULTIPLICATION ------------------
// GF2X multiplication of a and b of size GF2X_BASE_QWORDS, c = a * b
void gf2x_mul_base_port(uint64_t *c, const uint64_t *a, const uint64_t *b);
void karatzuba_add1_port(uint64_t *alah, uint64_t *blbh, const uint64_t *a,
			 const uint64_t *b, const size_t qwords_len);
void karatzuba_add2_port(uint64_t *z, const uint64_t *x, const uint64_t *y,
			 const size_t qwords_len);
void karatzuba_add3_port(uint64_t *c, const uint64_t *mid,
			 const size_t qwords_len);

// -------------------- FUNCTIONS NEEDED FOR GF2X INVERSION --------------------
// c = a^2
void gf2x_sqr_port(dbl_pad_r_t *c, const pad_r_t *a);
// The k-squaring function computes c = a^(2^k) % (x^r - 1),
// It is required by inversion, where l_param is derived from k.
void k_sqr_port(pad_r_t *c, const pad_r_t *a, size_t l_param);
// c = a mod (x^r - 1)
void gf2x_red_port(pad_r_t *c, const dbl_pad_r_t *a);

// AVX2 and AVX512 versions of the functions
#if defined(X86_64)
// ------------------ FUNCTIONS NEEDED FOR GF2X MULTIPLICATION ------------------
void gf2x_mul_base_pclmul(uint64_t *c, const uint64_t *a, const uint64_t *b);
void gf2x_mul_base_vpclmul(uint64_t *c, const uint64_t *a, const uint64_t *b);

void karatzuba_add1_avx2(uint64_t *alah, uint64_t *blbh, const uint64_t *a,
			 const uint64_t *b, const size_t qwords_len);
void karatzuba_add1_avx512(uint64_t *alah, uint64_t *blbh, const uint64_t *a,
			   const uint64_t *b, const size_t qwords_len);

void karatzuba_add2_avx2(uint64_t *z, const uint64_t *x, const uint64_t *y,
			 const size_t qwords_len);

void karatzuba_add2_avx512(uint64_t *z, const uint64_t *x, const uint64_t *y,
			   const size_t qwords_len);

void karatzuba_add3_avx2(uint64_t *c, const uint64_t *mid,
			 const size_t qwords_len);
void karatzuba_add3_avx512(uint64_t *c, const uint64_t *mid,
			   const size_t qwords_len);

// -------------------- FUNCTIONS NEEDED FOR GF2X INVERSION --------------------
// c = a^2
void gf2x_sqr_pclmul(dbl_pad_r_t *c, const pad_r_t *a);
void gf2x_sqr_vpclmul(dbl_pad_r_t *c, const pad_r_t *a);

// The k-squaring function computes c = a^(2^k) % (x^r - 1),
// It is required by inversion, where l_param is derived from k.
void k_sqr_avx2(pad_r_t *c, const pad_r_t *a, size_t l_param);
void k_sqr_avx512(pad_r_t *c, const pad_r_t *a, size_t l_param);

// c = a mod (x^r - 1)
void gf2x_red_avx2(pad_r_t *c, const dbl_pad_r_t *a);
void gf2x_red_avx512(pad_r_t *c, const dbl_pad_r_t *a);
#endif

// GF2X methods struct
typedef struct gf2x_ctx_st {
	size_t mul_base_qwords;
	void (*mul_base)(uint64_t *c, const uint64_t *a, const uint64_t *b);
	void (*karatzuba_add1)(uint64_t *alah, uint64_t *blbh,
			       const uint64_t *a, const uint64_t *b,
			       const size_t qwords_len);
	void (*karatzuba_add2)(uint64_t *z, const uint64_t *x,
			       const uint64_t *y, const size_t qwords_len);
	void (*karatzuba_add3)(uint64_t *c, const uint64_t *mid,
			       const size_t qwords_len);

	void (*sqr)(dbl_pad_r_t *c, const pad_r_t *a);
	void (*k_sqr)(pad_r_t *c, const pad_r_t *a, size_t l_param);

	void (*red)(pad_r_t *c, const dbl_pad_r_t *a);
} gf2x_ctx;

// Used in gf2x_inv.c to avoid initializing the context many times.
void gf2x_mod_mul_with_ctx(pad_r_t *c, const pad_r_t *a, const pad_r_t *b,
			   const gf2x_ctx *ctx);

static inline void gf2x_ctx_init(gf2x_ctx *ctx)
{
#if defined(X86_64)
	if (is_avx512_enabled()) {
		ctx->karatzuba_add1 = karatzuba_add1_avx512;
		ctx->karatzuba_add2 = karatzuba_add2_avx512;
		ctx->karatzuba_add3 = karatzuba_add3_avx512;
		ctx->k_sqr = k_sqr_avx512;
		ctx->red = gf2x_red_avx512;
	} else if (is_avx2_enabled()) {
		ctx->karatzuba_add1 = karatzuba_add1_avx2;
		ctx->karatzuba_add2 = karatzuba_add2_avx2;
		ctx->karatzuba_add3 = karatzuba_add3_avx2;
		ctx->k_sqr = k_sqr_avx2;
		ctx->red = gf2x_red_avx2;
	} else
#endif
	{
		ctx->karatzuba_add1 = karatzuba_add1_port;
		ctx->karatzuba_add2 = karatzuba_add2_port;
		ctx->karatzuba_add3 = karatzuba_add3_port;
		ctx->k_sqr = k_sqr_port;
		ctx->red = gf2x_red_port;
	}

#if defined(X86_64)
	if (is_vpclmul_enabled() && is_avx512_enabled()) {
		ctx->mul_base_qwords = GF2X_VPCLMUL_BASE_QWORDS;
		ctx->mul_base = gf2x_mul_base_vpclmul;
		ctx->sqr = gf2x_sqr_vpclmul;
	} else if (is_pclmul_enabled()) {
		ctx->mul_base_qwords = GF2X_PCLMUL_BASE_QWORDS;
		ctx->mul_base = gf2x_mul_base_pclmul;
		ctx->sqr = gf2x_sqr_pclmul;
	} else
#endif
	{
		ctx->mul_base_qwords = GF2X_PORT_BASE_QWORDS;
		ctx->mul_base = gf2x_mul_base_port;
		ctx->sqr = gf2x_sqr_port;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* BIKE_GF2X_INTERNAL_H */
