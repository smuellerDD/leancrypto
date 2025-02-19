/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/awslabs/bike-kem
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#ifndef BIKE_GF2X_H
#define BIKE_GF2X_H

#include "bike_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

// c = a+b mod (x^r - 1)
static inline void gf2x_mod_add(pad_r_t *c, const pad_r_t *a, const pad_r_t *b)
{
	const uint64_t *a_qwords = (const uint64_t *)a;
	const uint64_t *b_qwords = (const uint64_t *)b;
	uint64_t *c_qwords = (uint64_t *)c;
	unsigned int i;

	for (i = 0; i < LC_BIKE_R_PADDED_QWORDS; i++)
		c_qwords[i] = a_qwords[i] ^ b_qwords[i];
}

// c = a*b mod (x^r - 1)
void gf2x_mod_mul(pad_r_t *c, const pad_r_t *a, const pad_r_t *b,
		  dbl_pad_r_t *t,
		  uint64_t secure_buffer[LC_SECURE_BUFFER_QWORDS]);

// c = a^-1 mod (x^r - 1)
int gf2x_mod_inv(pad_r_t *c, const pad_r_t *a);

#ifdef __cplusplus
}
#endif

#endif /* BIKE_GF2X_H */
