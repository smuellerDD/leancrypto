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

#include "bike_gf2x_internal.h"
#include "bike_utilities.h"

#define LSB3(x) ((x) & 7)

// 64x64 bit multiplication
// The algorithm is based on the windowing method, for example as in:
// Brent, R. P., Gaudry, P., Thomé, E., & Zimmermann, P. (2008, May), "Faster
// multiplication in GF (2)[x]". In: International Algorithmic Number Theory
// Symposium (pp. 153-166). Springer, Berlin, Heidelberg. In this implementation,
// the last three bits are multiplied using a schoolbook multiplication.
void gf2x_mul_base_port(uint64_t *c, const uint64_t *a, const uint64_t *b)
{
	uint64_t h = 0, l = 0, g1, g2, u[8];
	const uint64_t w = 64;
	const uint64_t s = 3;
	const uint64_t a0 = a[0];
	const uint64_t b0 = b[0];

	// Multiplying 64 bits by 7 can results in an overflow of 3 bits.
	// Therefore, these bits are masked out, and are treated in step 3.
	const uint64_t b0m = b0 & LC_BIKE_MASK(61);
	size_t i;

	// Step 1: Calculate a multiplication table with 8 entries.
	u[0] = 0;
	u[1] = b0m;
	u[2] = u[1] << 1;
	u[3] = u[2] ^ b0m;
	u[4] = u[2] << 1;
	u[5] = u[4] ^ b0m;
	u[6] = u[3] << 1;
	u[7] = u[6] ^ b0m;

	// Step 2: Multiply two elements in parallel in positions i, i+s
	for (i = 0; i < 8; ++i) {
		// use a mask for secret-independent memory access
		l ^= u[i] & secure_cmpeq64_mask(LSB3(a0), i);
		l ^= (u[i] << 3) & secure_cmpeq64_mask(LSB3(a0 >> 3), i);
		h ^= (u[i] >> 61) & secure_cmpeq64_mask(LSB3(a0 >> 3), i);
	}

	for (i = (2 * s); i < w; i += (2 * s)) {
		const size_t i2 = (i + s);
		size_t j;

		g1 = 0;
		g2 = 0;
		for (j = 0; j < 8; ++j) {
			// use a mask for secret-independent memory access
			g1 ^= u[j] & secure_cmpeq64_mask(LSB3(a0 >> i), j);
			g2 ^= u[j] & secure_cmpeq64_mask(LSB3(a0 >> i2), j);
		}

		l ^= (g1 << i) ^ (g2 << i2);
		h ^= (g1 >> (w - i)) ^ (g2 >> (w - i2));
	}

	// Step 3: Multiply the last three bits.
	for (i = 61; i < 64; i++) {
		uint64_t mask = (-((b0 >> i) & 1));

		l ^= ((a0 << i) & mask);
		h ^= ((a0 >> (w - i)) & mask);
	}

	c[0] = l;
	c[1] = h;
}

// c = a^2
void gf2x_sqr_port(dbl_pad_r_t *c, const pad_r_t *a)
{
	const uint64_t *a64 = (const uint64_t *)a;
	uint64_t *c64 = (uint64_t *)c;
	size_t i;

	for (i = 0; i < LC_BIKE_R_QWORDS; i++) {
		gf2x_mul_base_port(&c64[2 * i], &a64[i], &a64[i]);
	}
}
