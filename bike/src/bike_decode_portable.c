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

#include "bike_decode.h"
#include "bike_decode_internal.h"
#include "bike_utilities.h"
#include "build_bug_on.h"
#include "small_stack_support.h"

#define R_QWORDS_HALF_LOG2 LC_BIKE_UPTOPOW2(LC_BIKE_R_QWORDS / 2)

static inline void rotr_big(syndrome_t *out, const syndrome_t *in,
			    uint32_t qw_num)
{
	uint32_t idx;

	// For preventing overflows (comparison in bytes)
	BUILD_BUG_ON(sizeof(*out) <=
		     8 * (LC_BIKE_R_QWORDS + (2 * R_QWORDS_HALF_LOG2)));

	*out = *in;

	for (idx = R_QWORDS_HALF_LOG2; idx >= 1; idx >>= 1) {
		// Convert 32 bit mask to 64 bit mask
		const uint64_t mask =
			((uint32_t)secure_l32_mask(qw_num, idx) + 1U) - 1ULL;
		size_t i;

		qw_num = qw_num - (idx & (uint32_t)u64_barrier(mask));

		// Rotate R_QWORDS quadwords and another idx quadwords,
		// as needed by the next iteration.
		for (i = 0; i < (LC_BIKE_R_QWORDS + idx); i++) {
			out->qw[i] = (out->qw[i] & u64_barrier(~mask)) |
				     (out->qw[i + idx] & u64_barrier(mask));
		}
	}
}

static inline void rotr_small(syndrome_t *out, const syndrome_t *in,
			      const size_t bits)
{
	// Convert |bits| to 0/1 by using !!bits; then create a mask of 0 or
	// 0xffffffffff Use high_shift to avoid undefined behaviour when doing x << 64;
	const uint64_t mask = (uint64_t)(0 - (!!bits));
	const uint64_t high_shift = (64 - bits) & u64_barrier(mask);
	size_t i;

	BUILD_BUG_ON(sizeof(*out) <= (8 * LC_BIKE_R_QWORDS));

	for (i = 0; i < LC_BIKE_R_QWORDS; i++) {
		const uint64_t low_part = in->qw[i] >> bits;
		const uint64_t high_part =
			(in->qw[i + 1] << high_shift) & u64_barrier(mask);

		out->qw[i] = low_part | high_part;
	}
}

void rotate_right_port(syndrome_t *out, const syndrome_t *in,
		       const uint32_t bitscount)
{
	// Rotate (64-bit) quad-words
	rotr_big(out, in, (bitscount / 64));
	// Rotate bits (less than 64)
	rotr_small(out, out, (bitscount % 64));
}

// Duplicates the first R_BITS of the syndrome three times
// |------------------------------------------|
// |  Third copy | Second copy | first R_BITS |
// |------------------------------------------|
// This is required by the rotate functions.
void dup_port(syndrome_t *s)
{
	size_t i;

	s->qw[LC_BIKE_R_QWORDS - 1] =
		(s->qw[0] << LC_BIKE_LAST_R_QWORD_LEAD) |
		(s->qw[LC_BIKE_R_QWORDS - 1] & LC_BIKE_LAST_R_QWORD_MASK);

	for (i = 0; i < (2 * LC_BIKE_R_QWORDS) - 1; i++) {
		s->qw[LC_BIKE_R_QWORDS + i] =
			(s->qw[i] >> LC_BIKE_LAST_R_QWORD_TRAIL) |
			(s->qw[i + 1] << LC_BIKE_LAST_R_QWORD_LEAD);
	}
}

// Use half-adder as described in [1].
void bit_sliced_adder_port(upc_t *upc, syndrome_t *rotated_syndrome,
			   const size_t num_of_slices)
{
	size_t i, j;

	// From cache-memory perspective this loop should be the outside loop
	for (j = 0; j < num_of_slices; j++) {
		for (i = 0; i < LC_BIKE_R_QWORDS; i++) {
			const uint64_t carry = (upc->slice[j].u.qw[i] &
						rotated_syndrome->qw[i]);
			upc->slice[j].u.qw[i] ^= rotated_syndrome->qw[i];
			rotated_syndrome->qw[i] = carry;
		}
	}
}

int bit_slice_full_subtract_port(upc_t *upc, uint8_t val)
{
	struct workspace {
		// Borrow
		uint64_t br[LC_BIKE_R_QWORDS];
	};
	size_t j;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	for (j = 0; j < LC_BIKE_SLICES; j++) {
		const uint64_t lsb_mask = 0 - (val & 0x1);
		size_t i;

		val >>= 1;

		// Perform a - b with c as the input/output carry
		// br = 0 0 0 0 1 1 1 1
		// a  = 0 0 1 1 0 0 1 1
		// b  = 0 1 0 1 0 1 0 1
		// -------------------
		// o  = 0 1 1 0 0 1 1 1
		// c  = 0 1 0 0 1 1 0 1
		//
		// o  = a^b^c
		//            _     __    _ _   _ _     _
		// br = abc + abc + abc + abc = abc + ((a+b))c

		for (i = 0; i < LC_BIKE_R_QWORDS; i++) {
			const uint64_t a = upc->slice[j].u.qw[i];
			const uint64_t b = lsb_mask;
			const uint64_t tmp = ((~a) & b & (~ws->br[i])) |
					     ((((~a) | b) & ws->br[i]));

			upc->slice[j].u.qw[i] = a ^ b ^ ws->br[i];
			ws->br[i] = tmp;
		}
	}

	LC_RELEASE_MEM(ws);
	return 0;
}
