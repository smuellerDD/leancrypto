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

#include "ext_headers.h"

#include "bike_internal.h"
#include "bike_sampling.h"
#include "bike_sampling_internal.h"
#include "bike_utilities.h"
#include "lc_memset_secure.h"
#include "lc_sha3.h"

#if defined(UNIFORM_SAMPLING)
static inline get_rand_mod_len(uint32_t *rand_pos, const uint32_t len,
			       struct lc_hash_ctx *prf_state)
{
	const uint64_t mask = LC_BIKE_MASK(bit_scan_reverse_vartime(len));

	lc_hash_set_digestsize(prf_state, sizeof(*rand_pos));

	do {
		// Generate a 32 bits (pseudo) random value.
		// This can be optimized to take only 16 bits.
		lc_hash_final(prf_state, (uint8_t *)rand_pos);

		// Mask relevant bits only
		(*rand_pos) &= mask;

		// Break if a number that is smaller than len is found.
		if ((*rand_pos) < len) {
			break;
		}

	} while (1 == 1);
}

static void generate_indices_mod_z(idx_t *out, const size_t num_indices,
				   const size_t z,
				   struct lc_hash_ctx *prf_state)
{
	size_t ctr = 0;

	// Generate num_indices unique (pseudo) random numbers modulo z.
	do {
		CKINT(get_rand_mod_len(&out[ctr], z, prf_state));

		// Check if the index is new and increment the counter if it is.
		int is_new = 1;
		for (size_t i = 0; i < ctr; i++) {
			if (out[i] == out[ctr]) {
				is_new = 0;
				break;
			}
		}
		ctr += is_new;
	} while (ctr < num_indices);
}
#endif

static void sample_indices_fisher_yates(idx_t *out, unsigned int num_indices,
					idx_t max_idx_val,
					struct lc_hash_ctx *prf_state)
{
#define CWW_RAND_BYTES 4

	lc_hash_set_digestsize(prf_state, CWW_RAND_BYTES);

	for (unsigned int i = num_indices; i-- > 0;) {
		uint64_t rand = 0ULL;

		lc_hash_final(prf_state, (uint8_t *)&rand);

		rand *= (max_idx_val - i);

		// new index l is such that i <= l < max_idx_val
		uint32_t l = i + (uint32_t)(rand >> (CWW_RAND_BYTES * 8));

		// Loop over (the end of) the output array to determine if l is a duplicate
		uint32_t is_dup = 0;
		for (size_t j = i + 1; j < num_indices; ++j) {
			is_dup |= secure_cmp32(l, out[j]);
		}

		// if l is a duplicate out[i] gets i else out[i] gets l
		// mask is all 1 if l is a duplicate, all 0 else
		uint32_t mask = -is_dup;
		out[i] = (mask & i) ^ (~mask & l);
	}
}

static inline void generate_sparse_rep_for_sk(pad_r_t *r, idx_t *wlist,
					      struct lc_hash_ctx *prf_state,
					      sampling_ctx *ctx)
{
	idx_t wlist_temp[LC_BIKE_D] = { 0 };

#if defined(UNIFORM_SAMPLING)
	generate_indices_mod_z(wlist_temp, LC_BIKE_D, LC_BIKE_R_BITS,
			       prf_state);
#else
	sample_indices_fisher_yates(wlist_temp, LC_BIKE_D, LC_BIKE_R_BITS,
				    prf_state);
#endif

	memcpy(wlist, wlist_temp, LC_BIKE_D * sizeof(idx_t));
	ctx->secure_set_bits(r, 0, wlist, LC_BIKE_D);

	lc_memset_secure((uint8_t *)wlist_temp, 0, sizeof(*wlist_temp));
}

void generate_secret_key(pad_r_t *h0, pad_r_t *h1, idx_t *h0_wlist,
			 idx_t *h1_wlist, const seed_t *seed)
{
	// Initialize the sampling context.
	sampling_ctx ctx = { 0 };
	LC_SHAKE_256_CTX_ON_STACK(prf_state);

	sampling_ctx_init(&ctx);

	lc_hash_init(prf_state);
	lc_hash_update(prf_state, seed->raw, sizeof(*seed));

	generate_sparse_rep_for_sk(h0, h0_wlist, prf_state, &ctx);
	generate_sparse_rep_for_sk(h1, h1_wlist, prf_state, &ctx);

	lc_hash_zero(prf_state);
}

void generate_error_vector(pad_e_t *e, const seed_t *seed)
{
	// Initialize the sampling context.
	sampling_ctx ctx;
	LC_SHAKE_256_CTX_ON_STACK(prf_state);

	sampling_ctx_init(&ctx);

	lc_hash_init(prf_state);
	lc_hash_update(prf_state, seed->raw, sizeof(*seed));

	idx_t wlist[LC_BIKE_T];
#if defined(UNIFORM_SAMPLING)
	ctx.sample_error_vec_indices(wlist, prf_state);
#else
	sample_indices_fisher_yates(wlist, LC_BIKE_T, LC_BIKE_N_BITS,
				    prf_state);
#endif

	// (e0, e1) hold bits 0..R_BITS-1 and R_BITS..2*R_BITS-1 of the error, resp.
	ctx.secure_set_bits(&e->val[0], 0, wlist, LC_BIKE_T);
	ctx.secure_set_bits(&e->val[1], LC_BIKE_R_BITS, wlist, LC_BIKE_T);

	// Clean the padding of the elements.
	PE0_RAW(e)[LC_BIKE_R_BYTES - 1] &= LC_BIKE_LAST_R_BYTE_MASK;
	PE1_RAW(e)[LC_BIKE_R_BYTES - 1] &= LC_BIKE_LAST_R_BYTE_MASK;
	memset(&PE0_RAW(e)[LC_BIKE_R_BYTES], 0,
	       LC_BIKE_R_PADDED_BYTES - LC_BIKE_R_BYTES);
	memset(&PE1_RAW(e)[LC_BIKE_R_BYTES], 0,
	       LC_BIKE_R_PADDED_BYTES - LC_BIKE_R_BYTES);

	lc_hash_zero(prf_state);
	lc_memset_secure((uint8_t *)wlist, 0, sizeof(*wlist));
}
