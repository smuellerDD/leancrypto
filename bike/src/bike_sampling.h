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

#ifndef BIKE_SAMPLING_H
#define BIKE_SAMPLING_H

#include "bike_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	LC_BIKE_NO_RESTRICTION = 0,
	LC_BIKE_MUST_BE_ODD = 1
} must_be_odd_t;

int generate_secret_key(pad_r_t *h0, pad_r_t *h1, idx_t *h0_wlist,
			 idx_t *h1_wlist, const seed_t *seed);

int generate_error_vector(pad_e_t *e, const seed_t *seed);

#ifdef __cplusplus
}
#endif

#endif /* BIKE_SAMPLING_H */
