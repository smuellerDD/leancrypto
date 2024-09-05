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

#ifndef BIKE_PRF_INTERNAL_H
#define BIKE_PRF_INTERNAL_H

#include "lc_bike.h"
#include "lc_sha3.h"
#include "ret_checkers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct shake256_prf_state_s {
  uint64_t s[25];
  uint8_t  buffer[LC_SHAKE_256_SIZE_BLOCK];
  size_t   curr_pos_in_buffer;
  size_t   rem_invocations;
} shake256_prf_state_t;

typedef shake256_prf_state_t prf_state_t;

#define MAX_PRF_INVOCATION (LC_BIKE_MASK(32))

// Methods for interacting with the PRFs.
ret_t init_prf_state(prf_state_t *s, size_t max_num_invocations,
                     const seed_t *seed);

ret_t get_prf_output(uint8_t *out, prf_state_t *s, size_t len);

void clean_prf_state(prf_state_t *s);

#ifdef __cplusplus
}
#endif

#endif /* BIKE_PRF_INTERNAL_H */
