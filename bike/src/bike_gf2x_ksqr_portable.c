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
 *
 * The k-squaring algorithm in this file is based on:
 * [1] Nir Drucker, Shay Gueron, and Dusan Kostic. 2020. "Fast polynomial
 * inversion for post quantum QC-MDPC cryptography". Cryptology ePrint Archive,
 * 2020. https://eprint.iacr.org/2020/298.pdf
 */

#include "bike_gf2x_internal.h"
#include "bike_utilities.h"

#define BITS_IN_BYTE (8)

// The k-squaring function computes c = a^(2^k) % (x^r - 1),
// By [1](Observation 1), if
//     a = sum_{j in supp(a)} x^j,
// then
//     a^(2^k) % (x^r - 1) = sum_{j in supp(a)} x^((j * 2^k) % r).
// Therefore, k-squaring can be computed as permutation of the bits of "a":
//     pi0 : j --> (j * 2^k) % r.
// For improved performance, we compute the result by inverted permutation pi1:
//     pi1 : (j * 2^-k) % r --> j.
// Input argument l_param is defined as the value (2^-k) % r.
void k_sqr_port(pad_r_t *c, const pad_r_t *a, const size_t l_param)
{
  memset(c->val.raw, 0, sizeof(c->val));

  // Compute the result byte by byte
  size_t idx = 0;
  for(size_t i = 0; i < LC_BIKE_R_BYTES; i++) {
    for(size_t j = 0; j < BITS_IN_BYTE; j++, idx++) {
      // Bit of "c" at position idx is set to the value of
      // the bit of "a" at position pi1(idx) = (l_param * idx) % R_BITS.
      size_t pos = (l_param * idx) % LC_BIKE_R_BITS;

      size_t  pos_byte = pos >> 3;
      size_t  pos_bit  = pos & 7;
      uint8_t bit      = (a->val.raw[pos_byte] >> pos_bit) & 1;

      c->val.raw[i] |= (bit << j);
    }
  }
  c->val.raw[LC_BIKE_R_BYTES - 1] &= LC_BIKE_LAST_R_BYTE_MASK;
}
