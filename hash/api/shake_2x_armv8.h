/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/PQClean/PQClean
 *
 * This file is licensed
 * under Apache 2.0 (https://www.apache.org/licenses/LICENSE-2.0.html)
 * at https://github.com/GMUCERG/PQC_NEON/blob/main/neon/kyber or
 * public domain at https://github.com/cothan/kyber/blob/master/neon
 */

#ifndef SHAKE_X2_ARMV8_H
#define SHAKE_X2_ARMV8_H

/* This code cannot be compiled for the Linux kernel as of now */
#include <arm_neon.h>

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64x2_t v128;

#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72

typedef struct {
	v128 s[25];
} keccakx2_state;

#define NROUNDS 24

extern const uint64_t neon_KeccakF_RoundConstants[NROUNDS];

void KeccakF1600_StatePermutex2(v128 state[25]);

extern void keccak_f1600x2_armce(uint64_t *state, const uint64_t *consts);

void shake128x2_armv8_absorb(keccakx2_state *state, const uint8_t *in0,
			     const uint8_t *in1, size_t inlen);

void shake128x2_armv8_squeezeblocks(uint8_t *out0, uint8_t *out1,
				    size_t nblocks, keccakx2_state *state);

void shake256x2_armv8_absorb(keccakx2_state *state, const uint8_t *in0,
			     const uint8_t *in1, size_t inlen);

void shake256x2_armv8_squeezeblocks(uint8_t *out0, uint8_t *out1,
				    size_t nblocks, keccakx2_state *state);

void shake128x2_armv8(uint8_t *out0, uint8_t *out1, size_t outlen,
		      const uint8_t *in0, const uint8_t *in1, size_t inlen);

void shake256x2_armv8(uint8_t *out0, uint8_t *out1, size_t outlen,
		      const uint8_t *in0, const uint8_t *in1, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif /* SHAKE_X2_ARMV8_H */
