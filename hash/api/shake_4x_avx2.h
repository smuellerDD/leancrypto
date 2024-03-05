/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef SHAKE_4X_AVX2_H
#define SHAKE_4X_AVX2_H

#include "ext_headers.h"
#include "ext_headers_x86.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	__m256i s[25];
} keccakx4_state;

void shake128x4_absorb_once(keccakx4_state *state, const uint8_t *in0,
			    const uint8_t *in1, const uint8_t *in2,
			    const uint8_t *in3, size_t inlen);

void shake128x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
			      uint8_t *out3, size_t nblocks,
			      keccakx4_state *state);

void shake256x4_absorb_once(keccakx4_state *state, const uint8_t *in0,
			    const uint8_t *in1, const uint8_t *in2,
			    const uint8_t *in3, size_t inlen);

void shake256x4_squeezeblocks(uint8_t *out0, uint8_t *out1, uint8_t *out2,
			      uint8_t *out3, size_t nblocks,
			      keccakx4_state *state);

void shake128x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
		size_t outlen, const uint8_t *in0, const uint8_t *in1,
		const uint8_t *in2, const uint8_t *in3, size_t inlen);

void shake256x4(uint8_t *out0, uint8_t *out1, uint8_t *out2, uint8_t *out3,
		size_t outlen, const uint8_t *in0, const uint8_t *in1,
		const uint8_t *in2, const uint8_t *in3, size_t inlen);

#ifdef __cplusplus
}
#endif

#endif /* SHAKE_4X_AVX2_H */
