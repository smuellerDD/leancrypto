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
 *
 * This code is derived from "The eXtended Keccak Code Package (XKCP)"
 * https://github.com/XKCP/XKCP
 *
 * The Keccak-p permutations, designed by Guido Bertoni, Joan Daemen, Michaël
 * Peeters and Gilles Van Assche.
 *
 * Implementation by Ronny Van Keer, hereby denoted as "the implementer".
 *
 * For more information, feedback or questions, please refer to the Keccak Team
 * website: https://keccak.team/
 *
 * To the extent possible under law, the implementer has waived all copyright
 * and related or neighboring rights to the source code in this file.
 * http://creativecommons.org/publicdomain/zero/1.0/
 */

#ifndef _KeccakP_1600_SnP_h_
#define _KeccakP_1600_SnP_h_

#include "ext_headers_internal.h"

#define KeccakF1600_FastLoop_supported
#define KeccakP1600_AVX512_12rounds_FastLoop_supported

#define KeccakP1600_AVX512_StaticInitialize()
void SYSV_ABI KeccakP1600_AVX512_Initialize(void *state);
//void KeccakP1600_AVX512_AddByte(void *state, unsigned char data, unsigned int offset);
static inline void KeccakP1600_AVX512_AddByte(void *state, unsigned char byte,
					      unsigned int offset)
{
	((unsigned char *)(state))[(offset)] ^= (byte);
}
void SYSV_ABI KeccakP1600_AVX512_AddBytes(void *state,
					  const unsigned char *data,
					  size_t offset, size_t length);
void SYSV_ABI KeccakP1600_AVX512_OverwriteBytes(void *state,
						const unsigned char *data,
						unsigned int offset,
						unsigned int length);
void SYSV_ABI KeccakP1600_AVX512_OverwriteWithZeroes(void *state,
						     unsigned int byteCount);
void SYSV_ABI SYSV_ABI KeccakP1600_AVX512_Permute_Nrounds(void *state,
							  unsigned int nrounds);
void SYSV_ABI KeccakP1600_AVX512_Permute_12rounds(void *state);
void SYSV_ABI KeccakP1600_AVX512_Permute_24rounds(void *state);
void SYSV_ABI KeccakP1600_AVX512_ExtractBytes(const void *state,
					      unsigned char *data,
					      size_t offset, size_t length);
void SYSV_ABI KeccakP1600_AVX512_ExtractAndAddBytes(const void *state,
						    const unsigned char *input,
						    unsigned char *output,
						    unsigned int offset,
						    unsigned int length);
size_t SYSV_ABI KeccakF1600_AVX512_FastLoop_Absorb(void *state,
						   unsigned int laneCount,
						   const unsigned char *data,
						   size_t dataByteLen);
size_t SYSV_ABI KeccakP1600_AVX512_12rounds_FastLoop_Absorb(
	void *state, unsigned int laneCount, const unsigned char *data,
	size_t dataByteLen);

#endif /* _KeccakP_1600_SnP_h_ */
