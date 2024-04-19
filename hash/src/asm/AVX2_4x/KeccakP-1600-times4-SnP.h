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
 *
 * This code is derived from "The eXtended Keccak Code Package (XKCP)"
 * https://github.com/XKCP/XKCP
 *
 * Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
 * Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
 * denoted as "the implementer".
 *
 * For more information, feedback or questions, please refer to our websites:
 * http://keccak.noekeon.org/
 * http://keyak.noekeon.org/
 * http://ketje.noekeon.org/
 *
 * To the extent possible under law, the implementer has waived all copyright
 * and related or neighboring rights to the source code in this file.
 * http://creativecommons.org/publicdomain/zero/1.0/
 */

#ifndef _KeccakP_1600_times4_SnP_h_
#define _KeccakP_1600_times4_SnP_h_

#include "shake_4x_avx2.h"

#define KeccakP1600times4_statesSizeInBytes 800
#define KeccakP1600times4_statesAlignment 32
#define KeccakF1600times4_FastLoop_supported
#define KeccakP1600times4_12rounds_FastLoop_supported

#define KeccakP1600times4_StaticInitialize()
void KeccakP1600times4_InitializeAll(void *states);
#define KeccakP1600times4_AddByte(states, instanceIndex, byte, offset)         \
	((unsigned char *)(states))[(instanceIndex) * 8 +                      \
				    ((offset) / 8) * 4 * 8 + (offset) % 8] ^=  \
		(byte)
void KeccakP1600times4_AddBytes(void *states, unsigned int instanceIndex,
				const unsigned char *data, unsigned int offset,
				unsigned int length);
void KeccakP1600times4_AddLanesAll(void *states, const unsigned char *data,
				   unsigned int laneCount,
				   unsigned int laneOffset);
void KeccakP1600times4_OverwriteBytes(void *states, unsigned int instanceIndex,
				      const unsigned char *data,
				      unsigned int offset, unsigned int length);

void KeccakP1600times4_OverwriteLanesAll(void *states,
					 const unsigned char *data,
					 unsigned int laneCount,
					 unsigned int laneOffset);
void KeccakP1600times4_OverwriteWithZeroes(void *states,
					   unsigned int instanceIndex,
					   unsigned int byteCount);
void KeccakP1600times4_PermuteAll_12rounds(void *states);
void KeccakP1600times4_PermuteAll_24rounds(void *states);
void KeccakP1600times4_ExtractBytes(const void *states,
				    unsigned int instanceIndex,
				    unsigned char *data, unsigned int offset,
				    unsigned int length);
void KeccakP1600times4_ExtractLanesAll(const void *states, unsigned char *data,
				       unsigned int laneCount,
				       unsigned int laneOffset);
void KeccakP1600times4_ExtractAndAddBytes(const void *states,
					  unsigned int instanceIndex,
					  const unsigned char *input,
					  unsigned char *output,
					  unsigned int offset,
					  unsigned int length);
void KeccakP1600times4_ExtractAndAddLanesAll(const void *states,
					     const unsigned char *input,
					     unsigned char *output,
					     unsigned int laneCount,
					     unsigned int laneOffset);
size_t KeccakF1600times4_FastLoop_Absorb(void *states, unsigned int laneCount,
					 unsigned int laneOffsetParallel,
					 unsigned int laneOffsetSerial,
					 const unsigned char *data,
					 size_t dataByteLen);
size_t KeccakP1600times4_12rounds_FastLoop_Absorb(
	void *states, unsigned int laneCount, unsigned int laneOffsetParallel,
	unsigned int laneOffsetSerial, const unsigned char *data,
	size_t dataByteLen);

#endif
