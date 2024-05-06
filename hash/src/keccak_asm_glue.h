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
 * https://github.com/XKCP/XKCP
 *
The eXtended Keccak Code Package (XKCP)
https://github.com/XKCP/XKCP

Keccak, designed by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche.

Implementation by the designers, hereby denoted as "the implementer".

For more information, feedback or questions, please refer to the Keccak Team website:
https://keccak.team/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

#ifndef KECCAK_ASM_GLUE_H
#define KECCAK_ASM_GLUE_H

#include "lc_sha3.h"
#include "sha3_common.h"

#define SnP_width 1600

#ifdef __cplusplus
extern "C" {
#endif

/**
 * StaticInitialize - Function called at least once before any use of the other
 * functions, possibly to initialize global variables.
 */
/**
 * Initialize - Function to initialize the state to the logical value 0^width.
 * @param  state   Pointer to the state to initialize.
 */
static inline void sha3_224_asm_init(void *_state,
				     void (*StaticInitialize)(void),
				     void (*Initialize)(void *state))
{
	struct lc_sha3_224_state *ctx = _state;

	if (!ctx)
		return;

	if (StaticInitialize)
		StaticInitialize();
	Initialize(ctx->state);

	sha3_224_init_common(_state);
}

static inline void sha3_256_asm_init(void *_state,
				     void (*StaticInitialize)(void),
				     void (*Initialize)(void *state))
{
	struct lc_sha3_256_state *ctx = _state;

	if (!ctx)
		return;

	if (StaticInitialize)
		StaticInitialize();
	Initialize(ctx->state);

	sha3_256_init_common(_state);
}

static inline void sha3_384_asm_init(void *_state,
				     void (*StaticInitialize)(void),
				     void (*Initialize)(void *state))
{
	struct lc_sha3_384_state *ctx = _state;

	if (!ctx)
		return;

	if (StaticInitialize)
		StaticInitialize();
	Initialize(ctx->state);

	sha3_384_init_common(_state);
}

static inline void sha3_512_asm_init(void *_state,
				     void (*StaticInitialize)(void),
				     void (*Initialize)(void *state))
{
	struct lc_sha3_512_state *ctx = _state;

	if (!ctx)
		return;

	if (StaticInitialize)
		StaticInitialize();
	Initialize(ctx->state);

	sha3_512_init_common(_state);
}

static inline void shake_128_asm_init(void *_state,
				      void (*StaticInitialize)(void),
				      void (*Initialize)(void *state))
{
	struct lc_shake_128_state *ctx = _state;

	if (!ctx)
		return;

	if (StaticInitialize)
		StaticInitialize();
	Initialize(ctx->state);

	shake_128_init_common(_state);
}

static inline void shake_256_asm_init(void *_state,
				      void (*StaticInitialize)(void),
				      void (*Initialize)(void *state))
{
	struct lc_sha3_256_state *ctx = _state;

	if (!ctx)
		return;

	if (StaticInitialize)
		StaticInitialize();
	Initialize(ctx->state);

	shake_256_init_common(_state);
}

static inline void cshake_128_asm_init(void *_state,
				       void (*StaticInitialize)(void),
				       void (*Initialize)(void *state))
{
	struct lc_shake_128_state *ctx = _state;

	if (!ctx)
		return;

	if (StaticInitialize)
		StaticInitialize();
	Initialize(ctx->state);

	cshake_128_init_common(_state);
}

static inline void cshake_256_asm_init(void *_state,
				       void (*StaticInitialize)(void),
				       void (*Initialize)(void *state))
{
	struct lc_sha3_256_state *ctx = _state;

	if (!ctx)
		return;

	if (StaticInitialize)
		StaticInitialize();
	Initialize(ctx->state);

	cshake_256_init_common(_state);
}

/**
 * AddBytes - Function to add (in GF(2), using bitwise exclusive-or) data given
 * as bytes into the state.
 *
 * The bit positions that are affected by this function are
 * from @a offset*8 to @a offset*8 + @a length*8.
 *
 * (The bit positions, the x,y,z coordinates and their link are defined in the
 * "Keccak reference".)
 * @param  state   Pointer to the state.
 * @param  data    Pointer to the input data.
 * @param  offset  Offset in bytes within the state.
 * @param  length  Number of bytes.
 * @pre    0 ≤ @a offset < (width in bytes)
 * @pre    0 ≤ @a offset + @a length ≤ (width in bytes)
 */
/**
 * Permute - Function to apply the permutation on the state.
 * @param  state   Pointer to the state.
 */
/**
 * FastLoop_Absorb - Function that has the same behavior as repeatedly calling
 * - SnP_AddBytes() with a block of @a laneCount lanes from data;
 * - SnP_Permute() on the state @a state;
 * - and advancing @a data by @a laneCount lane sizes, until not enough data
 *   are available.
 * The function returns the number of bytes processed from @a data.
 * @param  state   Pointer to the state.
 * @param  laneCount   The number of lanes processed each time (i.e., the block
 * size in lanes).
 * @param  data    Pointer to the data to use as input.
 * @param  dataByteLen The length of the input data in bytes.
 * @returns    The number of bytes processed.
 * @pre    0 < @a laneCount < SnP_laneCount
 */
static inline void
keccak_asm_absorb(void *_state, const uint8_t *in, size_t inlen,
		  void (*AddBytes)(void *state, const unsigned char *data,
				   size_t offset, size_t length),
		  void (*Permute)(void *state),
		  size_t (*FastLoop_Absorb)(void *state, unsigned int laneCount,
					    const unsigned char *data,
					    size_t dataByteLen))
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_224_state *ctx = _state;
	size_t partial;

	if (!ctx)
		return;

	partial = ctx->msg_len % ctx->r;
	ctx->squeeze_more = 0;
	ctx->msg_len += inlen;

	/* Check if we have a partial block stored */
	if (partial) {
		size_t todo = ctx->r - partial;

		/*
		 * If the provided data is small enough to fit in the partial
		 * buffer, copy it and leave it unprocessed.
		 */
		if (inlen < todo) {
			AddBytes(ctx->state, in, partial, inlen);
			return;
		}

		/*
		 * The input data is large enough to fill the entire partial
		 * block buffer. Thus, we fill it and transform it.
		 */
		AddBytes(ctx->state, in, partial, todo);
		inlen -= todo;
		in += todo;

		Permute(ctx->state);
	}

	while (inlen >= ctx->r) {
		/* processing full blocks first */
		if (FastLoop_Absorb && (ctx->r % (SnP_width / 200)) == 0) {
			/* fast lane: whole lane rate */
			size_t j = FastLoop_Absorb(ctx->state,
						   ctx->r / (SnP_width / 200),
						   in, inlen);
			inlen -= j;
			in += j;
		} else {
			for (; inlen >= ctx->r; inlen -= ctx->r, in += ctx->r) {
				AddBytes(ctx->state, in, 0, ctx->r);
				Permute(ctx->state);
			}
		}
	}

	/* If we have data left, copy it into the partial block buffer */
	AddBytes(ctx->state, in, 0, inlen);
}

static inline void keccak_asm_absorb_last_bits(
	void *_state,
	void (*AddByte)(void *state, unsigned char data, unsigned int offset),
	void (*Permute)(void *state))
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_224_state *ctx = _state;
	unsigned short partial;

	if (ctx->squeeze_more)
		return; /* Too late for additional input */

	partial = (unsigned short)(ctx->msg_len % ctx->r);

	/* Last few bits, whose delimiter coincides with first bit of padding */
	AddByte(ctx->state, ctx->padding, (unsigned int)partial);

	/*
	 * If the first bit of padding is at position rate - 1, we need a whole
	 * new block for the second bit of padding.
	 */
	if ((ctx->padding >= 0x80) && (partial == (ctx->r - 1)))
		Permute(ctx->state);

	/* Second bit of padding */
	AddByte(ctx->state, 0x80, ctx->r - 1);

	Permute(ctx->state);
	ctx->squeeze_more = 1;
}

/**
 * AddByte - Function to add (in GF(2), using bitwise exclusive-or) a given
 * byte into the state.
 *
 * The bit positions that are affected by this function are
 * from @a offset*8 to @a offset*8 + 8.
 * (The bit positions, the x,y,z coordinates and their link are defined in the
 * "Keccak reference".)
 * @param  state   Pointer to the state.
 * @param  data    The input byte.
 * @param  offset  Offset in bytes within the state.
 * @pre    0 ≤ @a offset < (width in bytes)
 */
/**
 * ExtractBytes - Function to retrieve data from the state.
 * The bit positions that are retrieved by this function are
 * from @a offset*8 to @a offset*8 + @a length*8.
 * (The bit positions, the x,y,z coordinates and their link are defined in the
 * "Keccak reference".)
 * @param  state   Pointer to the state.
 * @param  data    Pointer to the area where to store output data.
 * @param  offset  Offset in bytes within the state.
 * @param  length  Number of bytes.
 * @pre    0 ≤ @a offset < (width in bytes)
 * @pre    0 ≤ @a offset + @a length ≤ (width in bytes)
 */
static inline void keccak_asm_squeeze(
	void *_state, uint8_t *digest,
	void (*AddByte)(void *state, unsigned char data, unsigned int offset),
	void (*Permute)(void *state),
	void (*ExtractBytes)(const void *state, unsigned char *data,
			     size_t offset, size_t length))
{
	/*
	 * All lc_sha3_*_state are equal except for the last entry, thus we use
	 * the largest state.
	 */
	struct lc_sha3_224_state *ctx = _state;
	size_t i = 0, j, digest_len, partialBlock;
	unsigned int rateInBytes = ctx->r;

	if (!ctx || !digest)
		return;

	if (!ctx->squeeze_more)
		keccak_asm_absorb_last_bits(ctx, AddByte, Permute);

	digest_len = ctx->digestsize;

	while (i < digest_len) {
		if ((ctx->offset == ctx->r) &&
		    (digest_len - i >= rateInBytes)) {
			for (j = digest_len - i; j >= rateInBytes;
			     j -= rateInBytes) {
				Permute(ctx->state);
				ExtractBytes(ctx->state, digest, 0,
					     rateInBytes);
				digest += rateInBytes;
			}
			i = digest_len - j;
		} else {
			/* normal lane: using the message queue */
			if (ctx->offset == rateInBytes) {
				Permute(ctx->state);
				ctx->offset = 0;
			}
			if (digest_len - i > rateInBytes - ctx->offset)
				partialBlock = rateInBytes - ctx->offset;
			else
				partialBlock = digest_len - i;
			i += partialBlock;

			ExtractBytes(ctx->state, digest, ctx->offset,
				     partialBlock);
			digest += partialBlock;
			ctx->offset += (uint8_t)partialBlock;
		}
	}
}

#ifdef __cplusplus
}
#endif

#endif /* KECCAK_ASM_GLUE_H */
