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
 */

#ifndef KECCACK_INTERNAL_H
#define KECCACK_INTERNAL_H

#include "ext_headers.h"
#include "lc_sha3.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * All lc_sha3_*_state are equal except for the last entry, thus we use
 * the largest state.
 */
static inline void sha3_fill_state(struct lc_sha3_224_state *ctx,
				   const uint8_t *in)
{
	unsigned int i;

	for (i = 0; i < ctx->rword; i++) {
		ctx->state[i] ^= ptr_to_le64(in);
		in += 8;
	}
}

static inline int sha3_aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

static inline void sha3_fill_state_aligned(struct lc_sha3_224_state *ctx,
					   const uint64_t *in)
{
	unsigned int i;

	for (i = 0; i < ctx->rword; i++) {
		ctx->state[i] ^= le_bswap64(*in);
		in++;
	}
}

#if defined(LC_BIG_ENDIAN) || defined(__BIG_ENDIAN)

/*
 * This function works on both endianesses, but since it has more code than
 * the little endian code base, there is a special case for little endian.
 */
static inline void sha3_fill_state_bytes(struct lc_sha3_224_state *ctx,
					 size_t byte_offset, const uint8_t *in,
					 size_t inlen)
{
	unsigned int i;
	uint64_t *state = ctx->state;
	union {
		uint64_t dw;
		uint8_t b[sizeof(uint64_t)];
	} tmp;

	state += byte_offset / sizeof(ctx->state[0]);

	i = byte_offset & (sizeof(tmp) - 1);

	tmp.dw = 0;

	/*
	 * This loop simply XORs the data in *in with the state starting from
	 * byte_offset. The complication is that the simple XOR of the *in bytes
	 * with the respective bytes in the state only works on little endian
	 * systems. For big endian systems, we must apply a byte swap! This
	 * loop therefore concatenates the *in bytes in chunks of uint64_t
	 * and then XORs the byte swapped value into the state.
	 */
	while (inlen) {
		uint8_t ctr;

		for (ctr = 0; i < sizeof(tmp) && (size_t)ctr < inlen;
		     i++, in++, ctr++)
			tmp.b[i] = *in;

		*state ^= le_bswap64(tmp.dw);
		state++;
		inlen -= ctr;
		i = 0;

		/* This line also implies zeroization of the data */
		tmp.dw = 0;
	}
}

#elif defined(LC_LITTLE_ENDIAN) || defined(__LITTLE_ENDIAN)

static inline void sha3_fill_state_bytes(struct lc_sha3_224_state *ctx,
					 size_t byte_offset, const uint8_t *in,
					 size_t inlen)
{
	uint8_t *state = (uint8_t *)ctx->state;

	xor_64(state + byte_offset, in, min_size(ctx->r, inlen));
}

#else
#error "Endianess not defined"
#endif

#ifdef __cplusplus
}
#endif

#endif /* KECCACK_INTERNAL_H */
