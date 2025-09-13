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

#ifndef KECCAK_INTERNAL_H
#define KECCAK_INTERNAL_H

#include "bitshift.h"
#include "conv_be_le.h"
#include "ext_headers_internal.h"
#include "lc_sha3.h"
#include "math_helper.h"
#include "sponge_common.h"
#include "xor.h"

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

#if (defined(LC_BIG_ENDIAN) || __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
/*
 * This function works on both endianesses, but since it has more code than
 * the little endian code base, there is a special case for little endian.
 */
static inline void sha3_fill_state_bytes(uint64_t *state, const uint8_t *in,
					 size_t byte_offset, size_t inlen)
{
	sponge_fill_state_bytes(state, in, byte_offset, inlen, le_bswap64);
}

#elif (defined(LC_LITTLE_ENDIAN) || __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)

static inline void sha3_fill_state_bytes(uint64_t *state, const uint8_t *in,
					 size_t byte_offset, size_t inlen)
{
	uint8_t *_state = (uint8_t *)state;

	xor_64(_state + byte_offset, in, inlen);
}

#else
#error "Endianess not defined"
#endif

#ifdef __cplusplus
}
#endif

#endif /* KECCAK_INTERNAL_H */
