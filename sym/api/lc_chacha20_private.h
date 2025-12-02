/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_CHACHA20_PRIVATE_H
#define LC_CHACHA20_PRIVATE_H

#include "ext_headers.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
#define LC_CC20_KEY_SIZE 32
#define LC_CC20_KEY_SIZE_WORDS (LC_CC20_KEY_SIZE / sizeof(uint32_t))

#define LC_CC20_BLOCK_SIZE ((4 + 8 + 4) * sizeof(uint32_t))
#define LC_CC20_BLOCK_SIZE_WORDS (LC_CC20_BLOCK_SIZE / sizeof(uint32_t))

/*
 * State according to RFC 7539 section 2.3
 *
 * For accelerated ChaCha20 implementatinos, the key and the counter must be
 * aligned to 16 bytes boundary. This is guaranteed when aligning the entire
 * structure to 16 bytes as the constant field is 16 bytes in size.
 */
struct lc_sym_state {
	uint32_t constants[4];
	union {
		uint32_t u[LC_CC20_KEY_SIZE_WORDS];
		uint8_t b[LC_CC20_KEY_SIZE];
	} key;
	uint32_t counter[4];
	union {
		uint32_t u[LC_CC20_BLOCK_SIZE_WORDS];
		uint8_t b[LC_CC20_BLOCK_SIZE];
	} keystream;
	uint8_t keystream_ptr;
};

#define LC_CC20_STATE_SIZE (sizeof(struct lc_sym_state))

static inline void cc20_init_constants(struct lc_sym_state *ctx)
{
	if (!ctx)
		return;

	/* String "expand 32-byte k" */
	ctx->constants[0] = 0x61707865;
	ctx->constants[1] = 0x3320646e;
	ctx->constants[2] = 0x79622d32;
	ctx->constants[3] = 0x6b206574;
}

static inline void cc20_counter_overflow(struct lc_sym_state *ctx)
{
	if (ctx->counter[0] == 0) {
		ctx->counter[1]++;
		if (ctx->counter[1] == 0) {
			ctx->counter[2]++;
			if (ctx->counter[2] == 0)
				ctx->counter[3]++;
		}
	}
}

static inline void cc20_inc_counter(struct lc_sym_state *ctx)
{
	ctx->counter[0]++;
	cc20_counter_overflow(ctx);
}

static inline void cc20_resetkey(struct lc_sym_state *ctx)
{
	ctx->keystream_ptr = 0;
}

/// \endcond

#ifdef __cplusplus
}
#endif

#endif /* LC_CHACHA20_PRIVATE_H */
