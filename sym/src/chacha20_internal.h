/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef CHACHA20_INTERNAL_H
#define CHACHA20_INTERNAL_H

#include "lc_chacha20.h"
#include "lc_chacha20_private.h"
#include "lc_sym.h"
#include "xor.h"

#ifdef __cplusplus
extern "C" {
#endif

void cc20_selftest(int *tested, const char *impl);
int cc20_setkey(struct lc_sym_state *ctx, const uint8_t *key, size_t keylen);
int cc20_setiv(struct lc_sym_state *ctx, const uint8_t *iv, size_t ivlen);
void cc20_init(struct lc_sym_state *ctx);

static inline void cc20_crypt_asm(struct lc_sym_state *ctx, const uint8_t *in,
				  uint8_t *out, size_t len,
			   void (*chacha20_asm)(uint8_t *out,
						const uint8_t *in, size_t len,
						const uint32_t key[8],
						const uint32_t counter[4]))
{
	while (len > LC_CC20_BLOCK_SIZE) {
		size_t todo = len &~ (LC_CC20_BLOCK_SIZE - 1);
		size_t blocks = len / LC_CC20_BLOCK_SIZE;

		/*
		 * Identify a wrap of the counter and only perform the
		 * operation up to the wrap.
		 */
		if (ctx->counter[0] + blocks < ctx->counter[0]) {
			blocks = 0 - ctx->counter[0];
			todo = blocks * LC_CC20_BLOCK_SIZE;
		}

		chacha20_asm(out, in, todo, ctx->key.u, ctx->counter);

		ctx->counter[0] += (uint32_t)blocks;
		cc20_counter_overflow(ctx);

		in += todo;
		out += todo;
		len -= todo;
	}

	if (len) {
		uint8_t keystream[LC_CC20_BLOCK_SIZE]
			__align(sizeof(uint64_t)) = { 0 };

		chacha20_asm(keystream, keystream, sizeof(keystream),
			     ctx->key.u, ctx->counter);
		cc20_inc_counter(ctx);

		if (in != out)
			memcpy(out, in, len);

		xor_64(out, keystream, len);

		lc_memset_secure(keystream, 0, sizeof(keystream));
	}
}

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_INTERNAL_H */
