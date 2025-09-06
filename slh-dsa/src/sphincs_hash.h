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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/sphincs/sphincsplus
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#ifndef SPHINCS_HASH_H
#define SPHINCS_HASH_H

#include "ret_checkers.h"
#include "sphincs_type.h"
#include "sphincs_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Computes PRF(pk_seed, sk_seed, addr)
 */
static inline int prf_addr(struct lc_hash_ctx *hash_ctx, uint8_t out[LC_SPX_N],
			   const spx_ctx *ctx, const uint32_t addr[8])
{
	int ret;

	CKINT(lc_hash_init(hash_ctx));
	lc_hash_update(hash_ctx, ctx->pub_seed, LC_SPX_N);
	lc_hash_update(hash_ctx, (uint8_t *)addr, LC_SPX_ADDR_BYTES);
	lc_hash_update(hash_ctx, ctx->sk_seed, LC_SPX_N);
	lc_hash_set_digestsize(hash_ctx, LC_SPX_N);
	lc_hash_final(hash_ctx, out);

out:
	return ret;
}

static inline int prf_addr_ascon(struct lc_hash_ctx *hash_ctx,
				 uint8_t out[LC_SPX_N], const spx_ctx *ctx,
				 const uint32_t addr[8],
				 unsigned int addr_static, uint8_t *ascon_state,
				 int first)
{
	int ret;

	CKINT(lc_hash_init(hash_ctx));
	if (first) {
		lc_hash_update(hash_ctx, ctx->pub_seed, LC_SPX_N);
		lc_hash_update(hash_ctx, (uint8_t *)addr, addr_static);
		memcpy(ascon_state, hash_ctx->hash_state,
		       LC_ASCON_HASH_STATE_SIZE);
	} else {
		memcpy(hash_ctx->hash_state, ascon_state,
		       LC_ASCON_HASH_STATE_SIZE);
	}
	lc_hash_update(hash_ctx, (uint8_t *)addr + addr_static,
		       LC_SPX_ADDR_BYTES - addr_static);
	lc_hash_update(hash_ctx, ctx->sk_seed, LC_SPX_N);
	lc_hash_set_digestsize(hash_ctx, LC_SPX_N);
	lc_hash_final(hash_ctx, out);

out:
	return ret;
}

int gen_message_random(uint8_t R[LC_SPX_N], const uint8_t sk_prf[LC_SPX_N],
		       const uint8_t optrand[LC_SPX_N], const uint8_t *m,
		       size_t mlen, struct lc_sphincs_ctx *ctx);

int hash_message(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
		 const uint8_t R[LC_SPX_N], const uint8_t pk[LC_SPX_PK_BYTES],
		 const uint8_t *m, size_t mlen, struct lc_sphincs_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_HASH_H */
