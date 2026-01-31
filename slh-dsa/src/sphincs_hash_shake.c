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

#include "lc_sha3.h"
#include "signature_domain_separation.h"
#include "sphincs_type.h"
#include "sphincs_hash.h"
#include "sphincs_address.h"
#include "sphincs_utils.h"
#include "ret_checkers.h"

/**
 * Computes the message-dependent randomness R, using a secret seed and an
 * optional randomization value as well as the message.
 */
int gen_message_random(uint8_t R[LC_SPX_N], const uint8_t sk_prf[LC_SPX_N],
		       const uint8_t optrand[LC_SPX_N], const uint8_t *m,
		       size_t mlen, struct lc_sphincs_ctx *ctx)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_SPHINCS_HASH_TYPE);
	int ret;

	CKINT(lc_hash_init(hash_ctx));
	lc_hash_update(hash_ctx, sk_prf, LC_SPX_N);
	lc_hash_update(hash_ctx, optrand, LC_SPX_N);
	CKINT(signature_domain_separation(hash_ctx, ctx->slh_dsa_internal,
					  ctx->sphincs_prehash_type,
					  ctx->userctx, ctx->userctxlen, m,
					  mlen, 0, LC_SPHINCS_NIST_CATEGORY));
	CKINT(lc_hash_set_digestsize(hash_ctx, LC_SPX_N));
	lc_hash_final(hash_ctx, R);

	lc_hash_zero(hash_ctx);

out:
	return ret;
}

/**
 * Computes the message hash using R, the public key, and the message.
 * Outputs the message digest and the index of the leaf. The index is split in
 * the tree index and the leaf index, for convenient copying to an address.
 */
int hash_message(uint8_t *digest, uint64_t *tree, uint32_t *leaf_idx,
		 const uint8_t R[LC_SPX_N], const uint8_t pk[LC_SPX_PK_BYTES],
		 const uint8_t *m, size_t mlen, struct lc_sphincs_ctx *ctx)
{
#define LC_SPX_TREE_BITS (LC_SPX_TREE_HEIGHT * (LC_SPX_D - 1))
#define LC_SPX_TREE_BYTES ((LC_SPX_TREE_BITS + 7) / 8)
#define LC_SPX_LEAF_BITS LC_SPX_TREE_HEIGHT
#define LC_SPX_LEAF_BYTES ((LC_SPX_LEAF_BITS + 7) / 8)
#define LC_SPX_DGST_BYTES                                                      \
	(LC_SPX_FORS_MSG_BYTES + LC_SPX_TREE_BYTES + LC_SPX_LEAF_BYTES)

	uint8_t buf[LC_SPX_DGST_BYTES];
	uint8_t *bufp = buf;
	int ret;
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_SPHINCS_HASH_TYPE);

	CKINT(lc_hash_init(hash_ctx));
	lc_hash_update(hash_ctx, R, LC_SPX_N);
	lc_hash_update(hash_ctx, pk, LC_SPX_PK_BYTES);
	CKINT(signature_domain_separation(hash_ctx, ctx->slh_dsa_internal,
					  ctx->sphincs_prehash_type,
					  ctx->userctx, ctx->userctxlen, m,
					  mlen, 0, LC_SPHINCS_NIST_CATEGORY));
	CKINT(lc_hash_set_digestsize(hash_ctx, sizeof(buf)));
	lc_hash_final(hash_ctx, buf);

	lc_hash_zero(hash_ctx);

	memcpy(digest, bufp, LC_SPX_FORS_MSG_BYTES);
	bufp += LC_SPX_FORS_MSG_BYTES;

#if LC_SPX_TREE_BITS > 64
#error For given height and depth, 64 bits cannot represent all subtrees
#endif

	if (LC_SPX_D == 1) {
		*tree = 0;
	} else {
		*tree = bytes_to_ull(bufp, LC_SPX_TREE_BYTES);
		*tree &= (~(uint64_t)0) >> (64 - LC_SPX_TREE_BITS);
	}
	bufp += LC_SPX_TREE_BYTES;

	*leaf_idx = (uint32_t)bytes_to_ull(bufp, LC_SPX_LEAF_BYTES);
	*leaf_idx &= (~(uint32_t)0) >> (32 - LC_SPX_LEAF_BITS);

out:
	return ret;
}
