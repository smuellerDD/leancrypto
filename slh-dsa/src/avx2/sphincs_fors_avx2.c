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

#include "ret_checkers.h"
#include "small_stack_support.h"
#include "sphincs_address.h"
#include "sphincs_fors_avx2.h"
#include "sphincs_hash.h"
#include "sphincs_hashx4_avx2.h"
#include "sphincs_thash.h"
#include "sphincs_thashx4_avx2.h"
#include "sphincs_utils.h"
#include "sphincs_utilsx4_avx2.h"

static int fors_gen_sk(unsigned char *sk, const spx_ctx *ctx,
		       uint32_t fors_leaf_addr[8])
{
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_SPHINCS_HASH_TYPE);
	int ret;

	CKINT(prf_addr(hash_ctx, sk, ctx, fors_leaf_addr));
	lc_hash_zero(hash_ctx);

out:
	return ret;
}

static void fors_gen_skx4(unsigned char *sk0, unsigned char *sk1,
			  unsigned char *sk2, unsigned char *sk3,
			  const spx_ctx *ctx, uint32_t fors_leaf_addrx4[4 * 8])
{
	prf_addrx4(sk0, sk1, sk2, sk3, ctx, fors_leaf_addrx4);
}

static int fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
			   const spx_ctx *ctx, uint32_t fors_leaf_addr[8])
{
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_SPHINCS_HASH_TYPE);
	int ret;

	CKINT(thash(hash_ctx, leaf, sk, 1, ctx->pub_seed, fors_leaf_addr));
	lc_hash_zero(hash_ctx);

out:
	return ret;
}

static void fors_sk_to_leafx4(unsigned char *leaf0, unsigned char *leaf1,
			      unsigned char *leaf2, unsigned char *leaf3,
			      const unsigned char *sk0,
			      const unsigned char *sk1,
			      const unsigned char *sk2,
			      const unsigned char *sk3, const spx_ctx *ctx,
			      uint32_t fors_leaf_addrx4[4 * 8])
{
	thashx4_12(leaf0, leaf1, leaf2, leaf3, sk0, sk1, sk2, sk3, 1, ctx,
		   fors_leaf_addrx4);
}

struct fors_gen_leaf_info {
	uint32_t leaf_addrx[4 * 8];
};

static void fors_gen_leafx4(unsigned char *leaf, const spx_ctx *ctx,
			    uint32_t addr_idx, void *info, uint8_t *ws_buf,
			    uint8_t *thash_buf)
{
	struct fors_gen_leaf_info *fors_info = info;
	uint32_t *fors_leaf_addrx4 = fors_info->leaf_addrx;
	unsigned int j;

	(void)ws_buf;
	(void)thash_buf;

	/* Only set the parts that the caller doesn't set */
	for (j = 0; j < 4; j++) {
		set_tree_index(fors_leaf_addrx4 + j * 8, addr_idx + j);
		set_type(fors_leaf_addrx4 + j * 8, LC_SPX_ADDR_TYPE_FORSPRF);
	}

	fors_gen_skx4(leaf + 0 * LC_SPX_N, leaf + 1 * LC_SPX_N,
		      leaf + 2 * LC_SPX_N, leaf + 3 * LC_SPX_N, ctx,
		      fors_leaf_addrx4);

	for (j = 0; j < 4; j++) {
		set_type(fors_leaf_addrx4 + j * 8, LC_SPX_ADDR_TYPE_FORSTREE);
	}

	fors_sk_to_leafx4(leaf + 0 * LC_SPX_N, leaf + 1 * LC_SPX_N,
			  leaf + 2 * LC_SPX_N, leaf + 3 * LC_SPX_N,
			  leaf + 0 * LC_SPX_N, leaf + 1 * LC_SPX_N,
			  leaf + 2 * LC_SPX_N, leaf + 3 * LC_SPX_N, ctx,
			  fors_leaf_addrx4);
}

/**
 * Interprets m as LC_SPX_FORS_HEIGHT-bit unsigned integers.
 * Assumes m contains at least LC_SPX_FORS_HEIGHT * LC_SPX_FORS_TREES bits.
 * Assumes indices has space for LC_SPX_FORS_TREES integers.
 */
static void message_to_indices(uint32_t *indices, const unsigned char *m)
{
	unsigned int i, j;
	unsigned int offset = 0;

	for (i = 0; i < LC_SPX_FORS_TREES; i++) {
		indices[i] = 0;
		for (j = 0; j < LC_SPX_FORS_HEIGHT; j++) {
			indices[i] ^=
				(uint32_t)(((m[offset >> 3] >> (~offset & 0x7)) &
					    0x1)
					   << (LC_SPX_FORS_HEIGHT - 1 - j));
			offset++;
		}
	}
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least LC_SPX_FORS_HEIGHT * LC_SPX_FORS_TREES bits.
 */
int fors_sign_avx2(uint8_t sig[LC_SPX_FORS_BYTES], uint8_t pk[LC_SPX_N],
		   const uint8_t m[LC_SPX_FORS_MSG_BYTES], const spx_ctx *ctx,
		   const uint32_t fors_addr[8])
{
	struct workspace {
		uint32_t indices[LC_SPX_FORS_TREES];
		uint32_t fors_tree_addr[4 * 8];
		uint32_t fors_pk_addr[8];
		struct fors_gen_leaf_info fors_info;
		uint8_t roots[LC_SPX_FORS_TREES * LC_SPX_N];
		uint8_t stackx4[LC_SPX_FORS_HEIGHT * 4 * LC_SPX_N];
	};
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_SPHINCS_HASH_TYPE);
	uint32_t *fors_leaf_addr;
	uint32_t idx_offset;
	unsigned int i;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	fors_leaf_addr = ws->fors_info.leaf_addrx;

	for (i = 0; i < 4; i++) {
		copy_keypair_addr(ws->fors_tree_addr + 8 * i, fors_addr);
		set_type(ws->fors_tree_addr + 8 * i, LC_SPX_ADDR_TYPE_FORSTREE);
		copy_keypair_addr(fors_leaf_addr + 8 * i, fors_addr);
	}
	copy_keypair_addr(ws->fors_pk_addr, fors_addr);
	set_type(ws->fors_pk_addr, LC_SPX_ADDR_TYPE_FORSPK);

	message_to_indices(ws->indices, m);

	for (i = 0; i < LC_SPX_FORS_TREES; i++) {
		idx_offset = i * (1 << LC_SPX_FORS_HEIGHT);

		set_tree_height(ws->fors_tree_addr, 0);
		set_tree_index(ws->fors_tree_addr, ws->indices[i] + idx_offset);

		/* Include the secret key part that produces the selected leaf node. */
		set_type(ws->fors_tree_addr, LC_SPX_ADDR_TYPE_FORSPRF);
		CKINT(fors_gen_sk(sig, ctx, ws->fors_tree_addr));
		set_type(ws->fors_tree_addr, LC_SPX_ADDR_TYPE_FORSTREE);
		sig += LC_SPX_N;

		/* Compute the authentication path for this leaf node. */
		treehashx4(ws->roots + i * LC_SPX_N, sig, ctx, ws->indices[i],
			   idx_offset, LC_SPX_FORS_HEIGHT, fors_gen_leafx4,
			   ws->fors_tree_addr, &ws->fors_info, ws->stackx4,
			   NULL, NULL);

		sig += LC_SPX_N * LC_SPX_FORS_HEIGHT;
	}

	/* Hash horizontally across all tree roots to derive the public key. */
	CKINT(thash(hash_ctx, pk, ws->roots, LC_SPX_FORS_TREES, ctx->pub_seed,
		    ws->fors_pk_addr));

out:
	LC_RELEASE_MEM(ws);
	lc_hash_zero(hash_ctx);
	return ret;
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least LC_SPX_FORS_HEIGHT * LC_SPX_FORS_TREES bits.
 */
int fors_pk_from_sig_avx2(uint8_t pk[LC_SPX_N],
			  const uint8_t sig[LC_SPX_FORS_BYTES],
			  const uint8_t m[LC_SPX_FORS_MSG_BYTES],
			  const spx_ctx *ctx, const uint32_t fors_addr[8])
{
	struct workspace {
		uint32_t indices[LC_SPX_FORS_TREES];
		uint32_t fors_tree_addr[8];
		uint32_t fors_pk_addr[8];
		uint8_t roots[LC_SPX_FORS_TREES * LC_SPX_N];
		uint8_t leaf[LC_SPX_N];
	};
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_SPHINCS_HASH_TYPE);
	uint32_t idx_offset;
	unsigned int i;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	copy_keypair_addr(ws->fors_tree_addr, fors_addr);
	copy_keypair_addr(ws->fors_pk_addr, fors_addr);

	set_type(ws->fors_tree_addr, LC_SPX_ADDR_TYPE_FORSTREE);
	set_type(ws->fors_pk_addr, LC_SPX_ADDR_TYPE_FORSPK);

	message_to_indices(ws->indices, m);

	for (i = 0; i < LC_SPX_FORS_TREES; i++) {
		idx_offset = i * (1 << LC_SPX_FORS_HEIGHT);

		set_tree_height(ws->fors_tree_addr, 0);
		set_tree_index(ws->fors_tree_addr, ws->indices[i] + idx_offset);

		/* Derive the leaf from the included secret key part. */
		CKINT(fors_sk_to_leaf(ws->leaf, sig, ctx, ws->fors_tree_addr));
		sig += LC_SPX_N;

		/* Derive the corresponding root node of this tree. */
		CKINT(compute_root(ws->roots + i * LC_SPX_N, ws->leaf,
				   ws->indices[i], idx_offset, sig,
				   LC_SPX_FORS_HEIGHT, ctx->pub_seed,
				   ws->fors_tree_addr));
		sig += LC_SPX_N * LC_SPX_FORS_HEIGHT;
	}

	/* Hash horizontally across all tree roots to derive the public key. */
	CKINT(thash(hash_ctx, pk, ws->roots, LC_SPX_FORS_TREES, ctx->pub_seed,
		    ws->fors_pk_addr));

out:
	LC_RELEASE_MEM(ws);
	lc_hash_zero(hash_ctx);
	return 0;
}
