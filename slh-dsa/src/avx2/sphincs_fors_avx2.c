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
 */
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/sphincs/sphincsplus
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "sphincs_address.h"
#include "sphincs_fors_avx2.h"
#include "sphincs_hash.h"
#include "sphincs_hashx4_avx2.h"
#include "sphincs_thash.h"
#include "sphincs_thashx4_avx2.h"
#include "sphincs_utils.h"
#include "sphincs_utilsx4_avx2.h"

static void fors_gen_sk(unsigned char *sk, const spx_ctx *ctx,
			uint32_t fors_leaf_addr[8])
{
	prf_addr(sk, ctx, fors_leaf_addr);
}

static void fors_gen_skx4(unsigned char *sk0, unsigned char *sk1,
			  unsigned char *sk2, unsigned char *sk3,
			  const spx_ctx *ctx, uint32_t fors_leaf_addrx4[4 * 8])
{
	prf_addrx4(sk0, sk1, sk2, sk3, ctx, fors_leaf_addrx4);
}

static void fors_sk_to_leaf(unsigned char *leaf, const unsigned char *sk,
			    const spx_ctx *ctx, uint32_t fors_leaf_addr[8])
{
	thash(leaf, sk, 1, ctx->pub_seed, fors_leaf_addr);
}

static void fors_sk_to_leafx4(unsigned char *leaf0, unsigned char *leaf1,
			      unsigned char *leaf2, unsigned char *leaf3,
			      const unsigned char *sk0,
			      const unsigned char *sk1,
			      const unsigned char *sk2,
			      const unsigned char *sk3, const spx_ctx *ctx,
			      uint32_t fors_leaf_addrx4[4 * 8])
{
	thashx4(leaf0, leaf1, leaf2, leaf3, sk0, sk1, sk2, sk3, 1, ctx,
		fors_leaf_addrx4);
}

struct fors_gen_leaf_info {
	uint32_t leaf_addrx[4 * 8];
};

static void fors_gen_leafx4(unsigned char *leaf, const spx_ctx *ctx,
			    uint32_t addr_idx, void *info)
{
	struct fors_gen_leaf_info *fors_info = info;
	uint32_t *fors_leaf_addrx4 = fors_info->leaf_addrx;
	unsigned int j;

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
				(uint32_t)(((m[offset >> 3] >> (offset & 0x7)) &
					    0x1)
					   << j);
			offset++;
		}
	}
}

/**
 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
 * Assumes m contains at least LC_SPX_FORS_HEIGHT * LC_SPX_FORS_TREES bits.
 */
void fors_sign_avx2(uint8_t sig[LC_SPX_FORS_BYTES], uint8_t pk[LC_SPX_N],
		    const uint8_t m[LC_SPX_FORS_MSG_BYTES], const spx_ctx *ctx,
		    const uint32_t fors_addr[8])
{
	uint32_t indices[LC_SPX_FORS_TREES];
	unsigned char roots[LC_SPX_FORS_TREES * LC_SPX_N];
	uint32_t fors_tree_addr[4 * 8] = { 0 };
	struct fors_gen_leaf_info fors_info = { 0 };
	uint32_t *fors_leaf_addr = fors_info.leaf_addrx;
	uint32_t fors_pk_addr[8] = { 0 };
	uint32_t idx_offset;
	unsigned int i;

	for (i = 0; i < 4; i++) {
		copy_keypair_addr(fors_tree_addr + 8 * i, fors_addr);
		set_type(fors_tree_addr + 8 * i, LC_SPX_ADDR_TYPE_FORSTREE);
		copy_keypair_addr(fors_leaf_addr + 8 * i, fors_addr);
	}
	copy_keypair_addr(fors_pk_addr, fors_addr);
	set_type(fors_pk_addr, LC_SPX_ADDR_TYPE_FORSPK);

	message_to_indices(indices, m);

	for (i = 0; i < LC_SPX_FORS_TREES; i++) {
		idx_offset = i * (1 << LC_SPX_FORS_HEIGHT);

		set_tree_height(fors_tree_addr, 0);
		set_tree_index(fors_tree_addr, indices[i] + idx_offset);

		/* Include the secret key part that produces the selected leaf node. */
		set_type(fors_tree_addr, LC_SPX_ADDR_TYPE_FORSPRF);
		fors_gen_sk(sig, ctx, fors_tree_addr);
		set_type(fors_tree_addr, LC_SPX_ADDR_TYPE_FORSTREE);
		sig += LC_SPX_N;

		/* Compute the authentication path for this leaf node. */
		treehashx4(roots + i * LC_SPX_N, sig, ctx, indices[i],
			   idx_offset, LC_SPX_FORS_HEIGHT, fors_gen_leafx4,
			   fors_tree_addr, &fors_info);

		sig += LC_SPX_N * LC_SPX_FORS_HEIGHT;
	}

	/* Hash horizontally across all tree roots to derive the public key. */
	thash(pk, roots, LC_SPX_FORS_TREES, ctx->pub_seed, fors_pk_addr);
}

/**
 * Derives the FORS public key from a signature.
 * This can be used for verification by comparing to a known public key, or to
 * subsequently verify a signature on the derived public key. The latter is the
 * typical use-case when used as an FTS below an OTS in a hypertree.
 * Assumes m contains at least LC_SPX_FORS_HEIGHT * LC_SPX_FORS_TREES bits.
 */
void fors_pk_from_sig_avx2(uint8_t pk[LC_SPX_N],
			   const uint8_t sig[LC_SPX_FORS_BYTES],
			   const uint8_t m[LC_SPX_FORS_MSG_BYTES],
			   const spx_ctx *ctx, const uint32_t fors_addr[8])
{
	uint32_t indices[LC_SPX_FORS_TREES];
	unsigned char roots[LC_SPX_FORS_TREES * LC_SPX_N];
	unsigned char leaf[LC_SPX_N];
	uint32_t fors_tree_addr[8] = { 0 };
	uint32_t fors_pk_addr[8] = { 0 };
	uint32_t idx_offset;
	unsigned int i;

	copy_keypair_addr(fors_tree_addr, fors_addr);
	copy_keypair_addr(fors_pk_addr, fors_addr);

	set_type(fors_tree_addr, LC_SPX_ADDR_TYPE_FORSTREE);
	set_type(fors_pk_addr, LC_SPX_ADDR_TYPE_FORSPK);

	message_to_indices(indices, m);

	for (i = 0; i < LC_SPX_FORS_TREES; i++) {
		idx_offset = i * (1 << LC_SPX_FORS_HEIGHT);

		set_tree_height(fors_tree_addr, 0);
		set_tree_index(fors_tree_addr, indices[i] + idx_offset);

		/* Derive the leaf from the included secret key part. */
		fors_sk_to_leaf(leaf, sig, ctx, fors_tree_addr);
		sig += LC_SPX_N;

		/* Derive the corresponding root node of this tree. */
		compute_root(roots + i * LC_SPX_N, leaf, indices[i], idx_offset,
			     sig, LC_SPX_FORS_HEIGHT, ctx->pub_seed,
			     fors_tree_addr);
		sig += LC_SPX_N * LC_SPX_FORS_HEIGHT;
	}

	/* Hash horizontally across all tree roots to derive the public key. */
	thash(pk, roots, LC_SPX_FORS_TREES, ctx->pub_seed, fors_pk_addr);
}
