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

#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_thash.h"
#include "sphincs_utils.h"

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(uint8_t *out, unsigned int outlen, unsigned long long in)
{
	int i;

	/* Iterate over out in decreasing order, for big-endianness. */
	for (i = (signed int)outlen - 1; i >= 0; i--) {
		out[i] = in & 0xff;
		in = in >> 8;
	}
}

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const uint8_t *in, unsigned int inlen)
{
	unsigned long long retval = 0;
	unsigned int i;

	for (i = 0; i < inlen; i++) {
		retval |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
	}
	return retval;
}

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
void compute_root(uint8_t *root, const uint8_t *leaf, uint32_t leaf_idx,
		  uint32_t idx_offset, const uint8_t *auth_path,
		  uint32_t tree_height, const uint8_t pub_seed[LC_SPX_N],
		  uint32_t addr[8])
{
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_SPHINCS_HASH_TYPE);
	uint64_t ascon_state[LC_ASCON_HASH_STATE_WORDS];
	uint32_t i;
	uint8_t buffer[2 * LC_SPX_N];

	(void)ascon_state;

	/* If leaf_idx is odd (last bit = 1), current path element is a right child
	 *       and auth_path has to go left. Otherwise it is the other way around. */
	if (leaf_idx & 1) {
		memcpy(buffer + LC_SPX_N, leaf, LC_SPX_N);
		memcpy(buffer, auth_path, LC_SPX_N);
	} else {
		memcpy(buffer, leaf, LC_SPX_N);
		memcpy(buffer + LC_SPX_N, auth_path, LC_SPX_N);
	}
	auth_path += LC_SPX_N;

	for (i = 0; i < tree_height - 1; i++) {
		leaf_idx >>= 1;
		idx_offset >>= 1;
		/* Set the address of the node we're creating. */
		set_tree_height(addr, i + 1);
		set_tree_index(addr, leaf_idx + idx_offset);

		/* Pick the right or left neighbor, depending on parity of the node. */
		if (leaf_idx & 1) {
#if defined(LC_SPHINCS_TYPE_128F_ASCON) || defined(LC_SPHINCS_TYPE_128S_ASCON)
			thash_ascon(hash_ctx, buffer + LC_SPX_N, buffer, 2,
				    pub_seed, addr,
				    LC_SPX_ADDR_BYTES - LC_ASCON_HASH_RATE,
				    (uint8_t *)ascon_state, i == 0);
#else
			thash(hash_ctx, buffer + LC_SPX_N, buffer, 2, pub_seed,
			      addr);
#endif
			memcpy(buffer, auth_path, LC_SPX_N);
		} else {
#if defined(LC_SPHINCS_TYPE_128F_ASCON) || defined(LC_SPHINCS_TYPE_128S_ASCON)
			thash_ascon(hash_ctx, buffer, buffer, 2, pub_seed, addr,
				    LC_SPX_ADDR_BYTES - LC_ASCON_HASH_RATE,
				    (uint8_t *)ascon_state, i == 0);
#else
			thash(hash_ctx, buffer, buffer, 2, pub_seed, addr);
#endif
			memcpy(buffer + LC_SPX_N, auth_path, LC_SPX_N);
		}
		auth_path += LC_SPX_N;
	}

	/* The last iteration is exceptional; we do not copy an auth_path node. */
	leaf_idx >>= 1;
	idx_offset >>= 1;
	set_tree_height(addr, tree_height);
	set_tree_index(addr, leaf_idx + idx_offset);
	thash(hash_ctx, root, buffer, 2, pub_seed, addr);

#if defined(LC_SPHINCS_TYPE_128F_ASCON) || defined(LC_SPHINCS_TYPE_128S_ASCON)
	lc_memset_secure(ascon_state, 0, sizeof(ascon_state));
#endif

	lc_hash_zero(hash_ctx);
}

#if 0
/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. LC_SPX_ADDR_TYPE_HASHTREE or LC_SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
void treehash(uint8_t *root, uint8_t *auth_path, const spx_ctx *ctx,
	      uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
	      void (*gen_leaf)(uint8_t * /* leaf */, const spx_ctx * /* ctx */,
			       uint32_t /* addr_idx */,
			       const uint32_t[8] /* tree_addr */),
	      uint32_t tree_addr[8])
{
	uint8_t stack[(tree_height + 1) * LC_SPX_N];
	unsigned int heights[tree_height + 1];
	unsigned int offset = 0;
	uint32_t idx;
	uint32_t tree_idx;

	for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) {
		/* Add the next leaf node to the stack. */
		gen_leaf(stack + offset * LC_SPX_N, ctx, idx + idx_offset,
			 tree_addr);
		offset++;
		heights[offset - 1] = 0;

		/* If this is a node we need for the auth path.. */
		if ((leaf_idx ^ 0x1) == idx) {
			memcpy(auth_path, stack + (offset - 1) * LC_SPX_N,
			       LC_SPX_N);
		}

		/* While the top-most nodes are of equal height.. */
		while (offset >= 2 &&
		       heights[offset - 1] == heights[offset - 2]) {
			/* Compute index of the new node, in the next layer. */
			tree_idx = (idx >> (heights[offset - 1] + 1));

			/* Set the address of the node we're creating. */
			set_tree_height(tree_addr, heights[offset - 1] + 1);
			set_tree_index(tree_addr,
				       tree_idx + (idx_offset >>
						   (heights[offset - 1] + 1)));
			/* Hash the top-most nodes from the stack together. */
			thash(stack + (offset - 2) * LC_SPX_N,
			      stack + (offset - 2) * LC_SPX_N, 2, ctx->pub_seed,
			      tree_addr);
			offset--;
			/* Note that the top-most node is now one layer higher. */
			heights[offset - 1]++;

			/* If this is a node we need for the auth path.. */
			if (((leaf_idx >> heights[offset - 1]) ^ 0x1) ==
			    tree_idx) {
				memcpy(auth_path +
					       heights[offset - 1] * LC_SPX_N,
				       stack + (offset - 1) * LC_SPX_N,
				       LC_SPX_N);
			}
		}
	}
	memcpy(root, stack, LC_SPX_N);
}
#endif
