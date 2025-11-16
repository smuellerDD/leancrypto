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

#include "sidechannel_resistance.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_thashx2_armv8.h"
#include "sphincs_utils.h"
#include "sphincs_utilsx2_armv8.h"

/*
 * Generate the entire Merkle tree, computing the authentication path for leaf_idx,
 * and the resulting root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. LC_SPX_ADDR_TYPE_HASHTREE or LC_SPX_ADDR_TYPE_FORSTREE)
 *
 * This expects tree_addrx2 to be initialized to 2 parallel addr structures for
 * the Merkle tree nodes
 *
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 *
 * This works by using the standard Merkle tree building algorithm, except
 * that each 'node' tracked is actually 2 consecutive nodes in the real tree.
 * When we combine two logical nodes AB and WX, we perform the H
 * operation on adjacent real nodes, forming the parent logical node
 * (AB)(WX)
 *
 * When we get to the top level of the real tree (where there is only
 * one logical node), we continue this operation one more time; the right
 * most real node will by the actual root (and the other node will be
 * garbage).  We follow the same thashx2 logic so that the 'extract
 * authentication path components' part of the loop is still executed (and
 * to simplify the code somewhat)
 */
void treehashx2(
	unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx,
	uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
	void (*gen_leafx2)(unsigned char * /* Where to write the leaves */,
			   const spx_ctx *, uint32_t idx, void *info,
			   uint8_t *wots_pk_buffer, uint8_t *thash_buf),
	uint32_t tree_addrx2[2 * 8], void *info, uint8_t *wots_pk_buffer,
	uint8_t *thash_buf)
{
	/* This is where we keep the intermediate nodes */
#if (LC_SPX_TREE_HEIGHT < LC_SPX_FORS_HEIGHT)
	uint8_t stackx2[LC_SPX_FORS_HEIGHT * 2 * LC_SPX_N];
#else
	uint8_t stackx2[LC_SPX_TREE_HEIGHT * 2 * LC_SPX_N];
#endif

	uint32_t left_adj = 0, prev_left_adj = 0; /* When we're doing the top */
	/* level, the left-most part of the tree isn't at the beginning */
	/* of current[].  These give the offset of the actual start */

	uint32_t idx;
	uint32_t max_idx = (uint32_t)((1 << (tree_height - 1)) - 1);

	for (idx = 0;; idx++) {
		uint8_t current_idx[2 * LC_SPX_N]; /* Current logical node */

		gen_leafx2(current_idx, ctx, 2 * idx + idx_offset, info,
			   wots_pk_buffer, thash_buf);

		/* Now combine the freshly generated right node with previously */
		/* generated left ones */
		uint32_t internal_idx_offset = idx_offset;
		uint32_t internal_idx = idx;
		uint32_t internal_leaf = leaf_idx;
		uint32_t h, j; /* The height we are in the Merkle tree */
		for (h = 0;; h++, internal_idx >>= 1, internal_leaf >>= 1) {
			/* Special processing if we're at the top of the tree */
			if (h >= tree_height - 1) {
				if (h == tree_height) {
					/* We hit the root; return it */
					memcpy(root, &current_idx[1 * LC_SPX_N],
					       LC_SPX_N);
					return;
				}
				/* The tree indexing logic is a bit off in this case */
				/* Adjust it so that the left-most node of the part of */
				/* the tree that we're processing has index 0 */
				prev_left_adj = left_adj;
				left_adj = (uint32_t)(2 - (1 << (tree_height -
								 h - 1)));
			}

			/* Check if we hit the top of the tree */
			if (h == tree_height) {
				/* We hit the root; return it */
				memcpy(root, &current_idx[1 * LC_SPX_N],
				       LC_SPX_N);
				return;
			}

			/*
			 * Check if one of the nodes we have is a part of the
			 * authentication path; if it is, write it out
			 */
			if ((((internal_idx << 1) ^ internal_leaf) &
			     (uint32_t)~0x1) == 0) {
				memcpy(&auth_path[h * LC_SPX_N],
				       &current_idx[(((internal_leaf & 1) ^ 1) +
						     prev_left_adj) *
						    LC_SPX_N],
				       LC_SPX_N);
			}

			/*
			 * Check if we're at a left child; if so, stop going up the stack
			 * Exception: if we've reached the end of the tree, keep on going
			 * (so we combine the last 2 nodes into the one root node in two
			 * more iterations)
			 */
			if ((internal_idx & 1) == 0 && idx < max_idx) {
				break;
			}

			/* Ok, we're at a right node (or doing the top 3 levels) */
			/* Now combine the left and right logical nodes together */

			/* Set the address of the node we're creating. */
			internal_idx_offset >>= 1;
			for (j = 0; j < 2; j++) {
				set_tree_height(tree_addrx2 + j * 8, h + 1);
				set_tree_index(tree_addrx2 + j * 8,
					       (2 / 2) * (internal_idx &
							  (uint32_t)~1) +
						       j - left_adj +
						       internal_idx_offset);
			}
			unsigned char *left = &stackx2[h * 2 * LC_SPX_N];
			thashx2_12(&current_idx[0 * LC_SPX_N],
				   &current_idx[1 * LC_SPX_N],
				   &left[0 * LC_SPX_N],
				   &current_idx[0 * LC_SPX_N], 2, ctx,
				   tree_addrx2);
		}

		/* We've hit a left child; save the current for when we get the */
		/* corresponding right right */
		memcpy(&stackx2[h * 2 * LC_SPX_N], current_idx, 2 * LC_SPX_N);
	}
}
