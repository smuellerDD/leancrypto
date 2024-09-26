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

#include "small_stack_support.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_merkle_armv8.h"
#include "sphincs_thashx2_armv8.h"
#include "sphincs_utils.h"
#include "sphincs_utilsx2_armv8.h"
#include "sphincs_wots_armv8.h"
#include "sphincs_wotsx2_armv8.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).
 */
int sphincs_merkle_sign_armv8(uint8_t *sig, unsigned char *root,
			      const spx_ctx *ctx, uint32_t wots_addr[8],
			      uint32_t tree_addr[8], uint32_t idx_leaf)
{
	struct workspace {
		uint32_t tree_addrx2[2 * 8];
		unsigned int steps[LC_SPX_WOTS_LEN];
		struct leaf_info_x2 info;
		uint8_t wots_pk_buffer[2 * LC_SPX_WOTS_BYTES];
		uint8_t thash_buf[LC_THASHX4_BUFLEN * 2 +
				  LC_THASHX4_BITMASKLEN * 2];
	};
	unsigned char *auth_path = sig + LC_SPX_WOTS_BYTES;
	int j;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	ws->info.wots_sig = sig;
	chain_lengths_armv8(ws->steps, root);
	ws->info.wots_steps = ws->steps;

	for (j = 0; j < 2; j++) {
		set_type(&ws->tree_addrx2[8 * j], LC_SPX_ADDR_TYPE_HASHTREE);
		set_type(&ws->info.leaf_addr[8 * j], LC_SPX_ADDR_TYPE_WOTS);
		set_type(&ws->info.pk_addr[8 * j], LC_SPX_ADDR_TYPE_WOTSPK);
		copy_subtree_addr(&ws->tree_addrx2[8 * j], tree_addr);
		copy_subtree_addr(&ws->info.leaf_addr[8 * j], wots_addr);
		copy_subtree_addr(&ws->info.pk_addr[8 * j], wots_addr);
	}

	ws->info.wots_sign_leaf = idx_leaf;

	treehashx2(root, auth_path, ctx, idx_leaf, 0, LC_SPX_TREE_HEIGHT,
		   wots_gen_leafx2, ws->tree_addrx2, &ws->info,
		   ws->wots_pk_buffer, ws->thash_buf);

	LC_RELEASE_MEM(ws);
	return 0;
}

/* Compute root node of the top-most subtree. */
int sphincs_merkle_gen_root_armv8(unsigned char *root, const spx_ctx *ctx)
{
	/*
	 * We do not need the auth path in key generation, but it simplifies the
	 * code to have just one treehash routine that computes both root and
	 * path in one function.
	 */
	struct workspace {
		unsigned char auth_path[LC_SPX_TREE_HEIGHT * LC_SPX_N +
					LC_SPX_WOTS_BYTES];
		uint32_t top_tree_addr[8];
		uint32_t wots_addr[8];
	};
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	set_layer_addr(ws->top_tree_addr, LC_SPX_D - 1);
	set_layer_addr(ws->wots_addr, LC_SPX_D - 1);

	/* ~0 means "don't bother generating an auth path */
	sphincs_merkle_sign_armv8(ws->auth_path, root, ctx, ws->wots_addr,
				  ws->top_tree_addr, (uint32_t)~0);

	LC_RELEASE_MEM(ws);
	return 0;
}
