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

#include "ext_headers.h"
#include "small_stack_support.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_merkle.h"
#include "sphincs_utilsx1.h"
#include "sphincs_wots.h"
#include "sphincs_wotsx1.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path). This is in this file because most of the complexity
 * is involved with the WOTS signature; the Merkle authentication path logic
 * is mostly hidden in treehashx4
 */
int sphincs_merkle_sign_c(uint8_t *sig, unsigned char *root, const spx_ctx *ctx,
			  uint32_t wots_addr[8], uint32_t tree_addr[8],
			  uint32_t idx_leaf)
{
	struct workspace {
		struct leaf_info_x1 info;
		unsigned int steps[LC_SPX_WOTS_LEN];
	};
	uint8_t *auth_path = sig + LC_SPX_WOTS_BYTES;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	ws->info.wots_sig = sig;
	chain_lengths_c(ws->steps, root);
	ws->info.wots_steps = ws->steps;

	set_type(&tree_addr[0], LC_SPX_ADDR_TYPE_HASHTREE);
	set_type(&ws->info.pk_addr[0], LC_SPX_ADDR_TYPE_WOTSPK);
	copy_subtree_addr(&ws->info.leaf_addr[0], wots_addr);
	copy_subtree_addr(&ws->info.pk_addr[0], wots_addr);

	ws->info.wots_sign_leaf = idx_leaf;

	treehashx1(root, auth_path, ctx, idx_leaf, 0, LC_SPX_TREE_HEIGHT,
		   wots_gen_leafx1, tree_addr, &ws->info);

	LC_RELEASE_MEM(ws);
	return 0;
}

/* Compute root node of the top-most subtree. */
int sphincs_merkle_gen_root_c(unsigned char *root, const spx_ctx *ctx)
{
	/*
	 * We do not need the auth path in key generation, but it simplifies the
	 * code to have just one treehash routine that computes both root and
	 * path in one function.
	 */
	struct workspace {
		uint32_t top_tree_addr[8];
		uint32_t wots_addr[8];
		uint8_t auth_path[LC_SPX_TREE_HEIGHT * LC_SPX_N +
				  LC_SPX_WOTS_BYTES];
	};
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	set_layer_addr(ws->top_tree_addr, LC_SPX_D - 1);
	set_layer_addr(ws->wots_addr, LC_SPX_D - 1);

	/* ~0 means "don't bother generating an auth path */
	sphincs_merkle_sign_c(ws->auth_path, root, ctx, ws->wots_addr,
			      ws->top_tree_addr, (uint32_t)~0);

	LC_RELEASE_MEM(ws);
	return 0;
}
