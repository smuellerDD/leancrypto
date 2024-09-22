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

#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_merkle.h"
#include "sphincs_utils.h"
#include "sphincs_utilsx4_avx2.h"
#include "sphincs_wots.h"
#include "sphincs_wotsx4_avx2.h"

/*
 * This generates a Merkle signature (WOTS signature followed by the Merkle
 * authentication path).
 */ 
void sphincs_merkle_sign(uint8_t *sig, unsigned char *root, const spx_ctx* ctx,
			uint32_t wots_addr[8], uint32_t tree_addr[8],
			uint32_t idx_leaf)
{
	unsigned char *auth_path = sig + LC_SPX_WOTS_BYTES;
	uint32_t tree_addrx4[4*8] = { 0 };
	int j;
	struct leaf_info_x4 info = { 0 };
	unsigned steps[ LC_SPX_WOTS_LEN ];

	info.wots_sig = sig;
	chain_lengths(steps, root);
	info.wots_steps = steps;

	for (j=0; j<4; j++) {
		set_type(&tree_addrx4[8*j], LC_SPX_ADDR_TYPE_HASHTREE);
		set_type(&info.leaf_addr[8*j], LC_SPX_ADDR_TYPE_WOTS);
		set_type(&info.pk_addr[8*j], LC_SPX_ADDR_TYPE_WOTSPK);
		copy_subtree_addr(&tree_addrx4[8*j], tree_addr);
		copy_subtree_addr(&info.leaf_addr[8*j], wots_addr);
		copy_subtree_addr(&info.pk_addr[8*j], wots_addr);
	}

	info.wots_sign_leaf = idx_leaf;

	treehashx4(root, auth_path, ctx, idx_leaf, 0, LC_SPX_TREE_HEIGHT,
		   wots_gen_leafx4, tree_addrx4, &info);
}

/* Compute root node of the top-most subtree. */
void sphincs_merkle_gen_root(unsigned char *root, const spx_ctx* ctx)
{
	/* We do not need the auth path in key generation, but it simplifies the
	 *       code to have just one treehash routine that computes both root and path
	 *       in one function. */
	unsigned char auth_path[LC_SPX_TREE_HEIGHT * LC_SPX_N + LC_SPX_WOTS_BYTES];
	uint32_t top_tree_addr[8] = {0};
	uint32_t wots_addr[8] = {0};

	set_layer_addr(top_tree_addr, LC_SPX_D - 1);
	set_layer_addr(wots_addr, LC_SPX_D - 1);

	/* ~0 means "don't bother generating an auth path */
	sphincs_merkle_sign(auth_path, root, ctx, wots_addr, top_tree_addr,
			    (uint32_t)~0);
}
