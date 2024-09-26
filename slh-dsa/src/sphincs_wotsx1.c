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
#include "sphincs_hash.h"
#include "sphincs_thash.h"
#include "sphincs_utils.h"
#include "sphincs_wots.h"
#include "sphincs_wotsx1.h"

/*
 * This generates a WOTS public key
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with this WOTS key
 *
 * The frame-size is ignored here, as the frame is just a bit larger than the
 * 2048 limit. Further, this code is so deep embedded that a change is
 * not easily done.
 */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wframe-larger-than="
void wots_gen_leafx1(unsigned char *dest, const spx_ctx *ctx, uint32_t leaf_idx,
		     void *v_info)
{
	struct leaf_info_x1 *info = v_info;
	uint32_t *leaf_addr = info->leaf_addr;
	uint32_t *pk_addr = info->pk_addr;
	unsigned int i, k;
	unsigned char pk_buffer[LC_SPX_WOTS_BYTES];
	unsigned char *buffer;
	uint32_t wots_k_mask;

	if (leaf_idx == info->wots_sign_leaf) {
		/* We're traversing the leaf that's signing; generate the WOTS */
		/* signature */
		wots_k_mask = 0;
	} else {
		/* Nope, we're just generating pk's; turn off the signature logic */
		wots_k_mask = (uint32_t)~0;
	}

	set_keypair_addr(leaf_addr, leaf_idx);
	set_keypair_addr(pk_addr, leaf_idx);

	for (i = 0, buffer = pk_buffer; i < LC_SPX_WOTS_LEN;
	     i++, buffer += LC_SPX_N) {
		uint32_t wots_k =
			info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
		/* the step if we're generating a signature, ~0 if we're not */

		/* Start with the secret seed */
		set_chain_addr(leaf_addr, i);
		set_hash_addr(leaf_addr, 0);
		set_type(leaf_addr, LC_SPX_ADDR_TYPE_WOTSPRF);

		prf_addr(buffer, ctx, leaf_addr);

		set_type(leaf_addr, LC_SPX_ADDR_TYPE_WOTS);

		/* Iterate down the WOTS chain */
		for (k = 0;; k++) {
			/* Check if this is the value that needs to be saved as a */
			/* part of the WOTS signature */
			if (k == wots_k) {
				memcpy(info->wots_sig + i * LC_SPX_N, buffer,
				       LC_SPX_N);
			}

			/* Check if we hit the top of the chain */
			if (k == LC_SPX_WOTS_W - 1)
				break;

			/* Iterate one step on the chain */
			set_hash_addr(leaf_addr, k);

			thash(buffer, buffer, 1, ctx->pub_seed, leaf_addr);
		}
	}

	/* Do the final thash to generate the public keys */
	thash(dest, pk_buffer, LC_SPX_WOTS_LEN, ctx->pub_seed, pk_addr);
}
#pragma GCC diagnostic pop
