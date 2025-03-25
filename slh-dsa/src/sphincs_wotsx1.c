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

#include "sidechannel_resistantce.h"
#include "sphincs_type.h"
#include "sphincs_address.h"
#include "sphincs_hash.h"
#include "sphincs_thash.h"
#include "sphincs_utils.h"
#include "sphincs_wots.h"
#include "sphincs_wotsx1.h"
#include "timecop.h"

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
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_SPHINCS_HASH_TYPE);
	struct leaf_info_x1 *info = v_info;
	uint64_t ascon_state[LC_ASCON_HASH_STATE_WORDS];
	uint64_t ascon_state_prf[LC_ASCON_HASH_STATE_WORDS];
	uint32_t *leaf_addr = info->leaf_addr;
	uint32_t *pk_addr = info->pk_addr;
	unsigned int i, k;
	unsigned char pk_buffer[LC_SPX_WOTS_BYTES];
	unsigned char *buffer;
	uint32_t wots_k_mask;

	(void)ascon_state;
	(void)ascon_state_prf;

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

#if defined(LC_SPHINCS_TYPE_128F_ASCON) || defined(LC_SPHINCS_TYPE_128S_ASCON)
		prf_addr_ascon(hash_ctx, buffer, ctx, leaf_addr,
			       LC_SPX_ADDR_BYTES - LC_ASCON_HASH_RATE,
			       (uint8_t *)ascon_state_prf, i == 0);
#else
		prf_addr(hash_ctx, buffer, ctx, leaf_addr);
#endif

		set_type(leaf_addr, LC_SPX_ADDR_TYPE_WOTS);

		/* Iterate down the WOTS chain */
		for (k = 0;; k++) {
			/*
			 *Check if this is the value that needs to be saved as
			 * a part of the WOTS signature.
			 */

			/*
			 * The memcpy code path is from upstream but it is not
			 * side-channel-free - it has side channels on the
			 * ws->root (see lc_sphincs_sign_ctx).
			 */
#if 0
			if (k == wots_k) {
				memcpy(info->wots_sig + i * LC_SPX_N,
				       buffer, LC_SPX_N);
			}
#else
			cmov(info->wots_sig + i * LC_SPX_N, buffer, LC_SPX_N,
			     k == wots_k);
#endif

			/* Check if we hit the top of the chain */
			if (k == LC_SPX_WOTS_W - 1)
				break;

			/* Iterate one step on the chain */
			set_hash_addr(leaf_addr, k);

#if defined(LC_SPHINCS_TYPE_128F_ASCON) || defined(LC_SPHINCS_TYPE_128S_ASCON)
			thash_ascon(hash_ctx, buffer, buffer, 1, ctx->pub_seed,
				    leaf_addr,
				    LC_SPX_ADDR_BYTES - LC_ASCON_HASH_RATE,
				    (uint8_t *)ascon_state, i == 0);
#else
			thash(hash_ctx, buffer, buffer, 1, ctx->pub_seed,
			      leaf_addr);
#endif
		}
	}

	/* Do the final thash to generate the public keys */
	thash(hash_ctx, dest, pk_buffer, LC_SPX_WOTS_LEN, ctx->pub_seed,
	      pk_addr);

	lc_hash_zero(hash_ctx);

#if defined(LC_SPHINCS_TYPE_128F_ASCON) || defined(LC_SPHINCS_TYPE_128S_ASCON)
	lc_memset_secure(ascon_state, 0, sizeof(ascon_state));
	lc_memset_secure(ascon_state_prf, 0, sizeof(ascon_state_prf));
#endif
}
#pragma GCC diagnostic pop
