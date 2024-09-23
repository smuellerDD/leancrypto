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
#include "sphincs_hashx2_armv8.h"
#include "sphincs_thashx2_armv8.h"
#include "sphincs_utils.h"
#include "sphincs_utilsx2_armv8.h"
#include "sphincs_wots_armv8.h"
#include "sphincs_wotsx2_armv8.h"

/**
 * Computes up the chains
 */
static void gen_chains(unsigned char *out, const unsigned char *in,
		       unsigned int start[LC_SPX_WOTS_LEN],
		       unsigned int steps[LC_SPX_WOTS_LEN], const spx_ctx *ctx,
		       uint32_t addr[8])
{
	uint32_t i, j, k, idx, watching;
	int done;
	unsigned char empty[LC_SPX_N];
	unsigned char *bufs[4];
	uint32_t addrs[8 * 2];

	int l;
	uint16_t counts[LC_SPX_WOTS_W] = { 0 };
	uint16_t idxs[LC_SPX_WOTS_LEN];
	uint16_t total, newTotal;

	/* set addrs = {addr, addr} */
	for (j = 0; j < 2; j++) {
		memcpy(addrs + j * 8, addr, sizeof(uint32_t) * 8);
	}

	/* Initialize out with the value at position 'start'. */
	memcpy(out, in, LC_SPX_WOTS_LEN * LC_SPX_N);

	/* Sort the chains in reverse order by steps using counting sort. */
	for (i = 0; i < LC_SPX_WOTS_LEN; i++) {
		counts[steps[i]]++;
	}
	total = 0;
	for (l = LC_SPX_WOTS_W - 1; l >= 0; l--) {
		newTotal = counts[l] + total;
		counts[l] = total;
		total = newTotal;
	}
	for (i = 0; i < LC_SPX_WOTS_LEN; i++) {
		idxs[counts[steps[i]]] = (uint16_t)i;
		counts[steps[i]]++;
	}

	/* We got our work cut out for us: do it! */
	for (i = 0; i < LC_SPX_WOTS_LEN; i += 2) {
		for (j = 0; j < 2 && i + j < LC_SPX_WOTS_LEN; j++) {
			idx = idxs[i + j];
			set_chain_addr(addrs + j * 8, idx);
			bufs[j] = out + LC_SPX_N * idx;
		}

		/* As the chains are sorted in reverse order, we know that the first
         * chain is the longest and the last one is the shortest.  We keep
         * an eye on whether the last chain is done and then on the one before,
         * et cetera. */
		watching = 1;
		done = 0;
		while (i + watching >= LC_SPX_WOTS_LEN) {
			bufs[watching] = &empty[0];
			watching--;
		}

		for (k = 0;; k++) {
			while (k == steps[idxs[i + watching]]) {
				bufs[watching] = &empty[0];
				if (watching == 0) {
					done = 1;
					break;
				}
				watching--;
			}
			if (done) {
				break;
			}
			for (j = 0; j < watching + 1; j++) {
				set_hash_addr(addrs + j * 8,
					      k + start[idxs[i + j]]);
			}

			thashx2(bufs[0], bufs[1], bufs[0], bufs[1], 1, ctx,
				addrs);
		}
	}
}

/**
 * base_w algorithm as described in draft.
 * Interprets an array of bytes as integers in base w.
 * This only works when log_w is a divisor of 8.
 */
static void base_w(unsigned int *output, const int out_len,
		   const unsigned char *input)
{
	int in = 0;
	int out = 0;
	unsigned char total;
	int bits = 0;
	int consumed;

	for (consumed = 0; consumed < out_len; consumed++) {
		if (bits == 0) {
			total = input[in];
			in++;
			bits += 8;
		}
		bits -= LC_SPX_WOTS_LOGW;
		output[out] = (total >> bits) & (LC_SPX_WOTS_W - 1);
		out++;
	}
}

/* Computes the WOTS+ checksum over a message (in base_w). */
static void wots_checksum(unsigned int *csum_base_w,
			  const unsigned int *msg_base_w)
{
	unsigned int csum = 0;
	unsigned char csum_bytes[(LC_SPX_WOTS_LEN2 * LC_SPX_WOTS_LOGW + 7) / 8];
	unsigned int i;

	/* Compute checksum. */
	for (i = 0; i < LC_SPX_WOTS_LEN1; i++) {
		csum += LC_SPX_WOTS_W - 1 - msg_base_w[i];
	}

	/* Convert checksum to base_w. */
	/* Make sure expected empty zero bits are the least significant bits. */
	csum = csum << ((8 - ((LC_SPX_WOTS_LEN2 * LC_SPX_WOTS_LOGW) % 8)) % 8);
	ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
	base_w(csum_base_w, LC_SPX_WOTS_LEN2, csum_bytes);
}

/* Takes a message and derives the matching chain lengths. */
void chain_lengths_armv8(unsigned int *lengths, const uint8_t *msg)
{
	base_w(lengths, LC_SPX_WOTS_LEN1, msg);
	wots_checksum(lengths + LC_SPX_WOTS_LEN1, lengths);
}

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
int wots_pk_from_sig_armv8(uint8_t pk[LC_SPX_WOTS_BYTES], const uint8_t *sig,
			   const uint8_t *msg, const spx_ctx *ctx,
			   uint32_t addr[8])
{
	unsigned int steps[LC_SPX_WOTS_LEN];
	unsigned int start[LC_SPX_WOTS_LEN];
	uint32_t i;

	chain_lengths_armv8(start, msg);

	for (i = 0; i < LC_SPX_WOTS_LEN; i++) {
		steps[i] = LC_SPX_WOTS_W - 1 - start[i];
	}

	gen_chains(pk, sig, start, steps, ctx, addr);

	return 0;
}

/*
 * This generates 2 sequential WOTS public keys
 * It also generates the WOTS signature if leaf_info indicates
 * that we're signing with one of these WOTS keys
 */
void wots_gen_leafx2(unsigned char *dest, const spx_ctx *ctx, uint32_t leaf_idx,
		     void *v_info)
{
	struct leaf_info_x2 *info = v_info;
	uint32_t *leaf_addr = info->leaf_addr;
	uint32_t *pk_addr = info->pk_addr;
	unsigned int i, j, k;
	unsigned char pk_buffer[2 * LC_SPX_WOTS_BYTES];
	unsigned wots_offset = LC_SPX_WOTS_BYTES;
	unsigned char *buffer;
	uint32_t wots_k_mask;
	unsigned wots_sign_index;

	if (((leaf_idx ^ info->wots_sign_leaf) & (uint32_t)~1) == 0) {
		/* We're traversing the leaf that's signing; generate the WOTS */
		/* signature */
		wots_k_mask = 0;
		wots_sign_index =
			info->wots_sign_leaf & 1; /* Which of of the 2 */
		/* slots do the signatures come from */
	} else {
		/* Nope, we're just generating pk's; turn off the signature logic */
		wots_k_mask = (uint32_t)~0;
		wots_sign_index = 0;
	}

	for (j = 0; j < 2; j++) {
		set_keypair_addr(leaf_addr + j * 8, leaf_idx + j);
		set_keypair_addr(pk_addr + j * 8, leaf_idx + j);
	}

	for (i = 0, buffer = pk_buffer; i < LC_SPX_WOTS_LEN;
	     i++, buffer += LC_SPX_N) {
		uint32_t wots_k =
			info->wots_steps[i] | wots_k_mask; /* Set wots_k to */
		/* the step if we're generating a signature, ~0 if we're not */

		/* Start with the secret seed */
		for (j = 0; j < 2; j++) {
			set_chain_addr(leaf_addr + j * 8, i);
			set_hash_addr(leaf_addr + j * 8, 0);
			set_type(leaf_addr + j * 8, LC_SPX_ADDR_TYPE_WOTSPRF);
		}
		prf_addrx2(buffer + 0 * wots_offset, buffer + 1 * wots_offset,
			   ctx, leaf_addr);
		for (j = 0; j < 2; j++) {
			set_type(leaf_addr + j * 8, LC_SPX_ADDR_TYPE_WOTS);
		}

		/* Iterate down the WOTS chain */
		for (k = 0;; k++) {
			/* Check if one of the values we have needs to be saved as a */
			/* part of the WOTS signature */
			if (k == wots_k) {
				memcpy(info->wots_sig + i * LC_SPX_N,
				       buffer + wots_sign_index * wots_offset,
				       LC_SPX_N);
			}

			/* Check if we hit the top of the chain */
			if (k == LC_SPX_WOTS_W - 1)
				break;

			/* Iterate one step on all 4 chains */
			for (j = 0; j < 2; j++) {
				set_hash_addr(leaf_addr + j * 8, k);
			}
			thashx2(buffer + 0 * wots_offset,
				buffer + 1 * wots_offset,
				buffer + 0 * wots_offset,
				buffer + 1 * wots_offset, 1, ctx, leaf_addr);
		}
	}

	/* Do the final thash to generate the public keys */
	thashx2(dest + 0 * LC_SPX_N, dest + 1 * LC_SPX_N,
		pk_buffer + 0 * wots_offset, pk_buffer + 1 * wots_offset,
		LC_SPX_WOTS_LEN, ctx, pk_addr);
}