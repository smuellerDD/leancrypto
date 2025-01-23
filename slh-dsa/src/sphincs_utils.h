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

#ifndef SPHINCS_UTILS_H
#define SPHINCS_UTILS_H

#include "sphincs_type.h"
#include "sphincs_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
 */
void ull_to_bytes(unsigned char *out, unsigned int outlen,
		  unsigned long long in);

/**
 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
 */
unsigned long long bytes_to_ull(const unsigned char *in, unsigned int inlen);

/**
 * Computes a root node given a leaf and an auth path.
 * Expects address to be complete other than the tree_height and tree_index.
 */
void compute_root(uint8_t *root, const uint8_t *leaf, uint32_t leaf_idx,
		  uint32_t idx_offset, const uint8_t *auth_path,
		  uint32_t tree_height, const uint8_t pub_seed[LC_SPX_N],
		  uint32_t addr[8]);

#if 0
/**
 * For a given leaf index, computes the authentication path and the resulting
 * root node using Merkle's TreeHash algorithm.
 * Expects the layer and tree parts of the tree_addr to be set, as well as the
 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
 * Applies the offset idx_offset to indices before building addresses, so that
 * it is possible to continue counting indices across trees.
 */
void treehash(unsigned char *root, unsigned char *auth_path, const spx_ctx *ctx,
	      uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
	      void (*gen_leaf)(unsigned char * /* leaf */,
			       const spx_ctx *ctx /* ctx */,
			       uint32_t /* addr_idx */,
			       const uint32_t[8] /* tree_addr */),
	      uint32_t tree_addr[8]);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_UTILS_H */
