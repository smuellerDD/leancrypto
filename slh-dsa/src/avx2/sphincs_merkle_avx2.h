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

#ifndef SPHINCS_MERKLE_AVX2_H
#define SPHINCS_MERKLE_AVX2_H

#include "sphincs_type.h"
#include "sphincs_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Generate a Merkle signature (WOTS signature followed by the Merkle
 * authentication path)
 */
int sphincs_merkle_sign_avx2(uint8_t *sig, unsigned char *root,
			     const spx_ctx *ctx, uint32_t wots_addr[8],
			     uint32_t tree_addr[8], uint32_t idx_leaf);

/* Compute the root node of the top-most subtree. */
int sphincs_merkle_gen_root_avx2(unsigned char *root, const spx_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_MERKLE_AVX2_H */
