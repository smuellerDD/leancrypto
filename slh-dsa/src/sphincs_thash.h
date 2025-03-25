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

#ifndef SPHINCS_THASH_H
#define SPHINCS_THASH_H

#include "sphincs_type.h"

#ifdef __cplusplus
extern "C" {
#endif

void thash(struct lc_hash_ctx *hash_ctx, uint8_t out[LC_SPX_N],
	   const uint8_t *in, unsigned int inblocks,
	   const uint8_t pub_seed[LC_SPX_N], uint32_t addr[8]);
void thash_ascon(struct lc_hash_ctx *hash_ctx, uint8_t out[LC_SPX_N],
		 const uint8_t *in, unsigned int inblocks,
		 const uint8_t pub_seed[LC_SPX_N], uint32_t addr[8],
		 unsigned int addr_static, uint8_t *ascon_state, int first);

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_THASH_H */
