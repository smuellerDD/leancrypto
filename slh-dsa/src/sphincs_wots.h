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

#ifndef SPHINCS_WOTS_H
#define SPHINCS_WOTS_H

#include "sphincs_type.h"
#include "sphincs_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
 *
 * Writes the computed public key to 'pk'.
 */
void wots_pk_from_sig_c(uint8_t pk[LC_SPX_WOTS_BYTES], const uint8_t *sig,
			const uint8_t *msg, const spx_ctx *ctx,
			uint32_t addr[8]);

/*
 * Compute the chain lengths needed for a given message hash
 */
void chain_lengths_c(unsigned int *lengths, const uint8_t *msg);

typedef void (*wots_pk_from_sig_f)(uint8_t pk[LC_SPX_WOTS_BYTES],
				   const uint8_t *sig, const uint8_t *msg,
				   const spx_ctx *ctx, uint32_t addr[8]);
typedef void (*chain_lengths_f)(unsigned int *lengths, const uint8_t *msg);

#ifdef __cplusplus
}
#endif

#endif /* SPHINCS_WOTS_H */
