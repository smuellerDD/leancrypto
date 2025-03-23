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

#include "alignment.h"
#include "sphincs_type.h"
#include "sphincs_thash.h"
#include "lc_sha3.h"
#include "xor.h"

/**
 * Takes an array of inblocks concatenated arrays of LC_SPX_N bytes.
 */
void thash(uint8_t out[LC_SPX_N], const uint8_t *in, unsigned int inblocks,
	   const uint8_t pub_seed[LC_SPX_N], uint32_t addr[8])
{
	LC_HASH_CTX_ON_STACK(buf_ctx, LC_SPHINCS_HASH_TYPE);

	lc_hash_init(buf_ctx);
	lc_hash_update(buf_ctx, pub_seed, LC_SPX_N);
	lc_hash_update(buf_ctx, (uint8_t *)addr, LC_SPX_ADDR_BYTES);
	lc_hash_update(buf_ctx, in, LC_SPX_N * inblocks);

	/* Squeeze out the final data point */
	lc_hash_set_digestsize(buf_ctx, LC_SPX_N);
	lc_hash_final(buf_ctx, out);

	lc_hash_zero(buf_ctx);
}
