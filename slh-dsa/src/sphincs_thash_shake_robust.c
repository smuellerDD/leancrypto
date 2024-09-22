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
	uint8_t buf[LC_SPX_N + LC_SPX_ADDR_BYTES + inblocks * LC_SPX_N];
	uint8_t bitmask[inblocks * LC_SPX_N] __align(LC_HASH_COMMON_ALIGNMENT);
	unsigned int i;

	memcpy(buf, pub_seed, LC_SPX_N);
	memcpy(buf + LC_SPX_N, addr, LC_SPX_ADDR_BYTES);

	//	shake256(bitmask, inblocks * LC_SPX_N, buf, LC_SPX_N + LC_SPX_ADDR_BYTES);

	// LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);
	//
	// lc_hash_init(hash_ctx);
	// lc_hash_update(hash_ctx, pub_seed, LC_SPX_N);
	// lc_hash_update(hash_ctx, addr, LC_SPX_ADDR_BYTES);
	// lc_hash_set_digestsize(hash_ctx, sizeof(bitmask));
	// lc_hash_final(hash_ctx, bitmask);
	//
	// lc_hash_zero(hash_ctx);

	lc_xof(lc_shake256, buf, LC_SPX_N + LC_SPX_ADDR_BYTES, bitmask,
	       sizeof(bitmask));

	for (i = 0; i < inblocks * LC_SPX_N; i++) {
		buf[LC_SPX_N + LC_SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
	}

	lc_xof(lc_shake256, buf, sizeof(buf), out, LC_SPX_N);
}
