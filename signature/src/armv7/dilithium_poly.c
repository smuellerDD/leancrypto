/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "dilithium_poly.h"
#include "dilithium_poly_armv7.h"
#include "dilithium_service_helpers.h"
#include "lc_sha3.h"

extern unsigned int armv7_rej_uniform_asm(int32_t *a, unsigned int len,
					  const unsigned char *buf,
					  unsigned int buflen);
/**
 * @brief poly_uniform - Sample polynomial with uniformly random coefficients
 *			 in [0,Q-1] by performing rejection sampling on the
 *			 output stream of SHAKE128(seed|nonce).
 *
 * @param a [out] pointer to output polynomial
 * @param seed [in] byte array with seed of length LC_DILITHIUM_SEEDBYTES
 * @param nonce [in] 2-byte nonce
 */
void poly_uniform_armv7(poly *a, const uint8_t seed[LC_DILITHIUM_SEEDBYTES],
			uint16_t nonce, void *ws_buf)
{
	unsigned int i, ctr, off;
	unsigned int buflen = POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK;
	uint8_t *buf = ws_buf;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake128);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, seed, LC_DILITHIUM_SEEDBYTES);
	lc_hash_update(hash_ctx, (uint8_t *)&nonce, sizeof(nonce));
	lc_hash_set_digestsize(hash_ctx, buflen);
	lc_hash_final(hash_ctx, buf);

	lc_hash_set_digestsize(hash_ctx, LC_SHAKE_128_SIZE_BLOCK);

	ctr = armv7_rej_uniform_asm(a->coeffs, LC_DILITHIUM_N, buf, buflen);

	while (ctr < LC_DILITHIUM_N) {
		off = buflen % 3;
		for (i = 0; i < off; ++i)
			buf[i] = buf[buflen - off + i];

		lc_hash_final(hash_ctx, buf + off);
		buflen = LC_DILITHIUM_SEEDBYTES + off;
		ctr += armv7_rej_uniform_asm(a->coeffs + ctr,
					     LC_DILITHIUM_N - ctr, buf, buflen);
	}

	lc_hash_zero(hash_ctx);
}
