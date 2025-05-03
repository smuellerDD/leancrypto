/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/PQClean/PQClean/
 *
 * The code is referenced as Public Domain
 */
/**
 * @file shake_prng.c
 * @brief Implementation of SHAKE-256 based seed expander
 */

#include "hqc_type.h"
#include "shake_prng.h"

/**
 * @brief Initialise a SHAKE-256 based seed expander
 *
 * @param[out] state Keccak internal state and a counter
 * @param[in] seed A seed
 * @param[in] seedlen The seed bytes length
 */
void seedexpander_init(struct lc_hash_ctx *shake256, const uint8_t *seed,
		       size_t seedlen)
{
	static const uint8_t domain = LC_HQC_SEEDEXPANDER_DOMAIN;

	lc_hash_init(shake256);
	lc_hash_update(shake256, seed, seedlen);
	lc_hash_update(shake256, &domain, 1);
}

/**
 * @brief A SHAKE-256 based seed expander
 *
 * Squeezes Keccak state by 64-bit blocks (hardware version compatibility)
 *
 * @param[out] state Internal state of SHAKE
 * @param[out] output The XOF data
 * @param[in] outlen Number of bytes to return
 */
void seedexpander(struct lc_hash_ctx *shake256, uint8_t *output, size_t outlen)
{
	const size_t bsize = sizeof(uint64_t);
	const size_t remainder = outlen % bsize;

	lc_hash_set_digestsize(shake256, outlen - remainder);
	lc_hash_final(shake256, output);

	if (remainder != 0) {
		uint8_t i, tmp[sizeof(uint64_t)];

		lc_hash_set_digestsize(shake256, bsize);
		lc_hash_final(shake256, tmp);
		output += outlen - remainder;
		for (i = 0; i < remainder; i++)
			output[i] = tmp[i];

		lc_memset_secure(tmp, 0, sizeof(tmp));
	}
}
