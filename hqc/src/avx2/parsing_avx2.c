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
 * https://pqc-hqc.org/
 *
 * The code is referenced as Public Domain
 */
/**
 * @file parsing.c
 * @brief Functions to parse secret key, public key and ciphertext of the HQC scheme
 */

#include "lc_sha3.h"
#include "parsing_avx2.h"
#include "vector_avx2.h"
#include "../shake_prng.h"

/**
 * @brief Parse a secret key from a string
 *
 * The secret key is composed of the seed used to generate vectors <b>x</b> and <b>y</b>.
 * As technicality, the public key is appended to the secret key in order to respect NIST API.
 *
 * @param[out] y uint64_t representation of vector y
 * @param[in] sigma String used in HHK transform
 * @param[out] pk String containing the public key
 * @param[in] sk String containing the secret key
 */
void hqc_secret_key_from_string_avx2(__m256i *y256, uint8_t *sigma, uint8_t *pk,
				     const uint8_t *sk,
				     struct vect_set_random_fixed_weight_ws *ws)
{
	LC_SHAKE_256_CTX_ON_STACK(sk_seedexpander);

	memcpy(ws->sk_seed, sk, LC_HQC_SEED_BYTES);
	memcpy(sigma, sk + LC_HQC_SEED_BYTES, LC_HQC_VEC_K_SIZE_BYTES);
	seedexpander_init(sk_seedexpander, ws->sk_seed, LC_HQC_SEED_BYTES);

	vect_set_random_fixed_weight_avx2(sk_seedexpander, y256,
					  LC_HQC_PARAM_OMEGA, ws);
	memcpy(pk, sk + LC_HQC_SEED_BYTES + LC_HQC_VEC_K_SIZE_BYTES,
	       LC_HQC_PUBLIC_KEY_BYTES);

	lc_hash_zero(sk_seedexpander);
}
