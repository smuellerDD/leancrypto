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
 * @file hqc.c
 * @brief Implementation of hqc.h
 */

#include "code.h"
#include "gf2x.h"
#include "hqc.h"
#include "lc_sha3.h"
#include "parsing.h"
#include "ret_checkers.h"
#include "shake_prng.h"
#include "vector.h"

/**
 * @brief Keygen of the HQC_PKE IND_CPA scheme
 *
 * The public key is composed of the syndrome <b>s</b> as well as the
 * <b>seed</b> used to generate the vector <b>h</b>.
 *
 * The secret key is composed of the <b>seed</b> used to generate vectors
 * <b>x</b> and  <b>y</b>. As a technicality, the public key is appended to the
 * secret key in order to respect NIST API.
 *
 * @param[out] pk String containing the public key
 * @param[out] sk String containing the secret key
 */
int hqc_pke_keygen(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
		   struct lc_rng_ctx *rng_ctx)
{
	uint8_t sk_seed[LC_HQC_SEED_BYTES] = { 0 };
	uint8_t sigma[LC_HQC_VEC_K_SIZE_BYTES] = { 0 };
	uint8_t pk_seed[LC_HQC_SEED_BYTES] = { 0 };
	uint64_t x[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t y[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t h[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t s[LC_HQC_VEC_N_SIZE_64] = { 0 };
	int ret;
	LC_SHAKE_256_CTX_ON_STACK(sk_seedexpander);
	LC_SHAKE_256_CTX_ON_STACK(pk_seedexpander);

	// Create seed_expanders for public key and secret key
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, sk_seed, LC_HQC_SEED_BYTES));
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, sigma,
			      LC_HQC_VEC_K_SIZE_BYTES));
	seedexpander_init(sk_seedexpander, sk_seed, LC_HQC_SEED_BYTES);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, pk_seed, LC_HQC_SEED_BYTES));
	seedexpander_init(pk_seedexpander, pk_seed, LC_HQC_SEED_BYTES);

	// Compute secret key
	//TODO PQClean vs reference inconsistency: x and y calls are swapped
	vect_set_random_fixed_weight(sk_seedexpander, y, LC_HQC_PARAM_OMEGA);
	vect_set_random_fixed_weight(sk_seedexpander, x, LC_HQC_PARAM_OMEGA);

	// Compute public key
	vect_set_random(pk_seedexpander, h);
	vect_mul(s, y, h);
	vect_add(s, x, s, LC_HQC_VEC_N_SIZE_64);

	// Parse keys to string
	hqc_public_key_to_string(pk->pk, pk_seed, s);
	hqc_secret_key_to_string(sk->sk, sk_seed, sigma, pk->pk);

out:
	lc_hash_zero(sk_seedexpander);
	lc_hash_zero(pk_seedexpander);
	return ret;
}

/**
 * @brief Encryption of the HQC_PKE IND_CPA scheme
 *
 * The cihertext is composed of vectors <b>u</b> and <b>v</b>.
 *
 * @param[out] u Vector u (first part of the ciphertext)
 * @param[out] v Vector v (second part of the ciphertext)
 * @param[in] m Vector representing the message to encrypt
 * @param[in] theta Seed used to derive randomness required for encryption
 * @param[in] pk String containing the public key
 */
void hqc_pke_encrypt(uint64_t *u, uint64_t *v, uint8_t *m, uint8_t *theta,
		     const uint8_t *pk)
{
	uint64_t h[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t s[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t r1[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t r2[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t e[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t tmp1[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t tmp2[LC_HQC_VEC_N_SIZE_64] = { 0 };
	LC_SHAKE_256_CTX_ON_STACK(vec_seedexpander);

	// Create seed_expander from theta
	seedexpander_init(vec_seedexpander, theta, LC_HQC_SEED_BYTES);

	// Retrieve h and s from public key
	hqc_public_key_from_string(h, s, pk);

	// Generate r1, r2 and e
	//TODO PQClean vs reference inconsistency: r1 moved to the end of the generation
	vect_set_random_fixed_weight(vec_seedexpander, r2,
				     LC_HQC_PARAM_OMEGA_R);
	vect_set_random_fixed_weight(vec_seedexpander, e, LC_HQC_PARAM_OMEGA_E);
	vect_set_random_fixed_weight(vec_seedexpander, r1,
				     LC_HQC_PARAM_OMEGA_R);

	// Compute u = r1 + r2.h
	vect_mul(u, r2, h);
	vect_add(u, r1, u, LC_HQC_VEC_N_SIZE_64);

	// Compute v = m.G by encoding the message
	code_encode(v, m);
	vect_resize(tmp1, LC_HQC_PARAM_N, v, LC_HQC_PARAM_N1N2);

	// Compute v = m.G + s.r2 + e
	vect_mul(tmp2, r2, s);
	vect_add(tmp2, e, tmp2, LC_HQC_VEC_N_SIZE_64);
	vect_add(tmp2, tmp1, tmp2, LC_HQC_VEC_N_SIZE_64);
	vect_resize(v, LC_HQC_PARAM_N1N2, tmp2, LC_HQC_PARAM_N);

	lc_hash_zero(vec_seedexpander);
}

/**
 * @brief Decryption of the HQC_PKE IND_CPA scheme
 *
 * @param[out] m Vector representing the decrypted message
 * @param[in] u Vector u (first part of the ciphertext)
 * @param[in] v Vector v (second part of the ciphertext)
 * @param[in] sk String containing the secret key
 *
 * @returns 0
 */
uint8_t hqc_pke_decrypt(uint8_t *m, uint8_t *sigma, const uint64_t *u,
			const uint64_t *v, const uint8_t *sk)
{
	uint64_t y[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint8_t pk[LC_HQC_PUBLIC_KEY_BYTES] = { 0 };
	uint64_t tmp1[LC_HQC_VEC_N_SIZE_64] = { 0 };
	uint64_t tmp2[LC_HQC_VEC_N_SIZE_64] = { 0 };

	// Retrieve x, y, pk from secret
	//TODO PQClean vs reference inconsistency: x not required (changes how y is computed)
	hqc_secret_key_from_string(y, sigma, pk, sk);

	// Compute v - u.y
	vect_resize(tmp1, LC_HQC_PARAM_N, v, LC_HQC_PARAM_N1N2);
	vect_mul(tmp2, y, u);
	vect_add(tmp2, tmp1, tmp2, LC_HQC_VEC_N_SIZE_64);

	// Compute m by decoding v - u.y
	code_decode(m, tmp2);

	return 0;
}
