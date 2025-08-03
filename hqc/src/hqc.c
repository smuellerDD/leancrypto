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
#include "small_stack_support.h"
#include "timecop.h"
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
	struct workspace {
		uint8_t sk_seed[LC_HQC_SEED_BYTES];
		uint8_t sigma[LC_HQC_VEC_K_SIZE_BYTES];
		uint8_t pk_seed[LC_HQC_SEED_BYTES];
		uint64_t x[LC_HQC_VEC_N_SIZE_64];
		uint64_t y[LC_HQC_VEC_N_SIZE_64];
		uint64_t h[LC_HQC_VEC_N_SIZE_64];
		uint64_t s[LC_HQC_VEC_N_SIZE_64];
		union {
			struct vect_set_random_fixed_weight_ws vect_set_f_ws;
			struct vect_set_random_ws vect_set_r_ws;
			struct vect_mul_ws vect_mul_ws;
		} wsu;
	};
	int ret;
	LC_SHAKE_256_CTX_ON_STACK(sk_seedexpander);
	LC_SHAKE_256_CTX_ON_STACK(pk_seedexpander);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	// Create seed_expanders for public key and secret key
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->sk_seed,
			      LC_HQC_SEED_BYTES));
	poison(ws->sk_seed, LC_HQC_SEED_BYTES);
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->sigma,
			      LC_HQC_VEC_K_SIZE_BYTES));
	poison(ws->sigma, LC_HQC_VEC_K_SIZE_BYTES);
	seedexpander_init(sk_seedexpander, ws->sk_seed, LC_HQC_SEED_BYTES);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->pk_seed,
			      LC_HQC_SEED_BYTES));
	poison(ws->pk_seed, LC_HQC_SEED_BYTES);
	seedexpander_init(pk_seedexpander, ws->pk_seed, LC_HQC_SEED_BYTES);

	// Compute secret key
	vect_set_random_fixed_weight(sk_seedexpander, ws->y, LC_HQC_PARAM_OMEGA,
				     &ws->wsu.vect_set_f_ws);
	vect_set_random_fixed_weight(sk_seedexpander, ws->x, LC_HQC_PARAM_OMEGA,
				     &ws->wsu.vect_set_f_ws);

	// Compute public key
	vect_set_random(pk_seedexpander, ws->h, &ws->wsu.vect_set_r_ws);
	vect_mul(ws->s, ws->y, ws->h, &ws->wsu.vect_mul_ws);
	vect_add(ws->s, ws->x, ws->s, LC_HQC_VEC_N_SIZE_64);

	// Parse keys to string
	hqc_public_key_to_string(pk->pk, ws->pk_seed, ws->s);
	hqc_secret_key_to_string(sk->sk, ws->sk_seed, ws->sigma, pk->pk);

	/*
	 * Timecop: unpoison the generated keys now as they leave the scope of
	 * leancrypto.
	 */
	unpoison(pk->pk, sizeof(pk->pk));
	unpoison(sk->sk, sizeof(sk->sk));

out:
	lc_hash_zero(sk_seedexpander);
	lc_hash_zero(pk_seedexpander);
	LC_RELEASE_MEM(ws);
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
		     const uint8_t *pk, struct hqc_pke_encrypt_ws *ws)
{
	LC_SHAKE_256_CTX_ON_STACK(vec_seedexpander);

	// Create seed_expander from theta
	seedexpander_init(vec_seedexpander, theta, LC_HQC_SEED_BYTES);

	// Retrieve h and s from public key
	hqc_public_key_from_string(ws->h, ws->s, pk, &ws->wsu.vect_set_r_ws);

	// Generate r1, r2 and e
	vect_set_random_fixed_weight(vec_seedexpander, ws->r2,
				     LC_HQC_PARAM_OMEGA_R,
				     &ws->wsu.vect_set_f_ws);
	vect_set_random_fixed_weight(vec_seedexpander, ws->e,
				     LC_HQC_PARAM_OMEGA_E,
				     &ws->wsu.vect_set_f_ws);
	vect_set_random_fixed_weight(vec_seedexpander, ws->r1,
				     LC_HQC_PARAM_OMEGA_R,
				     &ws->wsu.vect_set_f_ws);

	// Compute u = r1 + r2.h
	vect_mul(u, ws->r2, ws->h, &ws->wsu.vect_mul_ws);
	vect_add(u, ws->r1, u, LC_HQC_VEC_N_SIZE_64);

	// Compute v = m.G by encoding the message
	code_encode(v, m);
	vect_resize(ws->tmp1, LC_HQC_PARAM_N, v, LC_HQC_PARAM_N1N2);

	// Compute v = m.G + s.r2 + e
	vect_mul(ws->tmp2, ws->r2, ws->s, &ws->wsu.vect_mul_ws);
	vect_add(ws->tmp2, ws->e, ws->tmp2, LC_HQC_VEC_N_SIZE_64);
	vect_add(ws->tmp2, ws->tmp1, ws->tmp2, LC_HQC_VEC_N_SIZE_64);
	vect_resize(v, LC_HQC_PARAM_N1N2, ws->tmp2, LC_HQC_PARAM_N);

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
noinline_stack uint8_t hqc_pke_decrypt(uint8_t *m, uint8_t *sigma,
				       const uint64_t *u, const uint64_t *v,
				       const uint8_t *sk,
				       struct hqc_pke_decrypt_ws *ws)
{
	// Retrieve x, y, pk from secret
	hqc_secret_key_from_string(ws->y, sigma, ws->pk, sk,
				   &ws->wsu.vect_set_f_ws);

	// Compute v - u.y
	vect_resize(ws->tmp1, LC_HQC_PARAM_N, v, LC_HQC_PARAM_N1N2);
	vect_mul(ws->tmp2, ws->y, u, &ws->wsu.vect_mul_ws);
	vect_add(ws->tmp2, ws->tmp1, ws->tmp2, LC_HQC_VEC_N_SIZE_64);
	// Compute m by decoding v - u.y
	memset(&ws->wsu.reed_solomon_decode_ws, 0,
	       sizeof(struct reed_solomon_decode_ws));

	//TODO: is this correct?
	unpoison(ws, sizeof(struct hqc_pke_decrypt_ws));
	code_decode(m, ws->tmp2, &ws->wsu.reed_solomon_decode_ws);
	poison(m, LC_HQC_VEC_K_SIZE_BYTES);

	return 0;
}
