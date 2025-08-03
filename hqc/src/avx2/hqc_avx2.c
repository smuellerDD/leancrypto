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
 * @file hqc.c
 * @brief Implementation of hqc.h
 */

#include "code_avx2.h"
#include "hqc_type.h"
#include "gf2x_avx2.h"
#include "hqc_avx2.h"
#include "lc_sha3.h"
#include "parsing_avx2.h"
#include "small_stack_support.h"
#include "timecop.h"
#include "ret_checkers.h"
#include "vector_avx2.h"

#include "../parsing.h"
#include "../shake_prng.h"
#include "../vector.h"

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
int hqc_pke_keygen_avx2(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
			struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		__m256i h_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
		__m256i y_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
		__m256i x_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
		__m256i tmp_256[LC_HQC_VEC_N_256_SIZE_64 >> 2];
		uint64_t s[LC_HQC_VEC_N_256_SIZE_64];
		uint8_t sk_seed[LC_HQC_SEED_BYTES];
		uint8_t sigma[LC_HQC_VEC_K_SIZE_BYTES];
		uint8_t pk_seed[LC_HQC_SEED_BYTES];
		union {
			struct vect_set_random_fixed_weight_ws vect_set_f_ws;
			struct vect_set_random_ws vect_set_r_ws;
			struct vect_mul_ws vect_mul_ws;
		} wsu;
	};
	int ret;
	LC_SHAKE_256_CTX_ON_STACK(sk_seedexpander);
	LC_SHAKE_256_CTX_ON_STACK(pk_seedexpander);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(__m256i));

	// Create seed_expanders for public key and secret key
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->sk_seed,
			      LC_HQC_SEED_BYTES));
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->sigma,
			      LC_HQC_VEC_K_SIZE_BYTES));
	seedexpander_init(sk_seedexpander, ws->sk_seed, LC_HQC_SEED_BYTES);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->pk_seed,
			      LC_HQC_SEED_BYTES));
	seedexpander_init(pk_seedexpander, ws->pk_seed, LC_HQC_SEED_BYTES);

	// Compute secret key
	vect_set_random_fixed_weight_avx2(sk_seedexpander, ws->y_256,
					  LC_HQC_PARAM_OMEGA,
					  &ws->wsu.vect_set_f_ws);
	vect_set_random_fixed_weight_avx2(sk_seedexpander, ws->x_256,
					  LC_HQC_PARAM_OMEGA,
					  &ws->wsu.vect_set_f_ws);

	// Compute public key
	vect_set_random(pk_seedexpander, (uint64_t *)ws->h_256,
			&ws->wsu.vect_set_r_ws);

	LC_FPU_ENABLE;

	vect_mul_avx2(ws->tmp_256, ws->y_256, ws->h_256, &ws->wsu.vect_mul_ws);
	vect_add(ws->s, (uint64_t *)ws->x_256, (uint64_t *)ws->tmp_256,
		 LC_HQC_VEC_N_256_SIZE_64);

	// Parse keys to string
	hqc_public_key_to_string(pk->pk, ws->pk_seed, ws->s);
	hqc_secret_key_to_string(sk->sk, ws->sk_seed, ws->sigma, pk->pk);

	LC_FPU_DISABLE;

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
noinline_stack void hqc_pke_encrypt_avx2(uint64_t *u, uint64_t *v, uint8_t *m,
					 uint8_t *theta, const uint8_t *pk,
					 struct hqc_pke_encrypt_ws *ws)
{
	LC_SHAKE_256_CTX_ON_STACK(vec_seedexpander);

	// Create seed_expander from theta
	seedexpander_init(vec_seedexpander, theta, LC_HQC_SEED_BYTES);

	// Retrieve h and s from public key
	hqc_public_key_from_string((uint64_t *)ws->h_256, (uint64_t *)ws->s_256,
				   pk, &ws->wsu.vect_set_r_ws);

	// Generate r1, r2 and e
	vect_set_random_fixed_weight_avx2(vec_seedexpander, ws->r2_256,
					  LC_HQC_PARAM_OMEGA_R,
					  &ws->wsu.vect_set_f_ws);
	vect_set_random_fixed_weight_avx2(vec_seedexpander, ws->e_256,
					  LC_HQC_PARAM_OMEGA_E,
					  &ws->wsu.vect_set_f_ws);
	vect_set_random_fixed_weight_avx2(vec_seedexpander, ws->r1_256,
					  LC_HQC_PARAM_OMEGA_R,
					  &ws->wsu.vect_set_f_ws);

	LC_FPU_ENABLE;

	// Compute u = r1 + r2.h
	vect_mul_avx2(ws->tmp1_256, ws->r2_256, ws->h_256,
		      &ws->wsu.vect_mul_ws);
	vect_add(u, (uint64_t *)ws->r1_256, (uint64_t *)ws->tmp1_256,
		 LC_HQC_VEC_N_256_SIZE_64);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	/*
	 * The cast is appropriate because lc_hqc_enc_impl aligns the variable
	 * tmp to 64 bits.
	 */
	// Compute v = m.G by encoding the message
	code_encode_avx2(v, (uint64_t *)m);
#pragma GCC diagnostic pop

	vect_resize((uint64_t *)ws->tmp2_256, LC_HQC_PARAM_N, v,
		    LC_HQC_PARAM_N1N2);

	// Compute v = m.G + s.r2 + e
	vect_mul_avx2(ws->tmp3_256, ws->r2_256, ws->s_256,
		      &ws->wsu.vect_mul_ws);
	vect_add(ws->tmp4, (uint64_t *)ws->e_256, (uint64_t *)ws->tmp3_256,
		 LC_HQC_VEC_N_256_SIZE_64);
	vect_add((uint64_t *)ws->tmp3_256, (uint64_t *)ws->tmp2_256, ws->tmp4,
		 LC_HQC_VEC_N_256_SIZE_64);
	vect_resize(v, LC_HQC_PARAM_N1N2, (uint64_t *)ws->tmp3_256,
		    LC_HQC_PARAM_N);

	LC_FPU_DISABLE;

	lc_hash_zero(vec_seedexpander);
}

/**
 * @brief Decryption of the HQC_PKE IND_CPA scheme
 *
 * @param[out] m Vector representing the decrypted message
 * @param[in] u Vector u (first part of the ciphertext)
 * @param[in] v Vector v (second part of the ciphertext)
 * @param[in] sk String containing the secret key
 * @returns 0 
 */
void vect_mul(uint64_t *o, const uint64_t *v1, const uint64_t *v2,
	      struct vect_mul_ws *ws);
noinline_stack uint8_t hqc_pke_decrypt_avx2(uint8_t *m, uint8_t *sigma,
					    const uint64_t *u,
					    const uint64_t *v,
					    const uint8_t *sk,
					    struct hqc_pke_decrypt_ws *ws)
{
	// Retrieve x, y, pk from secret key
	hqc_secret_key_from_string_avx2(ws->y_256, sigma, ws->pk, sk,
					&ws->wsu.vect_set_f_ws);

	// Compute v - u.y
	vect_resize(ws->tmp1, LC_HQC_PARAM_N, v, LC_HQC_PARAM_N1N2);

	LC_FPU_ENABLE;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	/*
	 * The cast is appropriate because lc_hqc_dec_impl aligns the variable
	 * u to 256 bits.
	 */
	//TODO
	vect_mul((uint64_t *)ws->tmp3_256, (uint64_t *)ws->y_256, u,
		 &ws->wsu.vect_mul_ws);
	//vect_mul_avx2(ws->tmp3_256, ws->y_256, (const __m256i *)u,
	//	 &ws->wsu.vect_mul_ws);
#pragma GCC diagnostic pop

	vect_add(ws->tmp2, ws->tmp1, (uint64_t *)ws->tmp3_256,
		 LC_HQC_VEC_N_256_SIZE_64);

	//TODO: is this correct?
	unpoison(ws, sizeof(struct hqc_pke_decrypt_ws));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
	/*
	 * The cast is appropriate because lc_hqc_dec_impl aligns the variable
	 * tmp to 64 bits.
	 */
	// Compute m by decoding v - u.y
	code_decode_avx2((uint64_t *)m, ws->tmp2, &ws->wsu.reed_decode_ws);
#pragma GCC diagnostic pop

	LC_FPU_DISABLE;

	return 0;
}
