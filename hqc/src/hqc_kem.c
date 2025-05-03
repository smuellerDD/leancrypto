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

#include "build_bug_on.h"
#include "hqc_internal.h"
#include "hqc.h"
#include "hqc_selftest.h"
#include "lc_kmac.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "parsing.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "vector.h"
#include "visibility.h"

/**
 * @brief hqc_ss_kdf - KDF to derive arbitrary sized SS from HQC SS
 *
 *	SS <- KMAC256(K = BIKE-SS, X = BIKE-CT, L = requested SS length,
 *		      S = "HQC KEM SS")
 *
 * This KDF is is consistent with SP800-108 rev 1.
 */
static inline void hqc_ss_kdf(uint8_t *ss, size_t ss_len,
			      const struct lc_hqc_ct *ct,
			      const uint8_t hqc_ss[LC_HQC_SHARED_SECRET_BYTES])
{
	static const uint8_t hqc_ss_label[] = "HQC KEM SS";

	lc_kmac(lc_cshake256, hqc_ss, LC_HQC_SHARED_SECRET_BYTES, hqc_ss_label,
		sizeof(hqc_ss_label) - 1, (uint8_t *)ct,
		sizeof(struct lc_hqc_ct), ss, ss_len);
}

/**
 * @brief Keygen of the HQC_KEM IND_CCA2 scheme
 *
 * The public key is composed of the syndrome <b>s</b> as well as the seed used
 * to generate the vector <b>h</b>.
 *
 * The secret key is composed of the seed used to generate vectors <b>x</b> and
 * <b>y</b>. As a technicality, the public key is appended to the secret key in
 * order to respect NIST API.
 *
 * @param[out] pk String containing the public key
 * @param[out] sk String containing the secret key
 *
 * @returns 0 if keygen is successful
 */
LC_INTERFACE_FUNCTION(int, lc_hqc_keypair, struct lc_hqc_pk *pk,
		      struct lc_hqc_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	static int tester = 0;

	hqc_kem_keygen_selftest(&tester, "HQC KEM keypair C", lc_hqc_keypair);
	return hqc_pke_keygen(pk, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_keypair_from_seed, struct lc_hqc_pk *pk,
		      struct lc_hqc_sk *sk, const uint8_t *seed, size_t seedlen)
{
	struct lc_static_rng_data static_data = {
		.seed = seed,
		.seedlen = seedlen,
	};
	LC_STATIC_DRNG_ON_STACK(sdrng, &static_data);

	return lc_hqc_keypair(pk, sk, &sdrng);
}

static inline void hqc_shake256_512(struct lc_hash_ctx *shake256,
				    uint8_t *output, const uint8_t *input,
				    size_t inlen, uint8_t domain)
{
	lc_hash_init(shake256);
	lc_hash_update(shake256, input, inlen);
	lc_hash_update(shake256, &domain, 1);
	lc_hash_set_digestsize(shake256, LC_HQC_SHAKE256_512_BYTES);
	lc_hash_final(shake256, output);
}

/**
 * @brief Encapsulation of the HQC_KEM IND_CAA2 scheme
 *
 * @param[out] ct String containing the ciphertext
 * @param[out] ss String containing the shared secret
 * @param[in] pk String containing the public key
 * @returns 0 if encapsulation is successful
 */
LC_INTERFACE_FUNCTION(int, lc_hqc_enc_internal, struct lc_hqc_ct *ct,
		      struct lc_hqc_ss *ss, const struct lc_hqc_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		uint8_t theta[LC_HQC_SHAKE256_512_BYTES];
		uint64_t u[LC_HQC_VEC_N_SIZE_64];
		uint64_t v[LC_HQC_VEC_N1N2_SIZE_64];
		uint8_t mc[LC_HQC_VEC_K_SIZE_BYTES + LC_HQC_VEC_N_SIZE_BYTES +
			   LC_HQC_VEC_N1N2_SIZE_BYTES];
		uint8_t tmp[LC_HQC_VEC_K_SIZE_BYTES +
			    2 * LC_HQC_SALT_SIZE_BYTES + LC_HQC_SALT_SIZE_BYTES];
		struct hqc_pke_encrypt_ws hqc_pke_ws;
	};
	uint8_t *m, *salt;
	int ret;
	LC_SHAKE_256_CTX_ON_STACK(shake256);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	m = ws->tmp;
	salt = ws->tmp + LC_HQC_VEC_K_SIZE_BYTES + 2 * LC_HQC_SALT_SIZE_BYTES;

	// Computing m
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, m, LC_HQC_VEC_K_SIZE_BYTES));

	// Computing theta
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, salt, LC_HQC_SALT_SIZE_BYTES));
	memcpy(ws->tmp + LC_HQC_VEC_K_SIZE_BYTES, pk->pk,
	       2 * LC_HQC_SALT_SIZE_BYTES);
	hqc_shake256_512(shake256, ws->theta, ws->tmp,
			 LC_HQC_VEC_K_SIZE_BYTES + 2 * LC_HQC_SALT_SIZE_BYTES +
				 LC_HQC_SALT_SIZE_BYTES,
			 LC_HQC_G_FCT_DOMAIN);

	// Encrypting m
	hqc_pke_encrypt(ws->u, ws->v, m, ws->theta, pk->pk, &ws->hqc_pke_ws);

	// Computing shared secret
	memcpy(ws->mc, m, LC_HQC_VEC_K_SIZE_BYTES);
	store8_arr(ws->mc + LC_HQC_VEC_K_SIZE_BYTES, LC_HQC_VEC_N_SIZE_BYTES,
		   ws->u, LC_HQC_VEC_N_SIZE_64);
	store8_arr(ws->mc + LC_HQC_VEC_K_SIZE_BYTES + LC_HQC_VEC_N_SIZE_BYTES,
		   LC_HQC_VEC_N1N2_SIZE_BYTES, ws->v, LC_HQC_VEC_N1N2_SIZE_64);
	hqc_shake256_512(shake256, ss->ss, ws->mc,
			 LC_HQC_VEC_K_SIZE_BYTES + LC_HQC_VEC_N_SIZE_BYTES +
				 LC_HQC_VEC_N1N2_SIZE_BYTES,
			 LC_HQC_K_FCT_DOMAIN);

	// Computing ciphertext
	hqc_ciphertext_to_string(ct->ct, ws->u, ws->v, salt);

out:
	lc_hash_zero(shake256);
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc, struct lc_hqc_ct *ct,
		      struct lc_hqc_ss *ss, const struct lc_hqc_pk *pk)
{
	static int tester = 0;

	hqc_kem_enc_selftest(&tester, "HQC KEM enc C", lc_hqc_enc_internal);
	return lc_hqc_enc_internal(ct, ss, pk, lc_seeded_rng);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc_kdf, struct lc_hqc_ct *ct, uint8_t *ss,
		      size_t ss_len, const struct lc_hqc_pk *pk)
{
	struct lc_hqc_ss hqc_ss;
	int ret;

	CKINT(lc_hqc_enc(ct, &hqc_ss, pk));

	hqc_ss_kdf(ss, ss_len, ct, hqc_ss.ss);

out:
	lc_memset_secure(&hqc_ss, 0, sizeof(hqc_ss));
	return ret;
}

/**
 * @brief Decapsulation of the HQC_KEM IND_CAA2 scheme
 *
 * @param[out] ss String containing the shared secret
 * @param[in] ct String containing the cipĥertext
 * @param[in] sk String containing the secret key
 * @returns 0 if decapsulation is successful, -1 otherwise
 */
LC_INTERFACE_FUNCTION(int, lc_hqc_dec, struct lc_hqc_ss *ss,
		      const struct lc_hqc_ct *ct, const struct lc_hqc_sk *sk)
{
	struct workspace {
		uint64_t u[LC_HQC_VEC_N_SIZE_64];
		uint64_t v[LC_HQC_VEC_N1N2_SIZE_64];
		uint64_t u2[LC_HQC_VEC_N_SIZE_64];
		uint64_t v2[LC_HQC_VEC_N1N2_SIZE_64];
		uint8_t sigma[LC_HQC_VEC_K_SIZE_BYTES];
		uint8_t theta[LC_HQC_SHAKE256_512_BYTES];
		uint8_t tmp[LC_HQC_VEC_K_SIZE_BYTES +
			    2 * LC_HQC_SALT_SIZE_BYTES + LC_HQC_SALT_SIZE_BYTES];
		union {
			uint8_t mc[LC_HQC_VEC_K_SIZE_BYTES +
				   LC_HQC_VEC_N_SIZE_BYTES +
				   LC_HQC_VEC_N1N2_SIZE_BYTES];
			struct hqc_pke_decrypt_ws hqc_decrypt_pke_ws;
			struct hqc_pke_encrypt_ws hqc_encrypt_pke_ws;
		} wsu;
	};
	static int tester = 0;
	const uint8_t *pk =
		sk->sk + LC_HQC_SEED_BYTES + LC_HQC_VEC_K_SIZE_BYTES;
	uint8_t *m, *salt;
	uint8_t result;
	LC_SHAKE_256_CTX_ON_STACK(shake256);
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	hqc_kem_dec_selftest(&tester, "HQC KEM dec C", lc_hqc_dec);

	m = ws->tmp;
	salt = ws->tmp + LC_HQC_VEC_K_SIZE_BYTES + 2 * LC_HQC_SALT_SIZE_BYTES;

	// Retrieving u, v and d from ciphertext
	hqc_ciphertext_from_string(ws->u, ws->v, salt, ct->ct);

	// Decrypting
	result = hqc_pke_decrypt(m, ws->sigma, ws->u, ws->v, sk->sk,
				 &ws->wsu.hqc_decrypt_pke_ws);

	// Computing theta
	memcpy(ws->tmp + LC_HQC_VEC_K_SIZE_BYTES, pk,
	       2 * LC_HQC_SALT_SIZE_BYTES);
	hqc_shake256_512(shake256, ws->theta, ws->tmp,
			 LC_HQC_VEC_K_SIZE_BYTES + 2 * LC_HQC_SALT_SIZE_BYTES +
				 LC_HQC_SALT_SIZE_BYTES,
			 LC_HQC_G_FCT_DOMAIN);

	// Encrypting m'
	memset(&ws->wsu.hqc_encrypt_pke_ws, 0,
	       sizeof(struct hqc_pke_encrypt_ws));
	hqc_pke_encrypt(ws->u2, ws->v2, m, ws->theta, pk,
			&ws->wsu.hqc_encrypt_pke_ws);

	// Check if c != c'
	result |= vect_compare((uint8_t *)ws->u, (uint8_t *)ws->u2,
			       LC_HQC_VEC_N_SIZE_BYTES);
	result |= vect_compare((uint8_t *)ws->v, (uint8_t *)ws->v2,
			       LC_HQC_VEC_N1N2_SIZE_BYTES);

	result -= 1;

	for (size_t i = 0; i < LC_HQC_VEC_K_SIZE_BYTES; ++i)
		ws->wsu.mc[i] = (m[i] & result) ^ (ws->sigma[i] & ~result);

	// Computing shared secret
	store8_arr(ws->wsu.mc + LC_HQC_VEC_K_SIZE_BYTES,
		   LC_HQC_VEC_N_SIZE_BYTES, ws->u, LC_HQC_VEC_N_SIZE_64);
	store8_arr(ws->wsu.mc + LC_HQC_VEC_K_SIZE_BYTES +
			   LC_HQC_VEC_N_SIZE_BYTES,
		   LC_HQC_VEC_N1N2_SIZE_BYTES, ws->v, LC_HQC_VEC_N1N2_SIZE_64);
	BUILD_BUG_ON(LC_HQC_SHAKE256_512_BYTES != LC_HQC_SHARED_SECRET_BYTES);
	hqc_shake256_512(shake256, ss->ss, ws->wsu.mc,
			 LC_HQC_VEC_K_SIZE_BYTES + LC_HQC_VEC_N_SIZE_BYTES +
				 LC_HQC_VEC_N1N2_SIZE_BYTES,
			 LC_HQC_K_FCT_DOMAIN);

	LC_RELEASE_MEM(ws);
	return (result & 1) - 1;
}

LC_INTERFACE_FUNCTION(int, lc_hqc_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_hqc_ct *ct, const struct lc_hqc_sk *sk)
{
	struct lc_hqc_ss hqc_ss;
	int ret;

	CKINT(lc_hqc_dec(&hqc_ss, ct, sk));

	hqc_ss_kdf(ss, ss_len, ct, hqc_ss.ss);

out:
	lc_memset_secure(&hqc_ss, 0, sizeof(hqc_ss));
	return ret;
}
