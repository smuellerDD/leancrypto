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

#ifndef HQC_KEM_IMPL_H
#define HQC_KEM_IMPL_H

#include "build_bug_on.h"
#include "compare.h"
#include "hqc.h"
#include "hqc_pct.h"
#include "hqc_selftest.h"
#include "lc_kmac.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "parsing.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "timecop.h"
#include "vector.h"

#ifdef __cplusplus
extern "C" {
#endif

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
	LC_FIPS_RODATA_SECTION
	static const uint8_t hqc_ss_label[] = "HQC KEM SS";

	lc_kmac(lc_cshake256, hqc_ss, LC_HQC_SHARED_SECRET_BYTES, hqc_ss_label,
		sizeof(hqc_ss_label) - 1, (uint8_t *)ct,
		sizeof(struct lc_hqc_ct), ss, ss_len);
}

static inline int lc_hqc_keypair_impl(
	struct lc_hqc_pk *pk, struct lc_hqc_sk *sk, struct lc_rng_ctx *rng_ctx,
	int (*pke_keygen)(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
			  struct lc_rng_ctx *rng_ctx))
{
	int ret;

	CKINT(pke_keygen(pk, sk, rng_ctx));

	CKINT(lc_hqc_pct_fips(pk, sk));
out:
	return ret;
}

static inline int lc_hqc_keypair_from_seed_impl(
	struct lc_hqc_pk *pk, struct lc_hqc_sk *sk, const uint8_t *seed,
	size_t seedlen,
	int (*pke_keygen)(struct lc_hqc_pk *pk, struct lc_hqc_sk *sk,
			  struct lc_rng_ctx *rng_ctx))
{
	struct lc_static_rng_data static_data = {
		.seed = seed,
		.seedlen = seedlen,
	};
	LC_STATIC_DRNG_ON_STACK(sdrng, &static_data);

	return lc_hqc_keypair_impl(pk, sk, &sdrng, pke_keygen);
}

static inline void hqc_shake256_512(struct lc_hash_ctx *shake256,
				    uint8_t *output, const uint8_t *input,
				    size_t inlen, uint8_t domain)
{
	if (lc_hash_init(shake256))
		return;
	lc_hash_update(shake256, input, inlen);
	lc_hash_update(shake256, &domain, 1);
	lc_hash_set_digestsize(shake256, LC_HQC_SHAKE256_512_BYTES);
	lc_hash_final(shake256, output);
}

static inline int lc_hqc_enc_internal_impl(
	struct lc_hqc_ct *ct, struct lc_hqc_ss *ss, const struct lc_hqc_pk *pk,
	struct lc_rng_ctx *rng_ctx,
	void (*pke_encrypt)(uint64_t *u, uint64_t *v, uint8_t *m,
			    uint8_t *theta, const uint8_t *pk,
			    struct hqc_pke_encrypt_ws *ws))
{
	struct workspace {
		uint64_t u[LC_HQC_VEC_N_SIZE_64];
		uint64_t v[LC_HQC_VEC_N1N2_SIZE_64];
		uint8_t tmp[LC_HQC_VEC_K_SIZE_BYTES +
			    2 * LC_HQC_SALT_SIZE_BYTES + LC_HQC_SALT_SIZE_BYTES];
		uint8_t theta[LC_HQC_SHAKE256_512_BYTES];
		uint8_t mc[LC_HQC_VEC_K_SIZE_BYTES + LC_HQC_VEC_N_SIZE_BYTES +
			   LC_HQC_VEC_N1N2_SIZE_BYTES];

		struct hqc_pke_encrypt_ws hqc_pke_ws;
	};
	uint8_t *m, *salt;
	int ret;
	LC_SHAKE_256_CTX_ON_STACK(shake256);
	/* For AVX2, the alignment is set to sizeof(__m256i) */
	LC_DECLARE_MEM(ws, struct workspace, 32);

	m = ws->tmp;
	salt = ws->tmp + LC_HQC_VEC_K_SIZE_BYTES + 2 * LC_HQC_SALT_SIZE_BYTES;

	// Computing m
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, m, LC_HQC_VEC_K_SIZE_BYTES));
	poison(m, LC_HQC_VEC_K_SIZE_BYTES);

	// Computing theta
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, salt, LC_HQC_SALT_SIZE_BYTES));
	memcpy(ws->tmp + LC_HQC_VEC_K_SIZE_BYTES, pk->pk,
	       2 * LC_HQC_SALT_SIZE_BYTES);
	hqc_shake256_512(shake256, ws->theta, ws->tmp,
			 LC_HQC_VEC_K_SIZE_BYTES + 2 * LC_HQC_SALT_SIZE_BYTES +
				 LC_HQC_SALT_SIZE_BYTES,
			 LC_HQC_G_FCT_DOMAIN);

	// Encrypting m
	pke_encrypt(ws->u, ws->v, m, ws->theta, pk->pk, &ws->hqc_pke_ws);

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

	/*
	 * Timecop: unpoison SS and CT as they go out of scope for leancrypto.
	 */
	unpoison(ct->ct, sizeof(ct->ct));
	unpoison(ss->ss, sizeof(ss->ss));

out:
	lc_hash_zero(shake256);
	LC_RELEASE_MEM(ws);
	return ret;
}

static inline int
lc_hqc_enc_impl(struct lc_hqc_ct *ct, struct lc_hqc_ss *ss,
		const struct lc_hqc_pk *pk,
		void (*pke_encrypt)(uint64_t *u, uint64_t *v, uint8_t *m,
				    uint8_t *theta, const uint8_t *pk,
				    struct hqc_pke_encrypt_ws *ws))
{
	return lc_hqc_enc_internal_impl(ct, ss, pk, lc_seeded_rng, pke_encrypt);
}

static inline int
lc_hqc_enc_kdf_impl(struct lc_hqc_ct *ct, uint8_t *ss, size_t ss_len,
		    const struct lc_hqc_pk *pk,
		    void (*pke_encrypt)(uint64_t *u, uint64_t *v, uint8_t *m,
					uint8_t *theta, const uint8_t *pk,
					struct hqc_pke_encrypt_ws *ws))
{
	struct lc_hqc_ss hqc_ss;
	int ret;

	CKINT(lc_hqc_enc_impl(ct, &hqc_ss, pk, pke_encrypt));

	hqc_ss_kdf(ss, ss_len, ct, hqc_ss.ss);

out:
	lc_memset_secure(&hqc_ss, 0, sizeof(hqc_ss));
	return ret;
}

static inline int lc_hqc_dec_impl(
	struct lc_hqc_ss *ss, const struct lc_hqc_ct *ct,
	const struct lc_hqc_sk *sk,
	void (*pke_encrypt)(uint64_t *u, uint64_t *v, uint8_t *m,
			    uint8_t *theta, const uint8_t *pk,
			    struct hqc_pke_encrypt_ws *ws),
	uint8_t (*pke_decrypt)(uint8_t *m, uint8_t *sigma, const uint64_t *u,
			       const uint64_t *v, const uint8_t *sk,
			       struct hqc_pke_decrypt_ws *ws))
{
	struct workspace {
		uint64_t u[LC_HQC_VEC_N_SIZE_64];
		uint64_t v[LC_HQC_VEC_N1N2_SIZE_64];
		uint64_t u2[LC_HQC_VEC_N_SIZE_64];
		uint64_t v2[LC_HQC_VEC_N1N2_SIZE_64];
		uint8_t tmp[LC_HQC_VEC_K_SIZE_BYTES +
			    2 * LC_HQC_SALT_SIZE_BYTES + LC_HQC_SALT_SIZE_BYTES];
		uint8_t sigma[LC_HQC_VEC_K_SIZE_BYTES];
		uint8_t theta[LC_HQC_SHAKE256_512_BYTES];
		union {
			uint8_t mc[LC_HQC_VEC_K_SIZE_BYTES +
				   LC_HQC_VEC_N_SIZE_BYTES +
				   LC_HQC_VEC_N1N2_SIZE_BYTES];
			struct hqc_pke_decrypt_ws hqc_decrypt_pke_ws;
			struct hqc_pke_encrypt_ws hqc_encrypt_pke_ws;
		} wsu;
	};
	const uint8_t *pk =
		sk->sk + LC_HQC_SEED_BYTES + LC_HQC_VEC_K_SIZE_BYTES;
	uint8_t *m, *salt;
	uint8_t result;
	LC_SHAKE_256_CTX_ON_STACK(shake256);

	/* For AVX2, the alignment is set to sizeof(__m256i) */
	LC_DECLARE_MEM(ws, struct workspace, 32);

	poison(sk->sk, sizeof(sk->sk));

	m = ws->tmp;
	salt = ws->tmp + LC_HQC_VEC_K_SIZE_BYTES + 2 * LC_HQC_SALT_SIZE_BYTES;

	// Retrieving u, v and d from ciphertext
	hqc_ciphertext_from_string(ws->u, ws->v, salt, ct->ct);

	// Decrypting
	result = pke_decrypt(m, ws->sigma, ws->u, ws->v, sk->sk,
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
	pke_encrypt(ws->u2, ws->v2, m, ws->theta, pk,
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

	/*
	 * Timecop: unpoison SK, SS and CT as they go out of scope for
	 * leancrypto.
	 */
	unpoison(sk->sk, sizeof(sk->sk));
	unpoison(ct->ct, sizeof(ct->ct));
	unpoison(ss->ss, sizeof(ss->ss));
	unpoison(&result, sizeof(result));

	LC_RELEASE_MEM(ws);
	return (result & 1) - 1;
}

static inline int lc_hqc_dec_kdf_impl(
	uint8_t *ss, size_t ss_len, const struct lc_hqc_ct *ct,
	const struct lc_hqc_sk *sk,
	void (*pke_encrypt)(uint64_t *u, uint64_t *v, uint8_t *m,
			    uint8_t *theta, const uint8_t *pk,
			    struct hqc_pke_encrypt_ws *ws),
	uint8_t (*pke_decrypt)(uint8_t *m, uint8_t *sigma, const uint64_t *u,
			       const uint64_t *v, const uint8_t *sk,
			       struct hqc_pke_decrypt_ws *ws))
{
	struct lc_hqc_ss hqc_ss;
	int ret;

	CKINT(lc_hqc_dec_impl(&hqc_ss, ct, sk, pke_encrypt, pke_decrypt));

	hqc_ss_kdf(ss, ss_len, ct, hqc_ss.ss);

out:
	lc_memset_secure(&hqc_ss, 0, sizeof(hqc_ss));
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* HQC_KEM_IMPL_H */
