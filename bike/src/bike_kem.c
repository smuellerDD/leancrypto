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
 * https://github.com/awslabs/bike-kem
 *
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0"
 *
 * Written by Nir Drucker, Shay Gueron, and Dusan Kostic,
 * AWS Cryptographic Algorithms Group.
 */

#include "bike_decode.h"
#include "bike_gf2x.h"
#include "bike_internal.h"
#include "bike_sampling.h"
#include "bike_utilities.h"

#include "build_bug_on.h"
#include "lc_kmac.h"
#include "lc_memset_secure.h"
#include "lc_memcmp_secure.h"
#include "lc_rng.h"
#include "lc_sha3.h"

#include "ret_checkers.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "visibility.h"

// m_t and seed_t have the same size and thus can be considered
// to be of the same type. However, for security reasons we distinguish
// these types, even on the costs of small extra complexity.
static inline void convert_seed_to_m_type(m_t *m, const seed_t *seed)
{
	BUILD_BUG_ON(sizeof(*m) != sizeof(*seed));
	memcpy(m->raw, seed->raw, sizeof(*m));
}

#if !defined(BIND_PK_AND_M)

static inline void convert_m_to_seed_type(seed_t *seed, const m_t *m)
{
	BUILD_BUG_ON(sizeof(*m) != sizeof(*seed));
	memcpy(seed->raw, m->raw, sizeof(*seed));
}

#endif

// (e0, e1) = H(m)
static inline int function_h(pad_e_t *e, const m_t *m, const r_t *pk)
{
	seed_t seed = { 0 };
	int ret;

#if defined(BIND_PK_AND_M)
	uint8_t dgst[LC_SHA3_384_SIZE_DIGEST];
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha3_384);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, pk->raw, sizeof(pk->raw));
	lc_hash_update(hash_ctx, m->raw, sizeof(m->raw));
	lc_hash_final(hash_ctx, dgst);
	lc_hash_zero(hash_ctx);

	memcpy(seed.raw, dgst, sizeof(seed));
	lc_memset_secure(&dgst, 0, sizeof(dgst));
#else
	// pk is unused parameter in this case so we do this to avoid
	// clang sanitizers complaining.
	(void)pk;

	convert_m_to_seed_type(&seed, m);
#endif

	CKINT(generate_error_vector(e, &seed));

out:
	lc_memset_secure(&seed, 0, sizeof(seed));
	return ret;
}

// out = L(e)
static inline void function_l(m_t *out, const pad_e_t *e)
{
	uint8_t dgst[LC_SHA3_384_SIZE_DIGEST];

	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha3_384);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, (const uint8_t *)&e->val[0].val,
		       sizeof(e->val[0].val));
	lc_hash_update(hash_ctx, (const uint8_t *)&e->val[1].val,
		       sizeof(e->val[1].val));
	lc_hash_final(hash_ctx, dgst);

	lc_hash_zero(hash_ctx);

	// Truncate the SHA384 digest to a 256-bits m_t
	BUILD_BUG_ON(sizeof(dgst) < sizeof(*out));
	memcpy(out->raw, dgst, sizeof(*out));

	lc_memset_secure(dgst, 0, sizeof(dgst));
}

// Generate the Shared Secret K(m, c0, c1)
static inline void function_k(struct lc_bike_ss *out, const m_t *m,
			      const struct lc_bike_ct *ct)
{
	uint8_t dgst[LC_SHA3_384_SIZE_DIGEST];
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha3_384);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, (const uint8_t *)m, sizeof(*m));
	lc_hash_update(hash_ctx, (const uint8_t *)&ct->c0, sizeof(ct->c0));
	lc_hash_update(hash_ctx, (const uint8_t *)&ct->c1, sizeof(ct->c1));
	lc_hash_final(hash_ctx, dgst);

	lc_hash_zero(hash_ctx);

	// Truncate the SHA384 digest to a 256-bits value
	// to subsequently use it as a seed.
	BUILD_BUG_ON(sizeof(dgst) < sizeof(*out));
	memcpy(out->ss, dgst, sizeof(out->ss));

	lc_memset_secure(dgst, 0, sizeof(dgst));
}

static inline void bike_encrypt(struct lc_bike_ct *ct, const pad_e_t *e,
				const r_t *pk, const m_t *m, pad_r_t *p_ct,
				pad_r_t *p_pk, dbl_pad_r_t *t,
				uint64_t secure_buffer[LC_SECURE_BUFFER_QWORDS])
{
	unsigned int i;

	p_pk->val = *pk;

	// Generate the ciphertext
	// ct = pk * e1 + e0
	gf2x_mod_mul(p_ct, &e->val[1], p_pk, t, secure_buffer);
	gf2x_mod_add(p_ct, p_ct, &e->val[0]);

	ct->c0 = p_ct->val;

	// c1 = L(e0, e1)
	function_l(&ct->c1, e);

	// m xor L(e0, e1)
	for (i = 0; i < sizeof(*m); i++)
		ct->c1.raw[i] ^= m->raw[i];

	//print("e0: ", (const uint64_t *)PE0_RAW(e), R_BITS);
	//print("e1: ", (const uint64_t *)PE1_RAW(e), R_BITS);
	//print("c0:  ", (uint64_t *)ct->c0.raw, R_BITS);
	//print("c1:  ", (uint64_t *)ct->c1.raw, M_BITS);
}

static inline void reencrypt(m_t *m, const pad_e_t *e,
			     const struct lc_bike_ct *l_ct, m_t *tmp)
{
	unsigned int i;

	function_l(tmp, e);

	// m' = c1 ^ L(e')
	for (i = 0; i < sizeof(*m); i++)
		m->raw[i] = tmp->raw[i] ^ l_ct->c1.raw[i];
}


/**
 * @brief kyber_ss_kdf - KDF to derive arbitrary sized SS from BIKE SS
 *
 *	SS <- KMAC256(K = BIKE-SS, X = BIKE-CT, L = requested SS length,
 *		      S = "BIKE KEM SS")
 *
 * This KDF is is consistent with SP800-108 rev 1.
 */
static inline void bike_ss_kdf(uint8_t *ss, size_t ss_len,
			       const struct lc_bike_ct *ct,
			       const uint8_t bike_ss[LC_BIKE_SS_BYTES])
{
	static const uint8_t kyber_ss_label[] = "BIKE KEM SS";

	lc_kmac(lc_cshake256, bike_ss, LC_BIKE_SS_BYTES, kyber_ss_label,
		sizeof(kyber_ss_label) - 1, (uint8_t *)ct,
		sizeof(struct lc_bike_ct), ss, ss_len);
}


////////////////////////////////////////////////////////////////////////////////
// The three APIs below (keypair, encapsulate, decapsulate) are defined by NIST:
////////////////////////////////////////////////////////////////////////////////
LC_INTERFACE_FUNCTION(int, lc_bike_keypair, struct lc_bike_pk *pk,
		      struct lc_bike_sk *sk, struct lc_rng_ctx *rng_ctx)
{
#if (defined(LC_BIG_ENDIAN) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
	(void)pk;
	(void)sk;
	(void)rng_ctx;
	return -EOPNOTSUPP;
#else
	struct workspace {
		// The secret key is (h0, h1),
		// and the public key h=(h0^-1 * h1).
		// Padded structures are used internally, and are required by
		// the decoder and the gf2x multiplication.
		pad_r_t h0, h1, h0inv, h;
		dbl_pad_r_t t;
		uint64_t secure_buffer[LC_SECURE_BUFFER_QWORDS];

		// The randomness of the key generation
		seeds_t seeds;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, LC_BIKE_ALIGN_BYTES);

	lc_rng_check(&rng_ctx);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, (uint8_t *)&ws->seeds.seed,
			      sizeof(ws->seeds.seed)));

	CKINT(generate_secret_key(&ws->h0, &ws->h1, sk->wlist[0].val,
				  sk->wlist[1].val, &ws->seeds.seed[0]));

	// Generate sigma
	convert_seed_to_m_type(&sk->sigma, &ws->seeds.seed[1]);

	// Calculate the public key
	CKINT(gf2x_mod_inv(&ws->h0inv, &ws->h0));
	gf2x_mod_mul(&ws->h, &ws->h1, &ws->h0inv, &ws->t, ws->secure_buffer);

	// Fill the secret key data structure with contents - cancel the padding
	sk->bin[0] = ws->h0.val;
	sk->bin[1] = ws->h1.val;
	sk->pk = ws->h.val;

	// Copy the data to the output buffers
	memcpy(pk, &sk->pk, sizeof(sk->pk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_bike_keypair_from_seed, struct lc_bike_pk *pk,
		      struct lc_bike_sk *sk, const uint8_t *seed,
		      size_t seedlen)
{
	struct lc_static_rng_data static_data = {
		.seed = seed,
		.seedlen = seedlen,
        };
	LC_STATIC_DRNG_ON_STACK(sdrng, &static_data);

	return lc_bike_keypair(pk, sk, &sdrng);
}

LC_INTERFACE_FUNCTION(int, lc_bike_enc_internal, struct lc_bike_ct *ct,
		      struct lc_bike_ss *ss, const struct lc_bike_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
#if (defined(LC_BIG_ENDIAN) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
	(void)ct;
	(void)ss;
	(void)pk;
	(void)rng_ctx;
	return -EOPNOTSUPP;
#else
	struct workspace {
		pad_e_t e;
		// Pad the public key and the ciphertext
		pad_r_t p_ct;
		pad_r_t p_pk;
		dbl_pad_r_t t;
		uint64_t secure_buffer[LC_SECURE_BUFFER_QWORDS];
		m_t m;
		seeds_t seeds;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, LC_BIKE_ALIGN_BYTES);

	lc_rng_check(&rng_ctx);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, (uint8_t *)&ws->seeds.seed,
			      sizeof(ws->seeds.seed)));

	// e = H(m) = H(seed[0])
	convert_seed_to_m_type(&ws->m, &ws->seeds.seed[0]);
	CKINT(function_h(&ws->e, &ws->m, &pk->pk));

	// Calculate the ciphertext
	bike_encrypt(ct, &ws->e, &pk->pk, &ws->m, &ws->p_ct, &ws->p_pk, &ws->t,
		     ws->secure_buffer);

	// Generate the shared secret
	function_k(ss, &ws->m, ct);

	//print("ss: ", (uint64_t *)l_ss.raw, SIZEOF_BITS(l_ss));

out:
	LC_RELEASE_MEM(ws);
	return ret;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_bike_enc, struct lc_bike_ct *ct,
		      struct lc_bike_ss *ss, const struct lc_bike_pk *pk)
{
	return lc_bike_enc_internal(ct, ss, pk, lc_seeded_rng);
}

LC_INTERFACE_FUNCTION(int, lc_bike_enc_kdf, struct lc_bike_ct *ct, uint8_t *ss,
		      size_t ss_len, const struct lc_bike_pk *pk)
{
	struct lc_bike_ss bike_ss;
	int ret;

	CKINT(lc_bike_enc(ct, &bike_ss, pk));

	bike_ss_kdf(ss, ss_len, ct, bike_ss.ss);

out:
	lc_memset_secure(&bike_ss, 0, sizeof(bike_ss));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_bike_dec, struct lc_bike_ss *ss,
		      const struct lc_bike_ct *ct, const struct lc_bike_sk *sk)
{
#if (defined(LC_BIG_ENDIAN) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__))
	(void)ss;
	(void)ct;
	(void)sk;
	return -EOPNOTSUPP;
#else
	struct workspace {
		pad_e_t e_tmp, e_prime;
		m_t tmp;
		e_t e;
		m_t m_prime;
	};
	uint32_t mask;
	unsigned int i;
	int success_cond, ret;
	LC_DECLARE_MEM(ws, struct workspace, LC_BIKE_ALIGN_BYTES);

	// Decode
	CKINT(bike_decode(&ws->e, ct, sk));

	// Copy the error vector in the padded struct.
	ws->e_prime.val[0].val = ws->e.val[0];
	ws->e_prime.val[1].val = ws->e.val[1];

	reencrypt(&ws->m_prime, &ws->e_prime, ct, &ws->tmp);

	// Check if H(m') is equal to (e0', e1')
	// (in constant-time)
	function_h(&ws->e_tmp, &ws->m_prime, &sk->pk);

	success_cond = !lc_memcmp_secure(PE0_RAW(&ws->e_prime), LC_BIKE_R_BYTES,
					 PE0_RAW(&ws->e_tmp), LC_BIKE_R_BYTES);
	success_cond &=
		!lc_memcmp_secure(PE1_RAW(&ws->e_prime), LC_BIKE_R_BYTES,
				  PE1_RAW(&ws->e_tmp), LC_BIKE_R_BYTES);

	// Compute either K(m', C) or K(sigma, C) based on the success condition
	mask = secure_l32_mask(0, (uint32_t)success_cond);
	for (i = 0; i < LC_BIKE_M_BYTES; i++) {
		ws->m_prime.raw[i] &= u8_barrier((uint8_t)(~mask));
		ws->m_prime.raw[i] |=
			(u8_barrier((uint8_t)mask) & sk->sigma.raw[i]);
	}

	// Generate the shared secret
	function_k(ss, &ws->m_prime, ct);

out:
	LC_RELEASE_MEM(ws);
	return ret;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_bike_dec_kdf, uint8_t *ss, size_t ss_len,
		      const struct lc_bike_ct *ct, const struct lc_bike_sk *sk)
{
	struct lc_bike_ss bike_ss;
	int ret;

	CKINT(lc_bike_dec(&bike_ss, ct, sk));

	bike_ss_kdf(ss, ss_len, ct, bike_ss.ss);

out:
	lc_memset_secure(&bike_ss, 0, sizeof(bike_ss));
	return ret;
}
