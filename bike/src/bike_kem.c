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
#include "bike_sampling.h"
#include "bike_utilities.h"

#include "build_bug_on.h"
#include "lc_bike.h"
#include "lc_memset_secure.h"
#include "lc_memcmp_secure.h"
#include "lc_rng.h"
#include "lc_sha3.h"

#include "ret_checkers.h"
#include "visibility.h"

// m_t and seed_t have the same size and thus can be considered
// to be of the same type. However, for security reasons we distinguish
// these types, even on the costs of small extra complexity.
static inline void convert_seed_to_m_type(m_t *m, const seed_t *seed)
{
  BUILD_BUG_ON(sizeof(*m) != sizeof(*seed));
  memcpy(m->raw, seed->raw, sizeof(*m));
}

#if defined(BIND_PK_AND_M)

static inline void convert_dgst_to_seed_type(seed_t *seed, const sha_dgst_t *in)
{
  memcpy(seed->raw, in->u.raw, sizeof(*seed));
}

#else

static inline void convert_m_to_seed_type(seed_t *seed, const m_t *m)
{
  BUILD_BUG_ON(sizeof(*m) != sizeof(*seed));
  memcpy(seed->raw, m->raw, sizeof(*seed));
}

#endif

// (e0, e1) = H(m)
static inline void function_h(pad_e_t *e, const m_t *m, const pk_t *pk)
{
  seed_t seed = {0};

#if defined(BIND_PK_AND_M)
  LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha384);

  lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, pk->raw, sizeof(pk->raw));
	lc_hash_update(hash_ctx, m->raw, sizeof(m->raw));
	lc_hash_final(hash_ctx, seed.u.raw);
	lc_hash_zero(hash_ctx);
#else
  // pk is unused parameter in this case so we do this to avoid
  // clang sanitizers complaining.
  (void)pk;

  convert_m_to_seed_type(&seed, m);
#endif

  generate_error_vector(e, &seed);

	lc_memset_secure(&seed, 0, sizeof(seed));

#if defined(BIND_PK_AND_M)
	lc_memset_secure(&dgst, 0, sizeof(dgst));
	lc_memset_secure(&pk_m, 0, sizeof(pk_m));
#endif
}

// out = L(e)
static inline void function_l(m_t *out, const pad_e_t *e)
{
  uint8_t dgst[LC_SHA3_384_SIZE_DIGEST];

  LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha3_384);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, (const uint8_t *)&e->val[0].val, sizeof(e->val[0].val));
	lc_hash_update(hash_ctx, (const uint8_t *)&e->val[1].val, sizeof(e->val[1].val));
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

static inline void encrypt(struct lc_bike_ct *ct, const pad_e_t *e,
			   const pk_t *pk, const m_t *m)
{
  // Pad the public key and the ciphertext
  pad_r_t p_ct = {0};
  pad_r_t p_pk = {0};
  unsigned int i;

  p_pk.val     = *pk;

  // Generate the ciphertext
  // ct = pk * e1 + e0
  gf2x_mod_mul(&p_ct, &e->val[1], &p_pk);
  gf2x_mod_add(&p_ct, &p_ct, &e->val[0]);

  ct->c0 = p_ct.val;

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
			     const struct lc_bike_ct *l_ct)
{
  m_t tmp;
  unsigned int i;

  function_l(&tmp, e);

  // m' = c1 ^ L(e')
  for (i = 0; i < sizeof(*m); i++)
    m->raw[i] = tmp.raw[i] ^ l_ct->c1.raw[i];

  lc_memset_secure(&tmp, 0, sizeof(tmp));
}

////////////////////////////////////////////////////////////////////////////////
// The three APIs below (keypair, encapsulate, decapsulate) are defined by NIST:
////////////////////////////////////////////////////////////////////////////////
LC_INTERFACE_FUNCTION(int, lc_bike_keypair, struct lc_bike_pk *pk,
		      struct lc_bike_sk *sk, struct lc_rng_ctx *rng_ctx)
{
  // The secret key is (h0, h1),
  // and the public key h=(h0^-1 * h1).
  // Padded structures are used internally, and are required by the
  // decoder and the gf2x multiplication.
  pad_r_t h0 = {0};
  pad_r_t h1 = {0};
  pad_r_t h0inv = {0};
  pad_r_t h = {0};

  // The randomness of the key generation
  seeds_t seeds = {0};

  lc_rng_check(&rng_ctx);

  lc_rng_generate(rng_ctx, NULL, 0, (uint8_t *)&seeds.seed,
		  sizeof(seeds.seed));
  generate_secret_key(&h0, &h1,
                            sk->wlist[0].val, sk->wlist[1].val,
                            &seeds.seed[0]);

  // Generate sigma
  convert_seed_to_m_type(&sk->sigma, &seeds.seed[1]);

  // Calculate the public key
  gf2x_mod_inv(&h0inv, &h0);
  gf2x_mod_mul(&h, &h1, &h0inv);

  // Fill the secret key data structure with contents - cancel the padding
  sk->bin[0] = h0.val;
  sk->bin[1] = h1.val;
  sk->pk     = h.val;

  // Copy the data to the output buffers
  memcpy(pk, &sk->pk, sizeof(sk->pk));

  return 0;
}

// Encapsulate - pk is the public key,
//               ct is a key encapsulation message (ciphertext),
//               ss is the shared secret.
LC_INTERFACE_FUNCTION(int, lc_bike_enc, struct lc_bike_ct *ct,
		      struct lc_bike_ss *ss, const struct lc_bike_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
  m_t m;
  seeds_t seeds = {0};
  pad_e_t e;

  lc_rng_check(&rng_ctx);

  lc_rng_generate(rng_ctx, NULL, 0, (uint8_t *)&seeds.seed, sizeof(seeds.seed));

  // e = H(m) = H(seed[0])
  convert_seed_to_m_type(&m, &seeds.seed[0]);
  function_h(&e, &m, &pk->pk);

  // Calculate the ciphertext
  encrypt(ct, &e, &pk->pk, &m);

  // Generate the shared secret
  function_k(ss, &m, ct);

  //print("ss: ", (uint64_t *)l_ss.raw, SIZEOF_BITS(l_ss));

	lc_memset_secure(&m, 0, sizeof(m));
	lc_memset_secure(&seeds, 0, sizeof(seeds));
	lc_memset_secure(&e, 0, sizeof(e));
  return 0;
}

// Decapsulate - ct is a key encapsulation message (ciphertext),
//               sk is the private key,
//               ss is the shared secret
LC_INTERFACE_FUNCTION(int, lc_bike_dec, struct lc_bike_ss *ss,
		      const struct lc_bike_ct *ct, const struct lc_bike_sk *sk)
{
  e_t e;
  m_t m_prime;
  pad_e_t e_tmp;
  pad_e_t e_prime = {0};
  uint32_t mask;
  unsigned int i;
  int success_cond;

  // Decode
  decode(&e, ct, sk);

  // Copy the error vector in the padded struct.
  e_prime.val[0].val = e.val[0];
  e_prime.val[1].val = e.val[1];

  reencrypt(&m_prime, &e_prime, ct);


  // Check if H(m') is equal to (e0', e1')
  // (in constant-time)
  function_h(&e_tmp, &m_prime, &sk->pk);

  success_cond = !lc_memcmp_secure(PE0_RAW(&e_prime), LC_BIKE_R_BYTES,
				  PE0_RAW(&e_tmp), LC_BIKE_R_BYTES);
  success_cond &= !lc_memcmp_secure(PE1_RAW(&e_prime), LC_BIKE_R_BYTES,
				   PE1_RAW(&e_tmp), LC_BIKE_R_BYTES);

  // Compute either K(m', C) or K(sigma, C) based on the success condition
  mask = secure_l32_mask(0, (uint32_t)success_cond);
  for (i = 0; i < LC_BIKE_M_BYTES; i++) {
    m_prime.raw[i] &= u8_barrier((uint8_t)(~mask));
    m_prime.raw[i] |= (u8_barrier((uint8_t)mask) &sk->sigma.raw[i]);
  }

  // Generate the shared secret
  function_k(ss, &m_prime, ct);

	lc_memset_secure(&e, 0, sizeof(e));
	lc_memset_secure(&m_prime, 0, sizeof(m_prime));
	lc_memset_secure(&e_tmp, 0, sizeof(e_tmp));
	lc_memset_secure(&e_prime, 0, sizeof(e_prime));
  return 0;
}
