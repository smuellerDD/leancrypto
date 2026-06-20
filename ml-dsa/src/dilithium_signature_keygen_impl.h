/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#ifndef DILITHIUM_SIGNATURE_KEYGEN_IMPL_H
#define DILITHIUM_SIGNATURE_KEYGEN_IMPL_H

#include "alignment.h"
#include "build_bug_on.h"
#include "dilithium_type.h"
#include "dilithium_internal.h"
#include "dilithium_pack.h"
#include "dilithium_pct.h"
#include "lc_hash.h"
#include "lc_memcmp_secure.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "signature_domain_separation.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "timecop.h"
#include "visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

#define _WS_POLY_UNIFORM_BUF_SIZE                                              \
	(POLY_UNIFORM_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 8)

#ifndef LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER
#error "LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER is not defined"
#endif

#define WS_POLY_UNIFORM_BUF_SIZE                                               \
	(_WS_POLY_UNIFORM_BUF_SIZE * LC_POLY_UNIFOR_BUF_SIZE_MULTIPLIER)

struct keygen_workspace {
	union {
		poly polyvecl_pointwise_acc_montgomery_buf;
		uint8_t poly_uniform_buf[WS_POLY_UNIFORM_BUF_SIZE];
		uint8_t poly_uniform_eta_buf[POLY_UNIFORM_ETA_BYTES];
	} tmp __align(sizeof(uint64_t));
	union {
		polyvecl s1, s1hat;
	} s1;
	union {
		polyvecl mat[LC_DILITHIUM_K];
		polyveck t0;
	} matrix;
	polyveck s2, t1;
	uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_CRHBYTES];
};

static void lc_dilithium_pk_sk_from_rho_s1_s2(uint8_t *pubkey, uint8_t *seckey,
					      const uint8_t *rho,
					      struct keygen_workspace *ws)
{
	polyveck *t1, *s2, *t0;
	polyvecl *s1;
	unsigned int i;

	polyvecl_ntt(&ws->s1.s1hat);

	/* Expand matrix */
	polyvec_matrix_expand(ws->matrix.mat, rho, ws->tmp.poly_uniform_buf);

	s1 = &ws->s1.s1hat;
	s2 = &ws->s2;
	t1 = &ws->t1;
	t0 = &ws->matrix.t0;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		polyvecl_pointwise_acc_montgomery(
			&t1->vec[i], &ws->matrix.mat[i], s1,
			&ws->tmp.polyvecl_pointwise_acc_montgomery_buf);

		poly_reduce(&t1->vec[i]);
		poly_invntt_tomont(&t1->vec[i]);

		/* Add error vector s2 */
		poly_add(&t1->vec[i], &t1->vec[i], &s2->vec[i]);

		/*
		* Reference: The following reduction is not present in the
		* reference implementation. Omitting this reduction requires the
		* output of the invntt to be small enough such that the addition
		* of s2 does not result in absolute values >= LC_DILITHIUM_Q.
		* While the C, x86_64, and AArch64 invntt implementations
		* produce small enough values for this to work out, it
		* complicates the bounds reasoning. Therefore, add an additional
		* reduction, allowing to relax the bounds requirements for the
		* invntt, especially when adding new invntt assembler
		* implementations.
		*/
#ifndef LC_DILITHIUM_INVNTT_SMALL
		poly_reduce(&t1->vec[i]);
#endif

		/* Extract t1 and write public key */
		poly_caddq(&t1->vec[i]);
		poly_power2round(&t1->vec[i], &t0->vec[i], &t1->vec[i]);

		polyt1_pack(pubkey + i * LC_DILITHIUM_POLYT1_PACKEDBYTES,
			    &t1->vec[i]);
		if (seckey) {
			polyt0_pack(seckey +
					    i * LC_DILITHIUM_POLYT0_PACKEDBYTES,
				    &t0->vec[i]);
		}
	}
}

static int lc_dilithium_pk_from_sk_impl(struct lc_dilithium_pk *pk,
					const struct lc_dilithium_sk *sk)
{
	uint8_t *rho, *pubkey;
	int ret;
	LC_DECLARE_MEM(ws, struct keygen_workspace, sizeof(uint64_t));

	CKNULL(pk, -EINVAL);
	CKNULL(sk, -EINVAL);

	/* Timecop: sk is secret */
	poison(sk->sk, sizeof(sk->sk));

	/* Unpack RHO directly into public key */
	rho = pk->pk;
	unpack_sk_rho(rho, sk);
	unpoison(rho, LC_DILITHIUM_SEEDBYTES);

	unpack_sk_s1(&ws->s1.s1, sk);
	unpack_sk_s2(&ws->s2, sk);

	/* Timecop: s1 and s2 are secret */
	poison(&ws->s1.s1, sizeof(polyvecl));
	poison(&ws->s2, sizeof(polyveck));

	pubkey = pk->pk + LC_DILITHIUM_SEEDBYTES;
	lc_dilithium_pk_sk_from_rho_s1_s2(pubkey, NULL, rho, ws);

	unpoison(pk->pk, sizeof(pk->pk));
	unpoison(sk->sk, sizeof(sk->sk));

	CKINT(lc_dilithium_pct_fips(pk, sk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_keypair_impl(struct lc_dilithium_pk *pk,
				     struct lc_dilithium_sk *sk,
				     struct lc_rng_ctx *rng_ctx)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t dimension[2] = { LC_DILITHIUM_K, LC_DILITHIUM_L };
	const uint8_t *rho, *rhoprime, *key;
	uint8_t *seckey, *pubkey, *tr;
	int ret;
	LC_HASH_CTX_ON_STACK(shake256_ctx, lc_shake256);
	LC_DECLARE_MEM(ws, struct keygen_workspace, sizeof(uint64_t));

	CKNULL(pk, -EINVAL);
	CKNULL(sk, -EINVAL);

	lc_rng_check(&rng_ctx);

	/* Get randomness for rho, rhoprime and key */
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->seedbuf,
			      LC_DILITHIUM_SEEDBYTES));

	CKINT(lc_hash_init(shake256_ctx));
	lc_hash_update(shake256_ctx, ws->seedbuf, LC_DILITHIUM_SEEDBYTES);
	lc_hash_update(shake256_ctx, dimension, sizeof(dimension));
	CKINT(lc_hash_set_digestsize(shake256_ctx, sizeof(ws->seedbuf)));
	lc_hash_final(shake256_ctx, ws->seedbuf);
	lc_hash_zero(shake256_ctx);

	rho = ws->seedbuf;
	pack_pk_rho(pk, rho);
	pack_sk_rho(sk, rho);

	/*
	 * Timecop: RHO' is a random number which is enlarged to sample the
	 * vectors S1 and S2 from. The sampling operation is not considered
	 * relevant for the side channel operation as (a) an attacker does not
	 * have access to the random number and (b) only the result after the
	 * sampling operation of S1 and S2 is released.
	 */
	rhoprime = rho + LC_DILITHIUM_SEEDBYTES;

	key = rhoprime + LC_DILITHIUM_CRHBYTES;

	/* Timecop: key goes into the secret key */
	poison(key, LC_DILITHIUM_SEEDBYTES);

	pack_sk_key(sk, key);

	/*
	 * Sample short vectors s1 and s2
	 *
	 * Do not implement the loop around L and K here, because ARMv8 has an
	 * accelerated implementation of this.
	 */
	polyvecl_uniform_eta(&ws->s1.s1, rhoprime, 0,
			     ws->tmp.poly_uniform_eta_buf);
	polyveck_uniform_eta(&ws->s2, rhoprime, LC_DILITHIUM_L,
			     ws->tmp.poly_uniform_eta_buf);

	/* Timecop: s1 and s2 are secret */
	poison(&ws->s1.s1, sizeof(polyvecl));
	poison(&ws->s2, sizeof(polyveck));

	pack_sk_s1(sk, &ws->s1.s1);
	pack_sk_s2(sk, &ws->s2);

	pubkey = pk->pk + LC_DILITHIUM_SEEDBYTES;
	seckey = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES +
		 LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES +
		 LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;
	lc_dilithium_pk_sk_from_rho_s1_s2(pubkey, seckey, rho, ws);

	/* Compute H(rho, t1) and write secret key */
	tr = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES;
	CKINT(lc_xof(lc_shake256, pk->pk, sizeof(pk->pk), tr,
		     LC_DILITHIUM_TRBYTES));

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(pk->pk, sizeof(pk->pk));
	unpoison(sk->sk, sizeof(sk->sk));

	CKINT(lc_dilithium_pct_fips(pk, sk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int lc_dilithium_keypair_from_seed_impl(struct lc_dilithium_pk *pk,
					       struct lc_dilithium_sk *sk,
					       const uint8_t *seed,
					       size_t seedlen)
{
	struct lc_static_rng_data s_rng_state;
	LC_STATIC_DRNG_ON_STACK(s_drng, &s_rng_state);
	int ret;

	if (seedlen != LC_DILITHIUM_SEEDBYTES)
		return -EINVAL;

	/* Set the seed that the key generation can pull via the RNG. */
	s_rng_state.seed = seed;
	s_rng_state.seedlen = seedlen;

	/* Generate the key pair from the seed. */
	CKINT(lc_dilithium_keypair_impl(pk, sk, &s_drng));

out:
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* DILITHIUM_SIGNATURE_KEYGEN_IMPL_H */
