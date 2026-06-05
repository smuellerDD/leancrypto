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

#include "alignment_x86.h"
#include "build_bug_on.h"
#include "dilithium_type.h"
#include "dilithium_pack_avx2.h"
#include "dilithium_poly_avx2.h"
#include "dilithium_poly_common.h"
#include "dilithium_polyvec_avx2.h"
#include "dilithium_pct.h"
#include "dilithium_signature_keygen_avx2.h"
#include "lc_rng.h"
#include "lc_sha3.h"
#include "lc_memcmp_secure.h"
#include "signature_domain_separation.h"
#include "static_rng.h"
#include "ret_checkers.h"
#include "shake_4x_avx2.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "timecop.h"
#include "visibility.h"

struct keygen_workspace_avx2 {
	union {
		BUF_ALIGNED_UINT8_M256I(REJ_UNIFORM_BUFLEN + 8)
		poly_uniform_4x_buf[4];
		BUF_ALIGNED_UINT8_M256I(REJ_UNIFORM_ETA_BUFLEN)
		poly_uniform_eta_4x_buf[4];
	} tmp;
	uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_CRHBYTES];
	polyvecl rowbuf[2], s1;
	polyveck s2;
	poly t1, t0;
	keccakx4_state keccak_state;
};

static void
lc_dilithium_pk_sk_from_rho_s1_s2_avx2(uint8_t *pubkey, uint8_t *seckey,
				       const uint8_t *rho,
				       struct keygen_workspace_avx2 *ws)
{
	polyvecl *row;
	unsigned int i;

	row = ws->rowbuf;

	/* Transform s1 */
	polyvecl_ntt_avx(&ws->s1);

	for (i = 0; i < LC_DILITHIUM_K; i++) {
		polyvec_matrix_expand_row(&row, ws->rowbuf, rho, i,
					  ws->tmp.poly_uniform_4x_buf,
					  &ws->keccak_state);

		/* Compute inner-product */
		polyvecl_pointwise_acc_montgomery_avx(&ws->t1, row, &ws->s1);

		poly_invntt_tomont_avx(&ws->t1);

		/* Add error polynomial */
		poly_add_avx(&ws->t1, &ws->t1, &ws->s2.vec[i]);

		/* Round t and pack t1, t0 */
		poly_caddq_avx(&ws->t1);
		poly_power2round_avx(&ws->t1, &ws->t0, &ws->t1);

		polyt1_pack_avx(pubkey + i * LC_DILITHIUM_POLYT1_PACKEDBYTES,
				&ws->t1);
		if (seckey) {
			polyt0_pack_avx(
				seckey + i * LC_DILITHIUM_POLYT0_PACKEDBYTES,
				&ws->t0);
		}
	}
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_pk_from_sk_avx2,
		      struct lc_dilithium_pk *pk,
		      const struct lc_dilithium_sk *sk)
{
	uint8_t *rho, *pubkey;
	int ret;
	LC_DECLARE_MEM(ws, struct keygen_workspace_avx2, 32);

	CKNULL(pk, -EINVAL);
	CKNULL(sk, -EINVAL);

	/* Timecop: sk is secret */
	poison(sk, sizeof(*sk));

	/* Unpack RHO directly into public key */
	rho = pk->pk;
	unpack_sk_rho_avx2(rho, sk);
	unpoison(rho, LC_DILITHIUM_SEEDBYTES);

	unpack_sk_s1_avx2(&ws->s1, sk);
	unpack_sk_s2_avx2(&ws->s2, sk);

	pubkey = pk->pk + LC_DILITHIUM_SEEDBYTES;
	lc_dilithium_pk_sk_from_rho_s1_s2_avx2(pubkey, NULL, rho, ws);

	unpoison(pk->pk, sizeof(pk->pk));
	unpoison(sk->sk, sizeof(sk->sk));

	CKINT(lc_dilithium_pct_fips(pk, sk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_avx2,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t dimension[2] = { LC_DILITHIUM_K, LC_DILITHIUM_L };
	unsigned int i;
	const uint8_t *rho, *rhoprime, *key;
	uint8_t *seckey, *pubkey;
	int ret;
	LC_HASH_CTX_ON_STACK(shake256_ctx, lc_shake256);
	LC_DECLARE_MEM(ws, struct keygen_workspace_avx2, 32);

	if (!pk || !sk || !rng_ctx) {
		ret = -EINVAL;
		goto out;
	}

	/* Get randomness for rho, rhoprime and key */
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, ws->seedbuf,
			      LC_DILITHIUM_SEEDBYTES));
	CKINT(lc_hash_init(shake256_ctx));
	lc_hash_update(shake256_ctx, ws->seedbuf, LC_DILITHIUM_SEEDBYTES);
	lc_hash_update(shake256_ctx, dimension, sizeof(dimension));
	lc_hash_set_digestsize(shake256_ctx, sizeof(ws->seedbuf));
	lc_hash_final(shake256_ctx, ws->seedbuf);
	lc_hash_zero(shake256_ctx);

	rho = ws->seedbuf;
	rhoprime = rho + LC_DILITHIUM_SEEDBYTES;
	key = rhoprime + LC_DILITHIUM_CRHBYTES;

	/* Timecop: key goes into the secret key */
	poison(key, LC_DILITHIUM_SEEDBYTES);

	/* Store rho, key */
	memcpy(pk->pk, rho, LC_DILITHIUM_SEEDBYTES);
	memcpy(sk->sk, rho, LC_DILITHIUM_SEEDBYTES);
	memcpy(sk->sk + LC_DILITHIUM_SEEDBYTES, key, LC_DILITHIUM_SEEDBYTES);

#if LC_DILITHIUM_K == 8 && LC_DILITHIUM_L == 7
	poly_uniform_eta_4x_avx(&ws->s1.vec[0], &ws->s1.vec[1], &ws->s1.vec[2],
				&ws->s1.vec[3], rhoprime, 0, 1, 2, 3,
				ws->tmp.poly_uniform_eta_4x_buf,
				&ws->keccak_state);
	poly_uniform_eta_4x_avx(&ws->s1.vec[4], &ws->s1.vec[5], &ws->s1.vec[6],
				&ws->s2.vec[0], rhoprime, 4, 5, 6, 7,
				ws->tmp.poly_uniform_eta_4x_buf,
				&ws->keccak_state);
	poly_uniform_eta_4x_avx(&ws->s2.vec[1], &ws->s2.vec[2], &ws->s2.vec[3],
				&ws->s2.vec[4], rhoprime, 8, 9, 10, 11,
				ws->tmp.poly_uniform_eta_4x_buf,
				&ws->keccak_state);
	poly_uniform_eta_4x_avx(&ws->s2.vec[5], &ws->s2.vec[6], &ws->s2.vec[7],
				&ws->t0, rhoprime, 12, 13, 14, 15,
				ws->tmp.poly_uniform_eta_4x_buf,
				&ws->keccak_state);
#elif LC_DILITHIUM_K == 6 && LC_DILITHIUM_L == 5
	poly_uniform_eta_4x_avx(&ws->s1.vec[0], &ws->s1.vec[1], &ws->s1.vec[2],
				&ws->s1.vec[3], rhoprime, 0, 1, 2, 3,
				ws->tmp.poly_uniform_eta_4x_buf,
				&ws->keccak_state);
	poly_uniform_eta_4x_avx(&ws->s1.vec[4], &ws->s2.vec[0], &ws->s2.vec[1],
				&ws->s2.vec[2], rhoprime, 4, 5, 6, 7,
				ws->tmp.poly_uniform_eta_4x_buf,
				&ws->keccak_state);
	poly_uniform_eta_4x_avx(&ws->s2.vec[3], &ws->s2.vec[4], &ws->s2.vec[5],
				&ws->t0, rhoprime, 8, 9, 10, 11,
				ws->tmp.poly_uniform_eta_4x_buf,
				&ws->keccak_state);
#else
#error "Undefined LC_DILITHIUM_K"
#endif

	/* Timecop: s1 and s2 are secret */
	poison(&ws->s1, sizeof(polyvecl));
	poison(&ws->s2, sizeof(polyveck));

	/* Pack secret vectors */
	for (i = 0; i < LC_DILITHIUM_L; i++)
		polyeta_pack_avx(sk->sk + 2 * LC_DILITHIUM_SEEDBYTES +
					 LC_DILITHIUM_TRBYTES +
					 i * LC_DILITHIUM_POLYETA_PACKEDBYTES,
				 &ws->s1.vec[i]);
	for (i = 0; i < LC_DILITHIUM_K; i++)
		polyeta_pack_avx(sk->sk + 2 * LC_DILITHIUM_SEEDBYTES +
					 LC_DILITHIUM_TRBYTES +
					 (LC_DILITHIUM_L +
					  i) * LC_DILITHIUM_POLYETA_PACKEDBYTES,
				 &ws->s2.vec[i]);

	pubkey = pk->pk + LC_DILITHIUM_SEEDBYTES;
	seckey = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_TRBYTES +
		 (LC_DILITHIUM_L + LC_DILITHIUM_K) *
			 LC_DILITHIUM_POLYETA_PACKEDBYTES;
	lc_dilithium_pk_sk_from_rho_s1_s2_avx2(pubkey, seckey, rho, ws);

	/* Compute H(rho, t1) and store in secret key */
	CKINT(lc_xof(lc_shake256, pk->pk, LC_DILITHIUM_PUBLICKEYBYTES,
		     sk->sk + 2 * LC_DILITHIUM_SEEDBYTES,
		     LC_DILITHIUM_TRBYTES));

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(pk->pk, sizeof(pk->pk));
	unpoison(sk->sk, sizeof(sk->sk));

	CKINT(lc_dilithium_pct_fips(pk, sk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_dilithium_keypair_from_seed_avx2,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk,
		      const uint8_t *seed, size_t seedlen)
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
	CKINT(lc_dilithium_keypair_avx2(pk, sk, &s_drng));

out:
	return ret;
}
