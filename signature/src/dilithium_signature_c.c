/*
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
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

#include "alignment.h"
#include "dilithium_polyvec.h"
#include "dilithium_pack.h"
#include "dilithium_signature_c.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sha3.h"
#include "memory_support.h"
#include "ret_checkers.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(
int, lc_dilithium_keypair_c, struct lc_dilithium_pk *pk,
			     struct lc_dilithium_sk *sk,
			     struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		polyvecl mat[LC_DILITHIUM_K];
		polyvecl s1, s1hat;
		polyveck s2, t1, t0;
		poly polyvecl_pointwise_acc_montgomery_buf;
		uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES +
				LC_DILITHIUM_CRHBYTES];
		uint8_t tr[LC_DILITHIUM_SEEDBYTES];
		uint8_t poly_uniform_eta_buf[POLY_UNIFORM_ETA_BYTES];
	};
	const uint8_t *rho, *rhoprime, *key;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (!pk || !sk || !rng_ctx) {
		ret = -EINVAL;
		goto out;
	}

	/* Get randomness for rho, rhoprime and key */
	CKINT(lc_rng_generate(rng_ctx, NULL, 0,
			      ws->seedbuf, LC_DILITHIUM_SEEDBYTES));
	lc_shake(lc_shake256, ws->seedbuf, LC_DILITHIUM_SEEDBYTES,
		 ws->seedbuf, sizeof(ws->seedbuf));

	rho = ws->seedbuf;
	rhoprime = rho + LC_DILITHIUM_SEEDBYTES;
	key = rhoprime + LC_DILITHIUM_CRHBYTES;

	/* Expand matrix */
	polyvec_matrix_expand(ws->mat, rho);

	/* Sample short vectors s1 and s2 */
	polyvecl_uniform_eta(&ws->s1, rhoprime, 0, ws->poly_uniform_eta_buf);
	polyveck_uniform_eta(&ws->s2, rhoprime, LC_DILITHIUM_L,
			     ws->poly_uniform_eta_buf);

	/* Matrix-vector multiplication */
	ws->s1hat = ws->s1;
	polyvecl_ntt(&ws->s1hat);

	polyvec_matrix_pointwise_montgomery(&ws->t1, ws->mat, &ws->s1hat,
		&ws->polyvecl_pointwise_acc_montgomery_buf);
	polyveck_reduce(&ws->t1);
	polyveck_invntt_tomont(&ws->t1);

	/* Add error vector s2 */
	polyveck_add(&ws->t1, &ws->t1, &ws->s2);

	/* Extract t1 and write public key */
	polyveck_caddq(&ws->t1);
	polyveck_power2round(&ws->t1, &ws->t0, &ws->t1);
	pack_pk(pk, rho, &ws->t1);

	/* Compute H(rho, t1) and write secret key */
	lc_shake(lc_shake256, pk->pk, sizeof(pk->pk), ws->tr, sizeof(ws->tr));
	pack_sk(sk, rho, ws->tr, key, &ws->t0, &ws->s1, &ws->s2);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(
int, lc_dilithium_sign_c, struct lc_dilithium_sig *sig,
			  const uint8_t *m,
			  size_t mlen,
			  const struct lc_dilithium_sk *sk,
			  struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		polyvecl mat[LC_DILITHIUM_K], s1, y, z;
		polyveck t0, s2, w1, w0, h;
		poly cp;
		/* See comment below - currently not needed */
		//poly polyvecl_pointwise_acc_montgomery_buf;
		uint8_t poly_uniform_gamma1_buf[POLY_UNIFORM_GAMMA1_BYTES];
		/* See comment below - currently not needed */
		//uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
		uint8_t seedbuf[3 * LC_DILITHIUM_SEEDBYTES +
				2 * LC_DILITHIUM_CRHBYTES];
	};
	unsigned int n;
	uint8_t *rho, *tr, *key, *mu, *rhoprime;
	uint16_t nonce = 0;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !m || !sk) {
		ret = -EINVAL;
		goto out;
	}

	rho = ws->seedbuf;
	tr = rho + LC_DILITHIUM_SEEDBYTES;
	key = tr + LC_DILITHIUM_SEEDBYTES;
	mu = key + LC_DILITHIUM_SEEDBYTES;
	rhoprime = mu + LC_DILITHIUM_CRHBYTES;
	unpack_sk(rho, tr, key, &ws->t0, &ws->s1, &ws->s2, sk);

	/* Compute CRH(tr, msg) */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, tr, LC_DILITHIUM_SEEDBYTES);
	lc_hash_update(hash_ctx, m, mlen);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
	lc_hash_final(hash_ctx, mu);

	if (rng_ctx) {
		CKINT(lc_rng_generate(rng_ctx, NULL, 0, rhoprime,
				      LC_DILITHIUM_CRHBYTES));
	} else {
		lc_shake(lc_shake256,
			 key, LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_CRHBYTES,
			 rhoprime, LC_DILITHIUM_CRHBYTES);
	}

	/* Expand matrix and transform vectors */
	polyvec_matrix_expand(ws->mat, rho);
	polyvecl_ntt(&ws->s1);
	polyveck_ntt(&ws->s2);
	polyveck_ntt(&ws->t0);

rej:
	/* Sample intermediate vector y */
	polyvecl_uniform_gamma1(&ws->y, rhoprime, nonce++,
				ws->poly_uniform_gamma1_buf);

	/* Matrix-vector multiplication */
	ws->z = ws->y;
	polyvecl_ntt(&ws->z);

	/* Use the cp for this operation as it is not used here so far. */
	polyvec_matrix_pointwise_montgomery(&ws->w1, ws->mat, &ws->z, &ws->cp);
	polyveck_reduce(&ws->w1);
	polyveck_invntt_tomont(&ws->w1);

	/* Decompose w and call the random oracle */
	polyveck_caddq(&ws->w1);
	polyveck_decompose(&ws->w1, &ws->w0, &ws->w1);
	polyveck_pack_w1(sig->sig, &ws->w1);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, sig->sig,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_SEEDBYTES);
	lc_hash_final(hash_ctx, sig->sig);

	/*
	 * Use the poly_uniform_gamma1_buf for this operation as
	 * poly_challenge_buf is smaller than buf and has the same alignment
	 */
	BUILD_BUG_ON(POLY_UNIFORM_GAMMA1_BYTES < POLY_CHALLENGE_BYTES);
	poly_challenge(&ws->cp, sig->sig, ws->poly_uniform_gamma1_buf);
	poly_ntt(&ws->cp);

	/* Compute z, reject if it reveals secret */
	polyvecl_pointwise_poly_montgomery(&ws->z, &ws->cp, &ws->s1);
	polyvecl_invntt_tomont(&ws->z);
	polyvecl_add(&ws->z, &ws->z, &ws->y);
	polyvecl_reduce(&ws->z);
	if (polyvecl_chknorm(&ws->z, LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA))
		goto rej;

	/* Check that subtracting cs2 does not change high bits of w and low bits
	 * do not reveal secret information */
	polyveck_pointwise_poly_montgomery(&ws->h, &ws->cp, &ws->s2);
	polyveck_invntt_tomont(&ws->h);
	polyveck_sub(&ws->w0, &ws->w0, &ws->h);
	polyveck_reduce(&ws->w0);
	if (polyveck_chknorm(&ws->w0, LC_DILITHIUM_GAMMA2 - LC_DILITHIUM_BETA))
		goto rej;

	/* Compute hints for w1 */
	polyveck_pointwise_poly_montgomery(&ws->h, &ws->cp, &ws->t0);
	polyveck_invntt_tomont(&ws->h);
	polyveck_reduce(&ws->h);
	if (polyveck_chknorm(&ws->h, LC_DILITHIUM_GAMMA2))
		goto rej;

	polyveck_add(&ws->w0, &ws->w0, &ws->h);
	n = polyveck_make_hint(&ws->h, &ws->w0, &ws->w1);
	if (n > LC_DILITHIUM_OMEGA)
		goto rej;

	/* Write signature */
	pack_sig(sig, sig->sig, &ws->z, &ws->h);

out:
	lc_hash_zero(hash_ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(
int, lc_dilithium_verify_c, const struct lc_dilithium_sig *sig,
			    const uint8_t *m,
			    size_t mlen,
			    const struct lc_dilithium_pk *pk)
{
	struct workspace {
		poly cp;
		poly polyvecl_pointwise_acc_montgomery_buf;
		polyvecl mat[LC_DILITHIUM_K], z;
		polyveck t1, w1, h;
		uint8_t buf[LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES];
		/* See comment below - currently not needed */
		//uint8_t poly_challenge_buf[POLY_CHALLENGE_BYTES];
		uint8_t rho[LC_DILITHIUM_SEEDBYTES];
		uint8_t mu[LC_DILITHIUM_CRHBYTES];
		BUF_ALIGNED_UINT8_UINT64(LC_DILITHIUM_SEEDBYTES) c;
		BUF_ALIGNED_UINT8_UINT64(LC_DILITHIUM_SEEDBYTES) c2;
	};
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	if (!sig || !m || !pk) {
		ret = -EINVAL;
		goto out;
	}

	unpack_pk(ws->rho, &ws->t1, pk);
	if (unpack_sig(ws->c.coeffs, &ws->z, &ws->h, sig))
		return -EINVAL;
	if (polyvecl_chknorm(&ws->z, LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA))
		return -EINVAL;

	/* Compute CRH(H(rho, t1), msg) */
	lc_shake(lc_shake256,
		 pk->pk, LC_DILITHIUM_PUBLICKEYBYTES,
		 ws->mu, LC_DILITHIUM_SEEDBYTES);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, ws->mu, LC_DILITHIUM_SEEDBYTES);
	lc_hash_update(hash_ctx, m, mlen);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
	lc_hash_final(hash_ctx, ws->mu);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */

	/*
	 * Use the buf for this operation as poly_challenge_buf is smaller than
	 * buf and has the same alignment
	 */
	BUILD_BUG_ON(sizeof(ws->buf) < POLY_CHALLENGE_BYTES);
	poly_challenge(&ws->cp, ws->c.coeffs, ws->buf);
	polyvec_matrix_expand(ws->mat, ws->rho);

	polyvecl_ntt(&ws->z);
	polyvec_matrix_pointwise_montgomery(&ws->w1, ws->mat, &ws->z,
		&ws->polyvecl_pointwise_acc_montgomery_buf);

	poly_ntt(&ws->cp);
	polyveck_shiftl(&ws->t1);
	polyveck_ntt(&ws->t1);
	polyveck_pointwise_poly_montgomery(&ws->t1, &ws->cp, &ws->t1);

	polyveck_sub(&ws->w1, &ws->w1, &ws->t1);
	polyveck_reduce(&ws->w1);
	polyveck_invntt_tomont(&ws->w1);

	/* Reconstruct w1 */
	polyveck_caddq(&ws->w1);
	polyveck_use_hint(&ws->w1, &ws->w1, &ws->h);
	polyveck_pack_w1(ws->buf, &ws->w1);

	/* Call random oracle and verify challenge */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, ws->mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, ws->buf,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_SEEDBYTES);
	lc_hash_final(hash_ctx, ws->c2.coeffs);

	/* Signature verification operation */
	if (memcmp_secure(ws->c.coeffs, LC_DILITHIUM_SEEDBYTES,
			  ws->c2.coeffs, LC_DILITHIUM_SEEDBYTES))
		ret = -EBADMSG;

out:
	lc_hash_zero(hash_ctx);
	LC_RELEASE_MEM(ws);
	return ret;
}
