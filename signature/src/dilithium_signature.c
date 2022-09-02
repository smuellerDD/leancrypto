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

#include "dilithium_polyvec.h"
#include "dilithium_pack.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sha3.h"
#include "memset_secure.h"
#include "ret_checkers.h"
#include "visibility.h"

DSO_PUBLIC
int lc_dilithium_keypair(struct lc_dilithium_pk *pk,
			 struct lc_dilithium_sk *sk,
			 struct lc_rng_ctx *rng_ctx)
{
	polyvecl mat[LC_DILITHIUM_K];
	polyvecl s1, s1hat;
	polyveck s2, t1, t0;
	uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_CRHBYTES];
	uint8_t tr[LC_DILITHIUM_SEEDBYTES];
	const uint8_t *rho, *rhoprime, *key;
	int ret;

	if (!pk || !sk || !rng_ctx)
		return -EINVAL;

	/* Get randomness for rho, rhoprime and key */
	CKINT(lc_rng_generate(rng_ctx, NULL, 0,
			      seedbuf, LC_DILITHIUM_SEEDBYTES));
	lc_shake(lc_shake256, seedbuf, LC_DILITHIUM_SEEDBYTES,
		 seedbuf, sizeof(seedbuf));

	rho = seedbuf;
	rhoprime = rho + LC_DILITHIUM_SEEDBYTES;
	key = rhoprime + LC_DILITHIUM_CRHBYTES;

	/* Expand matrix */
	polyvec_matrix_expand(mat, rho);

	/* Sample short vectors s1 and s2 */
	polyvecl_uniform_eta(&s1, rhoprime, 0);
	polyveck_uniform_eta(&s2, rhoprime, LC_DILITHIUM_L);

	/* Matrix-vector multiplication */
	s1hat = s1;
	polyvecl_ntt(&s1hat);

	polyvec_matrix_pointwise_montgomery(&t1, mat, &s1hat);
	polyveck_reduce(&t1);
	polyveck_invntt_tomont(&t1);

	/* Add error vector s2 */
	polyveck_add(&t1, &t1, &s2);

	/* Extract t1 and write public key */
	polyveck_caddq(&t1);
	polyveck_power2round(&t1, &t0, &t1);
	pack_pk(pk, rho, &t1);

	/* Compute H(rho, t1) and write secret key */
	lc_shake(lc_shake256, pk->pk, sizeof(pk->pk), tr, sizeof(tr));
	pack_sk(sk, rho, tr, key, &t0, &s1, &s2);

out:
	memset_secure(mat, 0, sizeof(mat));
	memset_secure(&s1, 0, sizeof(s1));
	memset_secure(&s1hat, 0, sizeof(s1hat));
	memset_secure(&s2, 0, sizeof(s2));
	memset_secure(&t1, 0, sizeof(t1));
	memset_secure(seedbuf, 0, sizeof(seedbuf));
	memset_secure(tr, 0, sizeof(tr));
	return ret;
}

DSO_PUBLIC
int lc_dilithium_sign(struct lc_dilithium_sig *sig,
		      const uint8_t *m,
		      size_t mlen,
		      const struct lc_dilithium_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);
	polyvecl mat[LC_DILITHIUM_K], s1, y, z;
	polyveck t0, s2, w1, w0, h;
	poly cp;
	unsigned int n;
	uint8_t seedbuf[3 * LC_DILITHIUM_SEEDBYTES + 2 * LC_DILITHIUM_CRHBYTES];
	uint8_t *rho, *tr, *key, *mu, *rhoprime;
	uint16_t nonce = 0;
	int ret = 0;

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !m || !sk)
		return -EINVAL;

	rho = seedbuf;
	tr = rho + LC_DILITHIUM_SEEDBYTES;
	key = tr + LC_DILITHIUM_SEEDBYTES;
	mu = key + LC_DILITHIUM_SEEDBYTES;
	rhoprime = mu + LC_DILITHIUM_CRHBYTES;
	unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

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
	polyvec_matrix_expand(mat, rho);
	polyvecl_ntt(&s1);
	polyveck_ntt(&s2);
	polyveck_ntt(&t0);

rej:
	/* Sample intermediate vector y */
	polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

	/* Matrix-vector multiplication */
	z = y;
	polyvecl_ntt(&z);
	polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
	polyveck_reduce(&w1);
	polyveck_invntt_tomont(&w1);

	/* Decompose w and call the random oracle */
	polyveck_caddq(&w1);
	polyveck_decompose(&w1, &w0, &w1);
	polyveck_pack_w1(sig->sig, &w1);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, sig->sig,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_SEEDBYTES);
	lc_hash_final(hash_ctx, sig->sig);

	poly_challenge(&cp, sig->sig);
	poly_ntt(&cp);

	/* Compute z, reject if it reveals secret */
	polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
	polyvecl_invntt_tomont(&z);
	polyvecl_add(&z, &z, &y);
	polyvecl_reduce(&z);
	if (polyvecl_chknorm(&z, LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA))
		goto rej;

	/* Check that subtracting cs2 does not change high bits of w and low bits
	 * do not reveal secret information */
	polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
	polyveck_invntt_tomont(&h);
	polyveck_sub(&w0, &w0, &h);
	polyveck_reduce(&w0);
	if (polyveck_chknorm(&w0, LC_DILITHIUM_GAMMA2 - LC_DILITHIUM_BETA))
		goto rej;

	/* Compute hints for w1 */
	polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
	polyveck_invntt_tomont(&h);
	polyveck_reduce(&h);
	if (polyveck_chknorm(&h, LC_DILITHIUM_GAMMA2))
		goto rej;

	polyveck_add(&w0, &w0, &h);
	n = polyveck_make_hint(&h, &w0, &w1);
	if (n > LC_DILITHIUM_OMEGA)
		goto rej;

	/* Write signature */
	pack_sig(sig, sig->sig, &z, &h);

out:
	lc_hash_zero(hash_ctx);
	memset_secure(mat, 0, sizeof(mat));
	memset_secure(&s1, 0, sizeof(s1));
	memset_secure(&y, 0, sizeof(y));
	memset_secure(&z, 0, sizeof(z));
	memset_secure(&t0, 0, sizeof(t0));
	memset_secure(&s2, 0, sizeof(s2));
	memset_secure(&w1, 0, sizeof(w1));
	memset_secure(&w0, 0, sizeof(w0));
	memset_secure(&h, 0, sizeof(h));
	memset_secure(&cp, 0, sizeof(cp));
	memset_secure(seedbuf, 0, sizeof(seedbuf));
	return ret;
}

DSO_PUBLIC
int lc_dilithium_verify(const struct lc_dilithium_sig *sig,
			const uint8_t *m,
			size_t mlen,
			const struct lc_dilithium_pk *pk)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);
	poly cp;
	polyvecl mat[LC_DILITHIUM_K], z;
	polyveck t1, w1, h;
	unsigned int i;
	uint8_t buf[LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES];
	uint8_t rho[LC_DILITHIUM_SEEDBYTES];
	uint8_t mu[LC_DILITHIUM_CRHBYTES];
	uint8_t c[LC_DILITHIUM_SEEDBYTES];
	uint8_t c2[LC_DILITHIUM_SEEDBYTES];

	if (!sig || !m || !pk)
		return -EINVAL;

	unpack_pk(rho, &t1, pk);
	if (unpack_sig(c, &z, &h, sig))
		return -EINVAL;
	if (polyvecl_chknorm(&z, LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA))
		return -EINVAL;

	/* Compute CRH(H(rho, t1), msg) */
	lc_shake(lc_shake256,
		 pk->pk, LC_DILITHIUM_PUBLICKEYBYTES,
		 mu, LC_DILITHIUM_SEEDBYTES);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_SEEDBYTES);
	lc_hash_update(hash_ctx, m, mlen);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_CRHBYTES);
	lc_hash_final(hash_ctx, mu);

	/* Matrix-vector multiplication; compute Az - c2^dt1 */
	poly_challenge(&cp, c);
	polyvec_matrix_expand(mat, rho);

	polyvecl_ntt(&z);
	polyvec_matrix_pointwise_montgomery(&w1, mat, &z);

	poly_ntt(&cp);
	polyveck_shiftl(&t1);
	polyveck_ntt(&t1);
	polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

	polyveck_sub(&w1, &w1, &t1);
	polyveck_reduce(&w1);
	polyveck_invntt_tomont(&w1);

	/* Reconstruct w1 */
	polyveck_caddq(&w1);
	polyveck_use_hint(&w1, &w1, &h);
	polyveck_pack_w1(buf, &w1);

	/* Call random oracle and verify challenge */
	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, buf,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_SEEDBYTES);
	lc_hash_final(hash_ctx, c2);

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		if(c[i] != c2[i])
			return -EBADMSG;

	lc_hash_zero(hash_ctx);
	memset_secure(&cp, 0, sizeof(cp));
	memset_secure(mat, 0, sizeof(mat));
	memset_secure(&z, 0, sizeof(z));
	memset_secure(&t1, 0, sizeof(t1));
	memset_secure(&w1, 0, sizeof(w1));
	memset_secure(&h, 0, sizeof(h));
	memset_secure(&buf, 0, sizeof(buf));
	memset_secure(&rho, 0, sizeof(rho));
	memset_secure(&mu, 0, sizeof(mu));
	memset_secure(&c, 0, sizeof(c));
	memset_secure(&c2, 0, sizeof(c2));

	return 0;
}
