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

#include <stdint.h>
#include <string.h>

#include "dilithium_align_avx2.h"
#include "dilithium_pack_avx2.h"
#include "dilithium_poly_avx2.h"
#include "dilithium_polyvec_avx2.h"
#include "dilithium_signature_avx2.h"
#include "lc_dilithium.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "lc_rng.h"
#include "visibility.h"

static inline void
polyvec_matrix_expand_row(polyvecl **row, polyvecl buf[2],
			  const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
			  unsigned int i)
{
	switch(i) {
		case 0:
			polyvec_matrix_expand_row0(buf, buf + 1, rho);
			*row = buf;
			break;
		case 1:
			polyvec_matrix_expand_row1(buf + 1, buf, rho);
			*row = buf + 1;
			break;
		case 2:
			polyvec_matrix_expand_row2(buf, buf + 1, rho);
			*row = buf;
			break;
		case 3:
			polyvec_matrix_expand_row3(buf + 1, buf, rho);
			*row = buf + 1;
			break;
		case 4:
			polyvec_matrix_expand_row4(buf, buf + 1, rho);
			*row = buf;
			break;
		case 5:
			polyvec_matrix_expand_row5(buf + 1, buf, rho);
			*row = buf + 1;
			break;
		case 6:
			polyvec_matrix_expand_row6(buf, buf + 1, rho);
			*row = buf;
			break;
		case 7:
			polyvec_matrix_expand_row7(buf + 1, buf, rho);
			*row = buf + 1;
			break;
	}
}

LC_INTERFACE_FUNCTION(
int, lc_dilithium_keypair_avx2, struct lc_dilithium_pk *pk,
				struct lc_dilithium_sk *sk,
				struct lc_rng_ctx *rng_ctx)
{
	unsigned int i;
	uint8_t seedbuf[2 * LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_CRHBYTES];
	const uint8_t *rho, *rhoprime, *key;
	polyvecl rowbuf[2];
	polyvecl s1, *row = rowbuf;
	polyveck s2;
	poly t1, t0;
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

	/* Store rho, key */
	memcpy(pk->pk, rho, LC_DILITHIUM_SEEDBYTES);
	memcpy(sk->sk, rho, LC_DILITHIUM_SEEDBYTES);
	memcpy(sk->sk + LC_DILITHIUM_SEEDBYTES, key, LC_DILITHIUM_SEEDBYTES);

	/* Sample short vectors s1 and s2 */
	poly_uniform_eta_4x_avx(&s1.vec[0], &s1.vec[1], &s1.vec[2], &s1.vec[3],
				rhoprime, 0, 1, 2, 3);
	poly_uniform_eta_4x_avx(&s1.vec[4], &s1.vec[5], &s1.vec[6], &s2.vec[0],
				rhoprime, 4, 5, 6, 7);
	poly_uniform_eta_4x_avx(&s2.vec[1], &s2.vec[2], &s2.vec[3], &s2.vec[4],
				rhoprime, 8, 9, 10, 11);
	poly_uniform_eta_4x_avx(&s2.vec[5], &s2.vec[6], &s2.vec[7], &t0,
				rhoprime, 12, 13, 14, 15);

	/* Pack secret vectors */
	for (i = 0; i < LC_DILITHIUM_L; i++)
		polyeta_pack_avx(sk->sk + 3 * LC_DILITHIUM_SEEDBYTES + i * LC_DILITHIUM_POLYETA_PACKEDBYTES,
			     &s1.vec[i]);
	for (i = 0; i < LC_DILITHIUM_K; i++)
		polyeta_pack_avx(sk->sk + 3 * LC_DILITHIUM_SEEDBYTES + (LC_DILITHIUM_L + i) * LC_DILITHIUM_POLYETA_PACKEDBYTES,
			     &s2.vec[i]);

	/* Transform s1 */
	polyvecl_ntt_avx(&s1);

	for (i = 0; i < LC_DILITHIUM_K; i++) {
		polyvec_matrix_expand_row(&row, rowbuf, rho, i);

		/* Compute inner-product */
		polyvecl_pointwise_acc_montgomery_avx(&t1, row, &s1);
		poly_invntt_tomont_avx(&t1);

		/* Add error polynomial */
		poly_add_avx(&t1, &t1, &s2.vec[i]);

		/* Round t and pack t1, t0 */
		poly_caddq_avx(&t1);
		poly_power2round_avx(&t1, &t0, &t1);

		polyt1_pack_avx(pk->pk + LC_DILITHIUM_SEEDBYTES + i * LC_DILITHIUM_POLYT1_PACKEDBYTES, &t1);


		polyt0_pack_avx(sk->sk + 3 * LC_DILITHIUM_SEEDBYTES + (LC_DILITHIUM_L + LC_DILITHIUM_K) * LC_DILITHIUM_POLYETA_PACKEDBYTES + i * LC_DILITHIUM_POLYT0_PACKEDBYTES, &t0);
	}

	/* Compute H(rho, t1) and store in secret key */
	lc_shake(lc_shake256,
		 pk->pk, LC_DILITHIUM_PUBLICKEYBYTES,
		 sk->sk + 2 * LC_DILITHIUM_SEEDBYTES,
		 LC_DILITHIUM_SEEDBYTES);

out:

	//TODO workspace clearing
	return ret;
}

LC_INTERFACE_FUNCTION(
int, lc_dilithium_sign_avx2, struct lc_dilithium_sig *sig,
			     const uint8_t *m,
			     size_t mlen,
			     const struct lc_dilithium_sk *sk,
			     struct lc_rng_ctx *rng_ctx)
{
	unsigned int i, n, pos;
	uint8_t seedbuf[3 * LC_DILITHIUM_SEEDBYTES + 2 * LC_DILITHIUM_CRHBYTES];
	uint8_t *rho, *tr, *key, *mu, *rhoprime;
	uint8_t hintbuf[LC_DILITHIUM_N];
	uint8_t *hint = sig->sig + LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_L * LC_DILITHIUM_POLYZ_PACKEDBYTES;
	uint64_t nonce = 0;
	polyvecl mat[LC_DILITHIUM_K], s1, z;
	polyveck t0, s2, w1;
	poly c, tmp;
	union {
		polyvecl y;
		polyveck w0;
	} tmpv;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	/* rng_ctx is allowed to be NULL as handled below */
	if (!sig || !m || !sk)
		return -EINVAL;

	rho = seedbuf;
	tr = rho + LC_DILITHIUM_SEEDBYTES;
	key = tr + LC_DILITHIUM_SEEDBYTES;
	mu = key + LC_DILITHIUM_SEEDBYTES;
	rhoprime = mu + LC_DILITHIUM_CRHBYTES;
	unpack_sk_avx2(rho, tr, key, &t0, &s1, &s2, sk->sk);

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
	polyvecl_ntt_avx(&s1);
	polyveck_ntt_avx(&s2);
	polyveck_ntt_avx(&t0);

rej:
	/* Sample intermediate vector y */
	poly_uniform_gamma1_4x_avx(&z.vec[0], &z.vec[1], &z.vec[2], &z.vec[3],
				   rhoprime,
				   (uint16_t)nonce, (uint16_t)(nonce + 1),
				   (uint16_t)(nonce + 2), (uint16_t)(nonce + 3));
	poly_uniform_gamma1_4x_avx(&z.vec[4], &z.vec[5], &z.vec[6], &tmp,
				   rhoprime,
				   (uint16_t)(nonce + 4),(uint16_t)(nonce + 5),
				   (uint16_t)(nonce + 6), 0);
	nonce += 7;

	/* Matrix-vector product */
	tmpv.y = z;
	polyvecl_ntt_avx(&tmpv.y);
	polyvec_matrix_pointwise_montgomery_avx(&w1, mat, &tmpv.y);
	polyveck_invntt_tomont_avx(&w1);

	/* Decompose w and call the random oracle */
	polyveck_caddq_avx(&w1);
	polyveck_decompose_avx(&w1, &tmpv.w0, &w1);
	polyveck_pack_w1_avx(sig->sig, &w1);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, mu, LC_DILITHIUM_CRHBYTES);
	lc_hash_update(hash_ctx, sig->sig,
		       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
	lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_SEEDBYTES);
	lc_hash_final(hash_ctx, sig->sig);

	poly_challenge_avx(&c, sig->sig);
	poly_ntt_avx(&c);

	/* Compute z, reject if it reveals secret */
	for (i = 0; i < LC_DILITHIUM_L; i++) {
		poly_pointwise_montgomery_avx(&tmp, &c, &s1.vec[i]);
		poly_invntt_tomont_avx(&tmp);
		poly_add_avx(&z.vec[i], &z.vec[i], &tmp);
		poly_reduce_avx(&z.vec[i]);
		if (poly_chknorm_avx(&z.vec[i],
				     LC_DILITHIUM_GAMMA1 - LC_DILITHIUM_BETA))
			goto rej;
	}

	/* Zero hint vector in signature */
	pos = 0;
	memset(hint, 0, LC_DILITHIUM_OMEGA);

	for (i = 0; i < LC_DILITHIUM_K; i++) {
		/*
		 * Check that subtracting cs2 does not change high bits of
		 * w and low bits do not reveal secret information
		 */
		poly_pointwise_montgomery_avx(&tmp, &c, &s2.vec[i]);
		poly_invntt_tomont_avx(&tmp);
		poly_sub_avx(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
		poly_reduce_avx(&tmpv.w0.vec[i]);
		if (poly_chknorm_avx(&tmpv.w0.vec[i],
				     LC_DILITHIUM_GAMMA2 - LC_DILITHIUM_BETA))
			goto rej;

		/* Compute hints */
		poly_pointwise_montgomery_avx(&tmp, &c, &t0.vec[i]);
		poly_invntt_tomont_avx(&tmp);
		poly_reduce_avx(&tmp);
		if (poly_chknorm_avx(&tmp, LC_DILITHIUM_GAMMA2))
			goto rej;

		poly_add_avx(&tmpv.w0.vec[i], &tmpv.w0.vec[i], &tmp);
		n = poly_make_hint_avx(hintbuf, &tmpv.w0.vec[i], &w1.vec[i]);
		if (pos + n > LC_DILITHIUM_OMEGA)
			goto rej;

		/* Store hints in signature */
		memcpy(&hint[pos], hintbuf, n);
		pos = pos + n;
		hint[LC_DILITHIUM_OMEGA + i] = (uint8_t)pos;
	}

	/* Pack z into signature */
	for (i = 0; i < LC_DILITHIUM_L; i++)
		polyz_pack_avx(sig->sig + LC_DILITHIUM_SEEDBYTES + i * LC_DILITHIUM_POLYZ_PACKEDBYTES, &z.vec[i]);

out:
	lc_hash_zero(hash_ctx);
	return ret;
}

LC_INTERFACE_FUNCTION(
int, lc_dilithium_verify_avx2, const struct lc_dilithium_sig *sig,
			       const uint8_t *m,
			       size_t mlen,
			       const struct lc_dilithium_pk *pk)
{
	unsigned int i, j, pos = 0;
	/* polyw1_pack writes additional 14 bytes */
	ALIGNED_UINT8(LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES+14) buf;
	uint8_t mu[LC_DILITHIUM_CRHBYTES];
	const uint8_t *hint = sig->sig + LC_DILITHIUM_SEEDBYTES + LC_DILITHIUM_L * LC_DILITHIUM_POLYZ_PACKEDBYTES;
	polyvecl rowbuf[2];
	polyvecl *row = rowbuf;
	polyvecl z;
	poly c, w1, h;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_shake256);

	if (!sig || !m || !pk)
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

	/* Expand challenge */
	poly_challenge_avx(&c, sig->sig);
	poly_ntt_avx(&c);

	/* Unpack z; shortness follows from unpacking */
	for (i = 0; i < LC_DILITHIUM_L; i++) {
		polyz_unpack_avx(&z.vec[i], sig->sig + LC_DILITHIUM_SEEDBYTES + i * LC_DILITHIUM_POLYZ_PACKEDBYTES);
		poly_ntt_avx(&z.vec[i]);
	}

	for (i = 0; i < LC_DILITHIUM_K; i++) {
		polyvec_matrix_expand_row(&row, rowbuf, pk->pk, i);

		/* Compute i-th row of Az - c2^Dt1 */
		polyvecl_pointwise_acc_montgomery_avx(&w1, row, &z);

		polyt1_unpack_avx(&h, pk->pk + LC_DILITHIUM_SEEDBYTES + i * LC_DILITHIUM_POLYT1_PACKEDBYTES);
		poly_shiftl_avx(&h);
		poly_ntt_avx(&h);
		poly_pointwise_montgomery_avx(&h, &c, &h);

		poly_sub_avx(&w1, &w1, &h);
		poly_reduce_avx(&w1);
		poly_invntt_tomont_avx(&w1);

		/* Get hint polynomial and reconstruct w1 */
		memset(h.coeffs, 0, sizeof(poly));
		if (hint[LC_DILITHIUM_OMEGA + i] < pos ||
		    hint[LC_DILITHIUM_OMEGA + i] > LC_DILITHIUM_OMEGA)
			return -1;

		for(j = pos; j < hint[LC_DILITHIUM_OMEGA + i]; ++j) {
			/* Coefficients are ordered for strong unforgeability */
			if (j > pos && hint[j] <= hint[j - 1])
				return -1;
			h.coeffs[hint[j]] = 1;
		}
		pos = hint[LC_DILITHIUM_OMEGA + i];

		poly_caddq_avx(&w1);
		poly_use_hint_avx(&w1, &w1, &h);
		polyw1_pack_avx(buf.coeffs + i * LC_DILITHIUM_POLYW1_PACKEDBYTES,
				&w1);
	}

	/* Extra indices are zero for strong unforgeability */
	for (j = pos; j < LC_DILITHIUM_OMEGA; ++j) {
		if(hint[j])
			return -1;
	}

	/* Call random oracle and verify challenge */
	lc_hash_init(hash_ctx);
        lc_hash_update(hash_ctx, mu, LC_DILITHIUM_CRHBYTES);
        lc_hash_update(hash_ctx, buf.coeffs,
                       LC_DILITHIUM_K * LC_DILITHIUM_POLYW1_PACKEDBYTES);
        lc_hash_set_digestsize(hash_ctx, LC_DILITHIUM_SEEDBYTES);
        lc_hash_final(hash_ctx, buf.coeffs);

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		if (buf.coeffs[i] != sig->sig[i])
			ret = -EBADMSG;

	lc_hash_zero(hash_ctx);
	return ret;
}
