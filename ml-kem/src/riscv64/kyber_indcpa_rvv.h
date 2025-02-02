/*
 * Copyright (C) 2023 - 2025, Stephan Mueller <smueller@chronox.de>
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
 * This file is derived from https://github.com/Ji-Peng/PQRV which uses the
 * following license.
 *
 * The MIT license, the text of which is below, applies to PQRV in general.
 *
 * Copyright (c) 2024 - 2025 Jipeng Zhang (jp-zhang@outlook.com)
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef KYBER_INDCPA_RVV_H
#define KYBER_INDCPA_RVV_H

#include "build_bug_on.h"
#include "ext_headers_riscv.h"
#include "kyber_debug.h"
#include "kyber_kem_input_validation.h"
#include "lc_sha3.h"
#include "small_stack_support.h"
#include "ret_checkers.h"
#include "timecop.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief pack_pk - Serialize the public key as concatenation of the
 *		    serialized vector of polynomials pk and the public seed
 *		    used to generate the matrix A.
 *
 * @param [out] r pointer to the output serialized public key
 * @param [in] pk pointer to the input public-key polyvec
 * @param [in] seed pointer to the input public seed
 */
static void pack_pk(uint8_t r[LC_KYBER_INDCPA_PUBLICKEYBYTES], polyvec *pk,
		    const uint8_t seed[LC_KYBER_SYMBYTES])
{
	unsigned int i;

	LC_VECTOR_ENABLE;
	for (i = 0; i < LC_KYBER_K; i++)
		LC_KYBER_RVV_TYPE(kyber_ntt2normal_order_rvv)(
			pk->vec[i].coeffs, LC_KYBER_RVV_TYPE(kyber_qdata_rvv));
	LC_VECTOR_DISABLE;

	polyvec_tobytes(r, pk);
	memcpy(&r[LC_KYBER_POLYVECBYTES], seed, LC_KYBER_SYMBYTES);
}

/**
 * @brief unpack_pk - De-serialize public key from a byte array;
 *		      approximate inverse of pack_pk
 *
 * @param [out] pk pointer to output public-key polynomial vector
 * @param [out] seed pointer to output seed to generate matrix A
 * @param [out] packedpk pointer to input serialized public key
 */
static void unpack_pk(polyvec *pk, uint8_t seed[LC_KYBER_SYMBYTES],
		      const uint8_t packedpk[LC_KYBER_INDCPA_PUBLICKEYBYTES])
{
	polyvec_frombytes(pk, packedpk);
	memcpy(seed, &packedpk[LC_KYBER_POLYVECBYTES], LC_KYBER_SYMBYTES);
}

/**
 * @brief pack_sk - Serialize the secret key
 *
 * @param [out] r pointer to output serialized secret key
 * @param [in] sk pointer to input vector of polynomials (secret key)
 */
static void pack_sk(uint8_t r[LC_KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
	unsigned int i;

	LC_VECTOR_ENABLE;
	for (i = 0; i < LC_KYBER_K; i++)
		LC_KYBER_RVV_TYPE(kyber_ntt2normal_order_rvv)(
			sk->vec[i].coeffs, LC_KYBER_RVV_TYPE(kyber_qdata_rvv));
	LC_VECTOR_DISABLE;

	polyvec_tobytes(r, sk);
}

/**
 * @brief unpack_sk - De-serialize the secret key; inverse of pack_sk
 *
 * @param [out] sk pointer to output vector of polynomials (secret key)
 * @param [in] packedsk pointer to input serialized secret key
 */
static void unpack_sk(polyvec *sk,
		      const uint8_t packedsk[LC_KYBER_INDCPA_SECRETKEYBYTES])
{
	polyvec_frombytes(sk, packedsk);
}

/**
 * @brief pack_ciphertext - Serialize the ciphertext as concatenation of the
 *			    compressed and serialized vector of polynomials b
 *			    and the compressed and serialized polynomial v
 *
 * @param [out] r pointer to the output serialized ciphertext
 * @param [in] pk pointer to the input vector of polynomials b
 * @param [in] v pointer to the input polynomial v
 */
static void pack_ciphertext(uint8_t r[LC_KYBER_INDCPA_BYTES], polyvec *b,
			    poly *v)
{
	polyvec_compress(r, b);
	poly_compress(r + LC_KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/**
 * @brief unpack_ciphertext - De-serialize and decompress ciphertext from a byte
 *			      array; approximate inverse of pack_ciphertext
 *
 * @param [out] b pointer to the output vector of polynomials b
 * @param [out] v pointer to the output polynomial v
 * @param [in] c pointer to the input serialized ciphertext
 */
static void unpack_ciphertext(polyvec *b, poly *v,
			      const uint8_t c[LC_KYBER_INDCPA_BYTES])
{
	polyvec_decompress(b, c);
	poly_decompress(v, c + LC_KYBER_POLYVECCOMPRESSEDBYTES);
}

/**
 * @brief rej_uniform - Run rejection sampling on uniform random bytes to
 *			generate uniform random integers mod q
 *
 * @param [out] r pointer to output buffer
 * @param [in] len requested number of 16-bit integers (uniform mod q)
 * @param [in] buf pointer to input buffer (assumed to be uniformly random
 *		   bytes)
 * @param [in] buflen length of input buffer in bytes
 *
 * @returns number of sampled 16-bit integers (at most len)
 */
static unsigned int rej_uniform(int16_t *r, unsigned int len,
				const uint8_t *buf, unsigned int buflen)
{
	unsigned int ctr, pos;
	uint16_t val0, val1;

	ctr = pos = 0;
	while (ctr < len && pos + 3 <= buflen) {
		val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) &
		       0xFFF;
		val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) &
		       0xFFF;
		pos += 3;

		if (val0 < LC_KYBER_Q)
			r[ctr++] = (int16_t)val0;
		if (ctr < len && val1 < LC_KYBER_Q)
			r[ctr++] = (int16_t)val1;
	}

	return ctr;
}

#define GEN_MATRIX_NBLOCKS                                                     \
	((12 * LC_KYBER_N / 8 * (1 << 12) / LC_KYBER_Q +                       \
	  LC_SHAKE_128_SIZE_BLOCK) /                                           \
	 LC_SHAKE_128_SIZE_BLOCK)
#define REJ_UNIFORM_VECTOR_BUFLEN (GEN_MATRIX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK)

static unsigned int rej_uniform_vector(int16_t *r, const uint8_t *buf)
{
	unsigned int ctr, pos;
	uint16_t val0, val1;

	LC_VECTOR_ENABLE;
	LC_KYBER_RVV_TYPE(kyber_rej_uniform_rvv)(
		r, buf, LC_KYBER_RVV_TYPE(kyber_qdata_rvv), &ctr, &pos);
	LC_VECTOR_DISABLE;

	while (ctr < LC_KYBER_N && pos <= REJ_UNIFORM_VECTOR_BUFLEN - 3) {
		val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) &
		       0xFFF;
		val1 = (uint16_t)((buf[pos + 1] >> 4) |
				  ((uint16_t)buf[pos + 2] << 4));
		pos += 3;
		if (val0 < LC_KYBER_Q)
			r[ctr++] = (int16_t)val0;
		if (val1 < LC_KYBER_Q && ctr < LC_KYBER_N)
			r[ctr++] = (int16_t)val1;
	}
	return ctr;
}

#define gen_a(A, B) gen_matrix(A, B, 0)
#define gen_at(A, B) gen_matrix(A, B, 1)

/**
 * @brief gen_matrix - Deterministically generate matrix A (or the transpose of
 *		       A) from a seed. Entries of the matrix are polynomials
 *		       that look uniformly random. Performs rejection sampling
 *		       on output of a XOF
 *
 * @param [out] a pointer to output matrix A
 * @param [in] seed pointer to input seed
 * @param [in] transposed boolean deciding whether A or A^T is generated
 */
static void gen_matrix(polyvec *a, const uint8_t seed[LC_KYBER_SYMBYTES],
		       int transposed)
{
	unsigned int ctr, i, j;
	unsigned int buflen;
	uint8_t buf[GEN_MATRIX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 8];
	LC_SHAKE_128_CTX_ON_STACK(shake_128);

	for (i = 0; i < LC_KYBER_K; i++) {
		for (j = 0; j < LC_KYBER_K; j++) {
			uint8_t i_tmp = (uint8_t)i, j_tmp = (uint8_t)j;

			lc_hash_init(shake_128);
			lc_hash_update(shake_128, seed, LC_KYBER_SYMBYTES);

			if (transposed) {
				lc_hash_update(shake_128, &i_tmp, 1);
				lc_hash_update(shake_128, &j_tmp, 1);
			} else {
				lc_hash_update(shake_128, &j_tmp, 1);
				lc_hash_update(shake_128, &i_tmp, 1);
			}

			buflen = GEN_MATRIX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK;
			lc_hash_set_digestsize(shake_128, buflen);
			lc_hash_final(shake_128, buf);

			ctr = rej_uniform_vector(a[i].vec[j].coeffs, buf);

			while (ctr < LC_KYBER_N) {
				lc_hash_set_digestsize(shake_128,
						       LC_SHAKE_128_SIZE_BLOCK);
				lc_hash_final(shake_128, buf);

				ctr += rej_uniform(a[i].vec[j].coeffs + ctr,
						   LC_KYBER_N - ctr, buf,
						   LC_SHAKE_128_SIZE_BLOCK);
			}
		}
	}

	lc_hash_zero(shake_128);
	lc_memset_secure(buf, 0, sizeof(buf));

	LC_VECTOR_ENABLE;
	for (i = 0; i < LC_KYBER_K; i++) {
		for (j = 0; j < LC_KYBER_K; j++)
			LC_KYBER_RVV_TYPE(kyber_normal2ntt_order_rvv)(
				a[i].vec[j].coeffs,
				LC_KYBER_RVV_TYPE(kyber_qdata_rvv));
	}
	LC_VECTOR_DISABLE;
}

static inline int
indcpa_keypair_rvv_common(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			  uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
			  struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		uint8_t buf[2 * LC_KYBER_SYMBYTES];
		uint8_t poly_getnoise_eta1_buf[POLY_GETNOISE_ETA1_BUFSIZE];
		polyvec a[LC_KYBER_K], e, pkpv, skpv;
		polyvec_half skpv_cache;
	};
	static const uint8_t kval = LC_KYBER_K;
	unsigned int i;
	uint8_t *buf;
	const uint8_t *publicseed, *noiseseed;
	uint8_t nonce = 0, nonce2 = LC_KYBER_K;
	int ret;
	LC_HASH_CTX_ON_STACK(sha3_512_ctx, lc_sha3_512);
	LC_DECLARE_MEM(ws, struct workspace, 32);

	buf = ws->buf;
	publicseed = ws->buf;
	noiseseed = ws->buf + LC_KYBER_SYMBYTES;

	/* Timecop: Mark sensitive part of the seed. */
	poison(noiseseed, LC_KYBER_SYMBYTES);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, buf, LC_KYBER_SYMBYTES));
	lc_hash_init(sha3_512_ctx);
	lc_hash_update(sha3_512_ctx, buf, LC_KYBER_SYMBYTES);
	lc_hash_update(sha3_512_ctx, &kval, sizeof(kval));
	lc_hash_final(sha3_512_ctx, buf);
	lc_hash_zero(sha3_512_ctx);

	gen_a(ws->a, publicseed);

	for (i = 0; i < LC_KYBER_K; i++) {
		poly_getnoise_eta1(&ws->skpv.vec[i], noiseseed, nonce++,
				   ws->poly_getnoise_eta1_buf);
		poly_getnoise_eta1(&ws->e.vec[i], noiseseed, nonce2++,
				   ws->poly_getnoise_eta1_buf);
	}

	polyvec_ntt(&ws->skpv);
	polyvec_reduce(&ws->skpv);
	polyvec_ntt(&ws->e);

	// matrix-vector multiplication
	polyvec_basemul_acc_cache_init(&ws->pkpv.vec[0], &ws->a[0], &ws->skpv,
				       &ws->skpv_cache);
	poly_tomont(&ws->pkpv.vec[0]);
	for (i = 1; i < LC_KYBER_K; i++) {
		polyvec_basemul_acc_cached(&ws->pkpv.vec[i], &ws->a[i],
					   &ws->skpv, &ws->skpv_cache);
		poly_tomont(&ws->pkpv.vec[i]);
	}

	polyvec_add(&ws->pkpv, &ws->pkpv, &ws->e);
	polyvec_reduce(&ws->pkpv);

	pack_sk(sk, &ws->skpv);
	pack_pk(pk, &ws->pkpv, publicseed);

	/* Timecop: sk, pk are not relevant any more for side-channels */
	unpoison(sk, LC_KYBER_INDCPA_SECRETKEYBYTES);
	unpoison(pk, LC_KYBER_INDCPA_PUBLICKEYBYTES);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static inline int
indcpa_enc_rvv_common(uint8_t c[LC_KYBER_INDCPA_BYTES],
		      const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		      const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		      const uint8_t coins[LC_KYBER_SYMBYTES])
{
	struct workspace {
		/* See comment below - currently not needed */
		uint8_t seed[LC_KYBER_SYMBYTES];
		uint8_t poly_getnoise_eta1_buf[POLY_GETNOISE_ETA1_BUFSIZE];
		uint8_t poly_getnoise_eta2_buf[POLY_GETNOISE_ETA2_BUFSIZE];

		/* See comment below - currently not needed */
		//uint8_t poly_getnoise_eta2_buf[POLY_GETNOISE_ETA2_BUFSIZE];
		polyvec sp, pkpv, ep, at[LC_KYBER_K], b;
		poly v, k, epp;
		polyvec_half sp_cache;
	};
	unsigned int i;
	uint8_t nonce = 0, nonce2 = LC_KYBER_K;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	/*
	 * Use the poly_getnoise_eta1_buf for this operation as seed is smaller
	 * than poly_getnoise_eta1_buf and has the same alignment.
	 */
	BUILD_BUG_ON(POLY_GETNOISE_ETA1_BUFSIZE < LC_KYBER_SYMBYTES);
	unpack_pk(&ws->pkpv, ws->seed, pk);
	kyber_print_polyvec(&ws->pkpv, "K-PKE Encrypt: tHat");

	poly_frommsg(&ws->k, m);
	kyber_print_poly(&ws->k, "K-PKE Encrypt: mu");
	gen_at(ws->at, ws->seed);
	kyber_print_polyveck(ws->at, "K-PKE Encrypt: BHat = AHat^T");

	/*
	 * Use the poly_getnoise_eta1_buf for this operation as
	 * poly_getnoise_eta2_buf is smaller than poly_getnoise_eta1_buf and has
	 * the same alignment.
	 */
	BUILD_BUG_ON(POLY_GETNOISE_ETA1_BUFSIZE < POLY_GETNOISE_ETA2_BUFSIZE);
	for (i = 0; i < LC_KYBER_K; i++) {
		poly_getnoise_eta1(ws->sp.vec + i, coins, nonce++,
				   ws->poly_getnoise_eta1_buf);
		poly_getnoise_eta2(ws->ep.vec + i, coins, nonce2++,
				   ws->poly_getnoise_eta2_buf);
	}
	kyber_print_polyvec(&ws->sp, "K-PKE Encrypt: r");
	kyber_print_polyvec(&ws->ep, "K-PKE Encrypt: e1");

	poly_getnoise_eta2(&ws->epp, coins, nonce2, ws->poly_getnoise_eta2_buf);
	kyber_print_poly(&ws->epp, "K-PKE Encrypt: e2");

	polyvec_ntt(&ws->sp);
	kyber_print_polyvec(&ws->sp, "K-PKE Encrypt: rHat = NTT(r)");

	// matrix-vector multiplication
	polyvec_basemul_acc_cache_init(&ws->b.vec[0], &ws->at[0], &ws->sp,
				       &ws->sp_cache);
	for (i = 1; i < LC_KYBER_K; i++) {
		polyvec_basemul_acc_cached(&ws->b.vec[i], &ws->at[i], &ws->sp,
					   &ws->sp_cache);
	}
	polyvec_basemul_acc_cached(&ws->v, &ws->pkpv, &ws->sp, &ws->sp_cache);

	/*
	 * Validate input of PK - this check must be after the last usage of
	 * the pkpv variable as the check will modify this variable.
	 */
	CKINT(kyber_kem_iv_pk_modulus(pk, &ws->pkpv, ws->seed, (void *)ws->at,
				      pack_pk));

	polyvec_invntt_tomont(&ws->b);
	kyber_print_polyvec(&ws->b, "K-PKE Encrypt: u = NTT-1(BHat * rHat)");
	poly_invntt_tomont(&ws->v);
	kyber_print_poly(&ws->v, "K-PKE Encrypt: v = NTT-1(tHat^T * rHat)");

	polyvec_add(&ws->b, &ws->b, &ws->ep);
	kyber_print_polyvec(&ws->b,
			    "K-PKE Encrypt: u = NTT-1(BHat * rHat) + e1");
	poly_add(&ws->v, &ws->v, &ws->epp);
	kyber_print_poly(&ws->v,
			 "K-PKE Encrypt: v = NTT-1(tHat^T * rHat) + e2");
	poly_add(&ws->v, &ws->v, &ws->k);
	kyber_print_poly(&ws->v,
			 "K-PKE Encrypt: v = NTT-1(tHat^T * rHat) + e2 + mu");

	polyvec_reduce(&ws->b);
	kyber_print_polyvec(&ws->b, "K-PKE Encrypt: u after reduction");
	poly_reduce(&ws->v);
	kyber_print_poly(&ws->v, "K-PKE Encrypt: v after reduction");

	pack_ciphertext(c, &ws->b, &ws->v);
	kyber_print_buffer(c, LC_KYBER_POLYVECCOMPRESSEDBYTES,
			   "K-PKE Encrypt: c1 = ByteEncode(Compress(u))");
	kyber_print_buffer(c + LC_KYBER_POLYVECCOMPRESSEDBYTES,
			   LC_KYBER_POLYCOMPRESSEDBYTES,
			   "K-PKE Encrypt: c2 = ByteEncode(Compress(v))");

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static inline int
indcpa_dec_rvv_common(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		      const uint8_t c[LC_KYBER_INDCPA_BYTES],
		      const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES])
{
	struct workspace {
		polyvec b, skpv;
		poly v, mp;
	};
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	unpack_sk(&ws->skpv, sk);

	/* Validate input */
	BUILD_BUG_ON(sizeof(ws->b) < LC_KYBER_INDCPA_SECRETKEYBYTES);

	unpack_ciphertext(&ws->b, &ws->v, c);

	polyvec_ntt(&ws->b);
	polyvec_basemul_acc(&ws->mp, &ws->skpv, &ws->b);

	/* Timecop: Mark the vector with the secret message */
	poison(&ws->mp, sizeof(ws->mp));
	poly_invntt_tomont(&ws->mp);

	poly_sub(&ws->mp, &ws->v, &ws->mp);
	poly_reduce(&ws->mp);

	poly_tomsg(m, &ws->mp);

	LC_RELEASE_MEM(ws);
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_INDCPA_RVV_H */
