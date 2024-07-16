/*
 * Copyright (C) 2023 - 2024, Stephan Mueller <smueller@chronox.de>
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
 * https://github.com/psanal2018/kyber-arm64
 *
 * That code is released under MIT license.
 */

#include "build_bug_on.h"
#include "kyber_indcpa_armv8.h"
#include "kyber_poly_armv8.h"
#include "kyber_polyvec_armv8.h"
#include "kyber_kem_input_validation.h"
#include "lc_sha3.h"
#include "small_stack_support.h"
#include "ret_checkers.h"
#include "timecop.h"

/**
 * @brief pack_pk - Serialize the public key as concatenation of the
 *		    serialized vector of polynomials pk and the public seed
 *		    used to generate the matrix A.
 *
 * @param r [out] pointer to the output serialized public key
 * @param pk [in] pointer to the input public-key polyvec
 * @param seed [in] pointer to the input public seed
 */
static void pack_pk(uint8_t r[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		    const polyvec *pk, const uint8_t seed[LC_KYBER_SYMBYTES])
{
	polyvec_tobytes(r, pk);
	memcpy(&r[LC_KYBER_POLYVECBYTES], seed, LC_KYBER_SYMBYTES);
}

/**
 * @brief unpack_pk - De-serialize public key from a byte array;
 *		      approximate inverse of pack_pk
 *
 * @param pk [out] pointer to output public-key polynomial vector
 * @param seed [out] pointer to output seed to generate matrix A
 * @param packedpk [out] pointer to input serialized public key
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
 * @param r [out] pointer to output serialized secret key
 * @param sk [in] pointer to input vector of polynomials (secret key)
 */
static void pack_sk(uint8_t r[LC_KYBER_INDCPA_SECRETKEYBYTES],
		    const polyvec *sk)
{
	polyvec_tobytes(r, sk);
}

/**
 * @brief unpack_sk - De-serialize the secret key; inverse of pack_sk
 *
 * @param sk [out] pointer to output vector of polynomials (secret key)
 * @param packedsk [in] pointer to input serialized secret key
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
 * @param r [out] pointer to the output serialized ciphertext
 * @param pk [in] pointer to the input vector of polynomials b
 * @param v [in] pointer to the input polynomial v
 */
static void pack_ciphertext(uint8_t r[LC_KYBER_INDCPA_BYTES], polyvec *b,
			    poly *v)
{
	polyvec_compress(r, b);
	poly_compress_armv8(r + LC_KYBER_POLYVECCOMPRESSEDBYTES, v);
}

/**
 * @brief unpack_ciphertext - De-serialize and decompress ciphertext from a byte
 *			      array; approximate inverse of pack_ciphertext
 *
 * @param b [out] pointer to the output vector of polynomials b
 * @param v [out] pointer to the output polynomial v
 * @param c [in] pointer to the input serialized ciphertext
 */
static void unpack_ciphertext(polyvec *b, poly *v,
			      const uint8_t c[LC_KYBER_INDCPA_BYTES])
{
	polyvec_decompress(b, c);
	poly_decompress_armv8(v, c + LC_KYBER_POLYVECCOMPRESSEDBYTES);
}

/**
 * @brief rej_uniform - Run rejection sampling on uniform random bytes to
 *			generate uniform random integers mod q
 *
 * @param r [out] pointer to output buffer
 * @param len [in] requested number of 16-bit integers (uniform mod q)
 * @param buf [in] pointer to input buffer (assumed to be uniformly random
 *		   bytes)
 * @param buflen [in] length of input buffer in bytes
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

#define gen_a(A, B) gen_matrix(A, B, 0)
#define gen_at(A, B) gen_matrix(A, B, 1)

/**
 * @brief gen_matrix - Deterministically generate matrix A (or the transpose of
 *		       A) from a seed. Entries of the matrix are polynomials
 *		       that look uniformly random. Performs rejection sampling
 *		       on output of a XOF
 *
 * @param a [out] pointer to output matrix A
 * @param seed [in] pointer to input seed
 * @param transposed [in] boolean deciding whether A or A^T is generated
 */
#define GEN_MATRIX_NBLOCKS                                                     \
	((12 * LC_KYBER_N / 8 * (1 << 12) / LC_KYBER_Q +                       \
	  LC_SHAKE_128_SIZE_BLOCK) /                                           \
	 LC_SHAKE_128_SIZE_BLOCK)
static void gen_matrix(polyvec *a, const uint8_t seed[LC_KYBER_SYMBYTES],
		       int transposed)
{
	unsigned int ctr, i, j;
	unsigned int buflen, off;
	uint8_t buf[GEN_MATRIX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2];
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

			ctr = rej_uniform(a[i].vec[j].coeffs, LC_KYBER_N, buf,
					  buflen);

			while (ctr < LC_KYBER_N) {
				off = buflen % 3;

				memcpy(buf, &buf[buflen - off], off);

				lc_hash_set_digestsize(shake_128,
						       LC_SHAKE_128_SIZE_BLOCK);
				lc_hash_final(shake_128, buf + off);
				buflen = off + LC_SHAKE_128_SIZE_BLOCK;
				ctr += rej_uniform(a[i].vec[j].coeffs + ctr,
						   LC_KYBER_N - ctr, buf,
						   buflen);
			}
		}
	}

	lc_hash_zero(shake_128);
	lc_memset_secure(buf, 0, sizeof(buf));
}

int indcpa_keypair_armv8(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			 uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
			 struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		uint8_t buf[2 * LC_KYBER_SYMBYTES];
		uint8_t poly_getnoise_eta1_buf[POLY_GETNOISE_ETA1_BUFSIZE];
		polyvec a[LC_KYBER_K], e, pkpv, skpv;
	};
	unsigned int i;
	uint8_t *buf;
	const uint8_t *publicseed, *noiseseed;
	uint8_t nonce = 0, nonce2 = LC_KYBER_K;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, 32);

	buf = ws->buf;
	publicseed = ws->buf;
	noiseseed = ws->buf + LC_KYBER_SYMBYTES;

	/* Timecop: Mark sensitive part of the seed. */
	poison(noiseseed, LC_KYBER_SYMBYTES);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, buf, LC_KYBER_SYMBYTES));
	lc_hash(lc_sha3_512, buf, LC_KYBER_SYMBYTES, buf);
	gen_a(ws->a, publicseed);

	for (i = 0; i < LC_KYBER_K; i++) {
		poly_getnoise_eta1_armv8(&ws->skpv.vec[i], noiseseed, nonce++,
					 ws->poly_getnoise_eta1_buf);
		poly_getnoise_eta1_armv8(&ws->e.vec[i], noiseseed, nonce2++,
					 ws->poly_getnoise_eta1_buf);
	}

	polyvec_ntt(&ws->skpv);
	polyvec_ntt(&ws->e);

	// matrix-vector multiplication
	for (i = 0; i < LC_KYBER_K; i++) {
		polyvec_basemul_acc_montgomery(&ws->pkpv.vec[i], &ws->a[i],
					       &ws->skpv);
		poly_tomont(&ws->pkpv.vec[i]);
	}

	polyvec_add_reduce(&ws->pkpv, &ws->pkpv, &ws->e);

	pack_sk(sk, &ws->skpv);
	pack_pk(pk, &ws->pkpv, publicseed);

	/* Timecop: sk, pk are not relevant any more for side-channels */
	unpoison(sk, LC_KYBER_INDCPA_SECRETKEYBYTES);
	unpoison(pk, LC_KYBER_INDCPA_PUBLICKEYBYTES);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

int indcpa_enc_armv8(uint8_t c[LC_KYBER_INDCPA_BYTES],
		     const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		     const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		     const uint8_t coins[LC_KYBER_SYMBYTES])
{
	struct workspace {
		/* See comment below - currently not needed */
		//uint8_t seed[LC_KYBER_SYMBYTES];
		uint8_t poly_getnoise_eta1_buf[POLY_GETNOISE_ETA1_BUFSIZE];
		/* See comment below - currently not needed */
		//uint8_t poly_getnoise_eta2_buf[POLY_GETNOISE_ETA2_BUFSIZE];
		polyvec sp, pkpv, ep, at[LC_KYBER_K], b;
		poly v, k, epp;
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
	unpack_pk(&ws->pkpv, ws->poly_getnoise_eta1_buf /* ws->seed */, pk);

	/* Validate input */
	CKINT(kyber_kem_iv_pk_modulus(pk, &ws->pkpv,
				      ws->poly_getnoise_eta1_buf /* ws->seed */,
				      (void *)ws->at, pack_pk));

	poly_frommsg(&ws->k, m);
	gen_at(ws->at, ws->poly_getnoise_eta1_buf /* ws->seed */);

	/*
	 * Use the poly_getnoise_eta1_buf for this operation as
	 * poly_getnoise_eta2_buf is smaller than poly_getnoise_eta1_buf and has
	 * the same alignment.
	 */
	BUILD_BUG_ON(POLY_GETNOISE_ETA1_BUFSIZE < POLY_GETNOISE_ETA2_BUFSIZE);
	for (i = 0; i < LC_KYBER_K; i++) {
		poly_getnoise_eta1_armv8(ws->sp.vec + i, coins, nonce++,
					 ws->poly_getnoise_eta1_buf);
		poly_getnoise_eta2_armv8(ws->ep.vec + i, coins, nonce2++,
					 ws->poly_getnoise_eta1_buf);
	}
	poly_getnoise_eta2_armv8(&ws->epp, coins, nonce2,
				 ws->poly_getnoise_eta1_buf);

	polyvec_ntt(&ws->sp);

	// matrix-vector multiplication
	for (i = 0; i < LC_KYBER_K; i++)
		polyvec_basemul_acc_montgomery(&ws->b.vec[i], &ws->at[i],
					       &ws->sp);

	polyvec_basemul_acc_montgomery(&ws->v, &ws->pkpv, &ws->sp);

	polyvec_invntt_tomont(&ws->b);
	poly_invntt_tomont(&ws->v);

	polyvec_add_reduce(&ws->b, &ws->b, &ws->ep);

	poly_add_add_reduce(&ws->v, &ws->v, &ws->epp, &ws->k);

	pack_ciphertext(c, &ws->b, &ws->v);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

int indcpa_dec_armv8(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		     const uint8_t c[LC_KYBER_INDCPA_BYTES],
		     const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES])
{
	struct workspace {
		polyvec b, skpv;
		poly v, mp;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	unpack_ciphertext(&ws->b, &ws->v, c);
	unpack_sk(&ws->skpv, sk);

	/* Validate input */
	BUILD_BUG_ON(sizeof(ws->b) < LC_KYBER_INDCPA_SECRETKEYBYTES);
	CKINT(kyber_kem_iv_sk_modulus(sk, &ws->skpv, &ws->b, pack_sk));

	polyvec_ntt(&ws->b);
	polyvec_basemul_acc_montgomery(&ws->mp, &ws->skpv, &ws->b);

	/* Timecop: Mark the vector with the secret message */
	poison(&ws->mp, sizeof(ws->mp));
	poly_invntt_tomont(&ws->mp);

	poly_sub_reduce(&ws->mp, &ws->v, &ws->mp);

	poly_tomsg(m, &ws->mp);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}
