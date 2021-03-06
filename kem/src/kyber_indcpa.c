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
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "kyber_indcpa.h"
#include "kyber_poly.h"
#include "kyber_polyvec.h"

#include "memset_secure.h"
#include "lc_sha3.h"
#include "ret_checkers.h"

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
		    polyvec *pk,
		    const uint8_t seed[LC_KYBER_SYMBYTES])
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
static void unpack_pk(polyvec *pk,
		      uint8_t seed[LC_KYBER_SYMBYTES],
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
static void pack_sk(uint8_t r[LC_KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
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
	poly_compress(r + LC_KYBER_POLYVECCOMPRESSEDBYTES, v);
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
	poly_decompress(v, c + LC_KYBER_POLYVECCOMPRESSEDBYTES);
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
static unsigned int rej_uniform(int16_t *r,
				unsigned int len,
				const uint8_t *buf,
				unsigned int buflen)
{
	unsigned int ctr, pos;
	int16_t val0, val1;

	ctr = pos = 0;
	while (ctr < len && pos + 3 <= buflen) {
		val0 = ((buf[pos+0] >> 0) | ((uint16_t)buf[pos+1] << 8)) & 0xFFF;
		val1 = ((buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4)) & 0xFFF;
		pos += 3;

		if(val0 < LC_KYBER_Q)
			r[ctr++] = val0;
		if(ctr < len && val1 < LC_KYBER_Q)
			r[ctr++] = val1;
	}

	return ctr;
}

#define gen_a(A, B)  gen_matrix(A, B, 0)
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
#define GEN_MATRIX_NBLOCKS						       \
	((12 * LC_KYBER_N / 8*(1 << 12) / LC_KYBER_Q +			       \
	 LC_SHAKE_128_SIZE_BLOCK)/LC_SHAKE_128_SIZE_BLOCK)

static void gen_matrix(polyvec *a, const uint8_t seed[LC_KYBER_SYMBYTES],
		       int transposed)
{
	LC_SHAKE_128_CTX_ON_STACK(shake_128);
	unsigned int ctr, i, j;
	unsigned int buflen, off;
	uint8_t buf[GEN_MATRIX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK + 2];

	for (i = 0; i< LC_KYBER_K; i++) {

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

			ctr = rej_uniform(a[i].vec[j].coeffs, LC_KYBER_N,
					  buf, buflen);

			while (ctr < LC_KYBER_N) {
				off = buflen % 3;

				memcpy(buf, &buf[buflen - off], off);

				lc_hash_set_digestsize(shake_128,
						       LC_SHAKE_128_SIZE_BLOCK);
				lc_hash_final(shake_128, buf + off);
				buflen = off + LC_SHAKE_128_SIZE_BLOCK;
				ctr += rej_uniform(a[i].vec[j].coeffs + ctr,
						   LC_KYBER_N - ctr,
						   buf, buflen);
			}
		}
	}

	lc_hash_zero(shake_128);
	memset_secure(buf, 0, sizeof(buf));
}

int indcpa_keypair(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		   uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
		   struct lc_rng_ctx *rng_ctx)
{
	unsigned int i;
	uint8_t buf[2 * LC_KYBER_SYMBYTES];
	const uint8_t *publicseed = buf;
	const uint8_t *noiseseed = buf + LC_KYBER_SYMBYTES;
	uint8_t nonce = 0, nonce2 = LC_KYBER_K;
	polyvec a[LC_KYBER_K], e, pkpv, skpv;
	int ret;

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, buf, LC_KYBER_SYMBYTES));
	lc_hash(lc_sha3_512, buf, LC_KYBER_SYMBYTES, buf);
	gen_a(a, publicseed);

	for (i = 0; i < LC_KYBER_K; i++) {
		poly_getnoise_eta1(&skpv.vec[i], noiseseed, nonce++);
		poly_getnoise_eta1(&e.vec[i], noiseseed, nonce2++);
	}

	polyvec_ntt(&skpv);
	polyvec_ntt(&e);

	// matrix-vector multiplication
	for (i = 0; i < LC_KYBER_K; i++) {
		polyvec_basemul_acc_montgomery(&pkpv.vec[i], &a[i], &skpv);
		poly_tomont(&pkpv.vec[i]);
	}

	polyvec_add(&pkpv, &pkpv, &e);
	polyvec_reduce(&pkpv);

	pack_sk(sk, &skpv);
	pack_pk(pk, &pkpv, publicseed);

out:
	memset_secure(buf, 0, sizeof(buf));
	memset_secure(a, 0, sizeof(a));
	memset_secure(&e, 0, sizeof(e));
	memset_secure(&pkpv, 0, sizeof(pkpv));
	memset_secure(&skpv, 0, sizeof(skpv));
	return ret;
}

void indcpa_enc(uint8_t c[LC_KYBER_INDCPA_BYTES],
		const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		const uint8_t coins[LC_KYBER_SYMBYTES])
{
	unsigned int i;
	uint8_t seed[LC_KYBER_SYMBYTES];
	uint8_t nonce = 0, nonce2 = LC_KYBER_K;
	polyvec sp, pkpv, ep, at[LC_KYBER_K], b;
	poly v, k, epp;

	unpack_pk(&pkpv, seed, pk);
	poly_frommsg(&k, m);
	gen_at(at, seed);

	for (i = 0; i < LC_KYBER_K; i++) {
		poly_getnoise_eta1(sp.vec+i, coins, nonce++);
		poly_getnoise_eta2(ep.vec+i, coins, nonce2++);
	}
	poly_getnoise_eta2(&epp, coins, nonce2++);

	polyvec_ntt(&sp);

	// matrix-vector multiplication
	for (i = 0; i < LC_KYBER_K; i++)
		polyvec_basemul_acc_montgomery(&b.vec[i], &at[i], &sp);

	polyvec_basemul_acc_montgomery(&v, &pkpv, &sp);

	polyvec_invntt_tomont(&b);
	poly_invntt_tomont(&v);

	polyvec_add(&b, &b, &ep);
	poly_add(&v, &v, &epp);
	poly_add(&v, &v, &k);
	polyvec_reduce(&b);
	poly_reduce(&v);

	pack_ciphertext(c, &b, &v);

	memset_secure(seed, 0, sizeof(seed));
	memset_secure(&sp, 0, sizeof(sp));
	memset_secure(&pkpv, 0, sizeof(pkpv));
	memset_secure(&ep, 0, sizeof(ep));
	memset_secure(at, 0, sizeof(at));
	memset_secure(&b, 0, sizeof(b));
	memset_secure(&v, 0, sizeof(v));
	memset_secure(&k, 0, sizeof(k));
	memset_secure(&epp, 0, sizeof(epp));
}

void indcpa_dec(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		const uint8_t c[LC_KYBER_INDCPA_BYTES],
		const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES])
{
	polyvec b, skpv;
	poly v, mp;

	unpack_ciphertext(&b, &v, c);
	unpack_sk(&skpv, sk);

	polyvec_ntt(&b);
	polyvec_basemul_acc_montgomery(&mp, &skpv, &b);
	poly_invntt_tomont(&mp);

	poly_sub(&mp, &v, &mp);
	poly_reduce(&mp);

	poly_tomsg(m, &mp);

	memset_secure(&b, 0, sizeof(b));
	memset_secure(&skpv, 0, sizeof(skpv));
	memset_secure(&v, 0, sizeof(v));
	memset_secure(&mp, 0, sizeof(mp));
}
