/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "build_bug_on.h"
#include "kyber_debug.h"
#include "kyber_indcpa.h"
#include "kyber_poly.h"
#include "kyber_polyvec.h"
#include "kyber_kem_input_validation.h"
#include "small_stack_support.h"
#include "lc_sha3.h"
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
static unsigned int rej_uniform(int16_t *r, unsigned int len,
				const uint8_t *buf, unsigned int buflen)
{
	unsigned int ctr, pos;
	int16_t val0, val1;

	ctr = pos = 0;
	while (ctr < len && pos + 3 <= buflen) {
		val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) &
		       0xFFF;
		val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) &
		       0xFFF;
		pos += 3;

		if (val0 < LC_KYBER_Q)
			r[ctr++] = val0;
		if (ctr < len && val1 < LC_KYBER_Q)
			r[ctr++] = val1;
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

int indcpa_keypair(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		   uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
		   struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		uint8_t buf[2 * LC_KYBER_SYMBYTES];
		polyvec e, pkpv, skpv;
		union {
			uint8_t poly_getnoise_eta1_buf
				[POLY_GETNOISE_ETA1_BUFSIZE];
			polyvec a[LC_KYBER_K];
		} tmp;
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
	kyber_print_buffer(buf, LC_KYBER_SYMBYTES, "Keygen: d");

	lc_hash_init(sha3_512_ctx);
	lc_hash_update(sha3_512_ctx, buf, LC_KYBER_SYMBYTES);
	lc_hash_update(sha3_512_ctx, &kval, sizeof(kval));
	lc_hash_final(sha3_512_ctx, buf);
	lc_hash_zero(sha3_512_ctx);

	kyber_print_buffer(buf, LC_KYBER_SYMBYTES, "Keygen: RHO");
	kyber_print_buffer(buf + LC_KYBER_SYMBYTES, LC_KYBER_SYMBYTES,
			   "Keygen: Sigma");

	for (i = 0; i < LC_KYBER_K; i++) {
		poly_getnoise_eta1(&ws->skpv.vec[i], noiseseed, nonce++,
				   ws->tmp.poly_getnoise_eta1_buf);
		poly_getnoise_eta1(&ws->e.vec[i], noiseseed, nonce2++,
				   ws->tmp.poly_getnoise_eta1_buf);
	}
	kyber_print_polyvec(&ws->skpv, "Keygen: s");
	kyber_print_polyvec(&ws->e, "Keygen: e");

	polyvec_ntt(&ws->skpv);
	polyvec_ntt(&ws->e);
	kyber_print_polyveck(&ws->skpv, "Keygen: sHat = NTT(s)");
	kyber_print_polyveck(&ws->e, "Keygen: eHat = NTT(e)");

	gen_a(ws->tmp.a, publicseed);
	kyber_print_polyveck(ws->tmp.a, "Keygen: AHat");

	// matrix-vector multiplication
	BUILD_BUG_ON(sizeof(poly) > sizeof(ws->tmp.a));
	for (i = 0; i < LC_KYBER_K; i++) {
		polyvec_basemul_acc_montgomery(&ws->pkpv.vec[i], &ws->tmp.a[i],
					       &ws->skpv, &ws->tmp.a);
		poly_tomont(&ws->pkpv.vec[i]);
	}
	kyber_print_polyvec(&ws->pkpv, "Keygen: tHat = (AHat * sHat)");

	polyvec_add(&ws->pkpv, &ws->pkpv, &ws->e);
	kyber_print_polyvec(
		&ws->pkpv,
		"Keygen: tHat = (AHat * sHat) + eHat before reduction");
	polyvec_reduce(&ws->pkpv);
	kyber_print_polyvec(&ws->pkpv, "Keygen: tHat = (AHat * sHat) + eHat");

	pack_sk(sk, &ws->skpv);
	pack_pk(pk, &ws->pkpv, publicseed);

	/* Timecop: sk, pk are not relevant any more for side-channels */
	unpoison(sk, LC_KYBER_INDCPA_SECRETKEYBYTES);
	unpoison(pk, LC_KYBER_INDCPA_PUBLICKEYBYTES);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

int indcpa_enc(uint8_t c[LC_KYBER_INDCPA_BYTES],
	       const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
	       const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
	       const uint8_t coins[LC_KYBER_SYMBYTES])
{
	struct workspace {
		polyvec sp, pkpv, ep, at[LC_KYBER_K], b;
		poly v, k, epp;
		union {
			uint8_t seed[LC_KYBER_SYMBYTES];
			uint8_t poly_getnoise_eta1_buf
				[POLY_GETNOISE_ETA1_BUFSIZE];
			uint8_t poly_getnoise_eta2_buf
				[POLY_GETNOISE_ETA2_BUFSIZE];
		} tmp;
	};
	unsigned int i;
	uint8_t nonce = 0, nonce2 = LC_KYBER_K;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	unpack_pk(&ws->pkpv, ws->tmp.seed, pk);
	kyber_print_polyvec(&ws->pkpv, "K-PKE Encrypt: tHat");

	/* Validate input */
	BUILD_BUG_ON(LC_KYBER_INDCPA_PUBLICKEYBYTES > sizeof(ws->at));
	CKINT(kyber_kem_iv_pk_modulus(pk, &ws->pkpv, ws->tmp.seed,
				      (void *)ws->at, pack_pk));

	poly_frommsg(&ws->k, m);
	kyber_print_poly(&ws->k, "K-PKE Encrypt: mu");
	gen_at(ws->at, ws->tmp.seed);
	kyber_print_polyveck(ws->at, "K-PKE Encrypt: BHat = AHat^T");

	for (i = 0; i < LC_KYBER_K; i++) {
		poly_getnoise_eta1(ws->sp.vec + i, coins, nonce++,
				   ws->tmp.poly_getnoise_eta1_buf);
		poly_getnoise_eta2(ws->ep.vec + i, coins, nonce2++,
				   ws->tmp.poly_getnoise_eta2_buf);
	}
	kyber_print_polyvec(&ws->sp, "K-PKE Encrypt: r");
	kyber_print_polyvec(&ws->ep, "K-PKE Encrypt: e1");

	poly_getnoise_eta2(&ws->epp, coins, nonce2,
			   ws->tmp.poly_getnoise_eta2_buf);
	kyber_print_poly(&ws->epp, "K-PKE Encrypt: e2");

	polyvec_ntt(&ws->sp);
	kyber_print_polyvec(&ws->sp, "K-PKE Encrypt: rHat = NTT(r)");

	// matrix-vector multiplication
	for (i = 0; i < LC_KYBER_K; i++)
		polyvec_basemul_acc_montgomery(&ws->b.vec[i], &ws->at[i],
					       &ws->sp, &ws->v);
	kyber_print_polyvec(&ws->b, "K-PKE Encrypt: u = BHat * rHat");

	BUILD_BUG_ON(sizeof(poly) > sizeof(ws->at));
	polyvec_basemul_acc_montgomery(&ws->v, &ws->pkpv, &ws->sp, ws->at);
	kyber_print_poly(&ws->v, "K-PKE Encrypt: v = tHat^T * rHat");

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

int indcpa_dec(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
	       const uint8_t c[LC_KYBER_INDCPA_BYTES],
	       const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES])
{
	struct workspace {
		polyvec skpv;
		poly v, mp;
		union {
			polyvec b;
			poly v;
		} tmp;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	unpack_sk(&ws->skpv, sk);
	kyber_print_polyvec(&ws->skpv,
			    "K-PKE Decrypt: sHat = Decompress(Bytedecode(dk))");

	/* Validate input */
	BUILD_BUG_ON(sizeof(ws->tmp.b) < LC_KYBER_INDCPA_SECRETKEYBYTES);
	CKINT(kyber_kem_iv_sk_modulus(sk, &ws->skpv, &ws->tmp.b, pack_sk));

	unpack_ciphertext(&ws->tmp.b, &ws->v, c);
	kyber_print_polyvec(&ws->tmp.b,
			    "K-PKE Decrypt: u = Decompress(Bytedecode(c1))");
	kyber_print_poly(&ws->v,
			 "K-PKE Decrypt: v = Decompress(Bytedecode(c2))");

	polyvec_ntt(&ws->tmp.b);
	kyber_print_polyvec(&ws->tmp.b, "K-PKE Decrypt: NTT(u)");
	polyvec_basemul_acc_montgomery(&ws->mp, &ws->skpv, &ws->tmp.b,
				       &ws->tmp.v);

	/* Timecop: Mark the vector with the secret message */
	poison(&ws->mp, sizeof(ws->mp));
	kyber_print_poly(&ws->mp, "K-PKE Decrypt: sHat^T * NTT(u)");
	poly_invntt_tomont(&ws->mp);
	kyber_print_poly(&ws->mp, "K-PKE Decrypt: NTT-1(s * NTT(u))");

	poly_sub(&ws->mp, &ws->v, &ws->mp);
	kyber_print_poly(&ws->mp, "K-PKE Decrypt: w = v - NTT-1(s * NTT(u))");
	poly_reduce(&ws->mp);

	poly_tomsg(m, &ws->mp);
	kyber_print_buffer(m, LC_KYBER_INDCPA_MSGBYTES,
			   "K-PKE Decrypt: m = ByteEncode(Compress(w))");

out:
	LC_RELEASE_MEM(ws);
	return ret;
}
