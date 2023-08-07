/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#include "alignment_x86.h"
#include "build_bug_on.h"
#include "kyber_indcpa_avx2.h"
#include "kyber_poly_avx2.h"
#include "kyber_polyvec_avx2.h"
#include "kyber_rejsample_avx2.h"
#include "lc_sha3.h"
#include "shake_4x_avx2.h"
#include "small_stack_support.h"
#include "ret_checkers.h"

#if LC_KYBER_K != 4
#error "Kyber AVX2 support only present for Kyber1024"
#endif

/**
 * @brief pack_pk - Serialize the public key as concatenation of the
 *		    serialized vector of polynomials pk and the public seed
 *		    used to generate the matrix A.
 *
 * @param r [out] pointer to the output serialized public key
 * @param pk [in] pointer to the input public-key polyvec
 * @param seed [in] pointer to the input public seed
 */
static void pack_pk(uint8_t r[LC_KYBER_INDCPA_PUBLICKEYBYTES], polyvec *pk,
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
	poly_compress_avx(r + LC_KYBER_POLYVECCOMPRESSEDBYTES, v);
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
	poly_decompress_avx(v, c + LC_KYBER_POLYVECCOMPRESSEDBYTES);
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

#define gen_a(A, B, ws_buf) gen_matrix(A, B, ws_buf, 0)
#define gen_at(A, B, ws_buf) gen_matrix(A, B, ws_buf, 1)

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
static int gen_matrix(polyvec *a, const uint8_t seed[LC_KYBER_SYMBYTES],
		      void *ws_buf, int transposed)
{
	keccakx4_state state;
	unsigned int ctr0, ctr1, ctr2, ctr3;
	uint8_t i;
	__m256i f;
#define BUFSIZE (REJ_UNIFORM_AVX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK)
	__m256i *vec0 = (__m256i *)ws_buf;
	__m256i *vec1 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE);
	__m256i *vec2 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 2;
	__m256i *vec3 = (__m256i *)(ws_buf) + ALIGNED_UINT8_M256I(BUFSIZE) * 3;
	uint8_t *coeffs0 = (uint8_t *)vec0;
	uint8_t *coeffs1 = (uint8_t *)vec1;
	uint8_t *coeffs2 = (uint8_t *)vec2;
	uint8_t *coeffs3 = (uint8_t *)vec3;
#undef BUFSIZE

	for (i = 0; i < 4; i++) {
		LC_FPU_ENABLE;
		f = _mm256_loadu_si256((__m256i_u *)seed);
		_mm256_store_si256(vec0, f);
		_mm256_store_si256(vec1, f);
		_mm256_store_si256(vec2, f);
		_mm256_store_si256(vec3, f);
		LC_FPU_DISABLE;

		if (transposed) {
			coeffs0[32] = i;
			coeffs0[33] = 0;
			coeffs1[32] = i;
			coeffs1[33] = 1;
			coeffs2[32] = i;
			coeffs2[33] = 2;
			coeffs3[32] = i;
			coeffs3[33] = 3;
		} else {
			coeffs0[32] = 0;
			coeffs0[33] = i;
			coeffs1[32] = 1;
			coeffs1[33] = i;
			coeffs2[32] = 2;
			coeffs2[33] = i;
			coeffs3[32] = 3;
			coeffs3[33] = i;
		}

		shake128x4_absorb_once(&state, coeffs0, coeffs1, coeffs2,
				       coeffs3, 34);
		shake128x4_squeezeblocks(coeffs0, coeffs1, coeffs2, coeffs3,
					 REJ_UNIFORM_AVX_NBLOCKS, &state);

		ctr0 = kyber_rej_uniform_avx(a[i].vec[0].coeffs, coeffs0);
		ctr1 = kyber_rej_uniform_avx(a[i].vec[1].coeffs, coeffs1);
		ctr2 = kyber_rej_uniform_avx(a[i].vec[2].coeffs, coeffs2);
		ctr3 = kyber_rej_uniform_avx(a[i].vec[3].coeffs, coeffs3);

		while (ctr0 < LC_KYBER_N || ctr1 < LC_KYBER_N ||
		       ctr2 < LC_KYBER_N || ctr3 < LC_KYBER_N) {
			shake128x4_squeezeblocks(coeffs0, coeffs1, coeffs2,
						 coeffs3, 1, &state);

			ctr0 += rej_uniform(a[i].vec[0].coeffs + ctr0,
					    LC_KYBER_N - ctr0, coeffs0,
					    LC_SHAKE_128_SIZE_BLOCK);
			ctr1 += rej_uniform(a[i].vec[1].coeffs + ctr1,
					    LC_KYBER_N - ctr1, coeffs1,
					    LC_SHAKE_128_SIZE_BLOCK);
			ctr2 += rej_uniform(a[i].vec[2].coeffs + ctr2,
					    LC_KYBER_N - ctr2, coeffs2,
					    LC_SHAKE_128_SIZE_BLOCK);
			ctr3 += rej_uniform(a[i].vec[3].coeffs + ctr3,
					    LC_KYBER_N - ctr3, coeffs3,
					    LC_SHAKE_128_SIZE_BLOCK);
		}

		poly_nttunpack_avx(&a[i].vec[0]);
		poly_nttunpack_avx(&a[i].vec[1]);
		poly_nttunpack_avx(&a[i].vec[2]);
		poly_nttunpack_avx(&a[i].vec[3]);
	}

	lc_memset_secure(&state, 0, sizeof(state));
	return 0;
}

int indcpa_keypair_avx(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		       uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
		       struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		/* See comment below - currently not needed */
		//BUF_ALIGNED_UINT8_M256I(NOISE_NBLOCKS *
		//	LC_SHAKE_256_SIZE_BLOCK) poly_getnoise_eta1_buf[4];
		BUF_ALIGNED_UINT8_M256I(
			REJ_UNIFORM_AVX_NBLOCKS *LC_SHAKE_128_SIZE_BLOCK)
		gen_a_buf[4];
		uint8_t buf[2 * LC_KYBER_SYMBYTES];
		polyvec a[LC_KYBER_K], e, pkpv, skpv;
		keccakx4_state keccak_state;
	};
	unsigned int i;
	uint8_t *buf;
	const uint8_t *publicseed, *noiseseed;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, 32);

	buf = ws->buf;
	publicseed = ws->buf;
	noiseseed = ws->buf + LC_KYBER_SYMBYTES;

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, buf, LC_KYBER_SYMBYTES));
	lc_hash(lc_sha3_512, buf, LC_KYBER_SYMBYTES, buf);

	CKINT(gen_a(ws->a, publicseed, ws->gen_a_buf));

	/*
	 * Use the gen_a_buf for this operation as poly_getnoise_eta1_buf is
	 * smaller than gen_a_buf and has the same alignment.
	 */
	BUILD_BUG_ON(REJ_UNIFORM_AVX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK <
		     NOISE_NBLOCKS * LC_SHAKE_256_SIZE_BLOCK);
	poly_getnoise_eta1_4x(ws->skpv.vec + 0, ws->skpv.vec + 1,
			      ws->skpv.vec + 2, ws->skpv.vec + 3, noiseseed, 0,
			      1, 2, 3, ws->gen_a_buf, &ws->keccak_state);
	poly_getnoise_eta1_4x(ws->e.vec + 0, ws->e.vec + 1, ws->e.vec + 2,
			      ws->e.vec + 3, noiseseed, 4, 5, 6, 7,
			      ws->gen_a_buf, &ws->keccak_state);
	polyvec_ntt(&ws->skpv);
	polyvec_reduce(&ws->skpv);
	polyvec_ntt(&ws->e);

	// matrix-vector multiplication
	for (i = 0; i < LC_KYBER_K; i++) {
		polyvec_basemul_acc_montgomery(&ws->pkpv.vec[i], &ws->a[i],
					       &ws->skpv);
		poly_tomont_avx(&ws->pkpv.vec[i]);
	}

	polyvec_add(&ws->pkpv, &ws->pkpv, &ws->e);
	polyvec_reduce(&ws->pkpv);

	pack_sk(sk, &ws->skpv);
	pack_pk(pk, &ws->pkpv, publicseed);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

int indcpa_enc_avx(uint8_t c[LC_KYBER_INDCPA_BYTES],
		   const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		   const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
		   const uint8_t coins[LC_KYBER_SYMBYTES])
{
	struct workspace {
		/* See comment below - currently not needed */
		//BUF_ALIGNED_UINT8_M256I(NOISE_NBLOCKS *
		//	LC_SHAKE_256_SIZE_BLOCK) poly_getnoise_eta1_buf[4];
		BUF_ALIGNED_UINT8_M256I(
			REJ_UNIFORM_AVX_NBLOCKS *LC_SHAKE_128_SIZE_BLOCK)
		gen_at_buf[4];
		uint8_t seed[LC_KYBER_SYMBYTES];
		polyvec sp, pkpv, ep, at[LC_KYBER_K], b;
		poly v, k, epp;
		keccakx4_state keccak_state;
	};
	unsigned int i;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, 32);

	unpack_pk(&ws->pkpv, ws->seed, pk);
	poly_frommsg_avx(&ws->k, m);
	CKINT(gen_at(ws->at, ws->seed, ws->gen_at_buf));

	/*
	 * Use the gen_a_buf for this operation as poly_getnoise_eta1_buf is
	 * smaller than gen_a_buf and has the same alignment.
	 */
	BUILD_BUG_ON(REJ_UNIFORM_AVX_NBLOCKS * LC_SHAKE_128_SIZE_BLOCK <
		     NOISE_NBLOCKS * LC_SHAKE_256_SIZE_BLOCK);
	poly_getnoise_eta1_4x(ws->sp.vec + 0, ws->sp.vec + 1, ws->sp.vec + 2,
			      ws->sp.vec + 3, coins, 0, 1, 2, 3, ws->gen_at_buf,
			      &ws->keccak_state);
	poly_getnoise_eta1_4x(ws->ep.vec + 0, ws->ep.vec + 1, ws->ep.vec + 2,
			      ws->ep.vec + 3, coins, 4, 5, 6, 7, ws->gen_at_buf,
			      &ws->keccak_state);
	poly_getnoise_eta2_avx(&ws->epp, coins, 8);
	polyvec_ntt(&ws->sp);

	// matrix-vector multiplication
	for (i = 0; i < LC_KYBER_K; i++)
		polyvec_basemul_acc_montgomery(&ws->b.vec[i], &ws->at[i],
					       &ws->sp);

	polyvec_basemul_acc_montgomery(&ws->v, &ws->pkpv, &ws->sp);

	polyvec_invntt_tomont(&ws->b);
	poly_invntt_tomont_avx(&ws->v);

	polyvec_add(&ws->b, &ws->b, &ws->ep);
	kyber_poly_add_avx(&ws->v, &ws->v, &ws->epp);
	kyber_poly_add_avx(&ws->v, &ws->v, &ws->k);
	polyvec_reduce(&ws->b);
	poly_reduce_avx(&ws->v);

	pack_ciphertext(c, &ws->b, &ws->v);

out:
	LC_RELEASE_MEM(ws);
	return 0;
}

int indcpa_dec_avx(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
		   const uint8_t c[LC_KYBER_INDCPA_BYTES],
		   const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES])
{
	struct workspace {
		polyvec b, skpv;
		poly v, mp;
	};
	LC_DECLARE_MEM(ws, struct workspace, 32);

	unpack_ciphertext(&ws->b, &ws->v, c);
	unpack_sk(&ws->skpv, sk);

	polyvec_ntt(&ws->b);
	polyvec_basemul_acc_montgomery(&ws->mp, &ws->skpv, &ws->b);
	poly_invntt_tomont_avx(&ws->mp);

	kyber_poly_sub_avx(&ws->mp, &ws->v, &ws->mp);
	poly_reduce_avx(&ws->mp);

	poly_tomsg_avx(m, &ws->mp);

	LC_RELEASE_MEM(ws);
	return 0;
}
