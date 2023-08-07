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
 * https://github.com/pq-crystals/dilithium
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/);
 * or Apache 2.0 License (https://www.apache.org/licenses/LICENSE-2.0.html).
 */

#include "build_bug_on.h"
#include "dilithium_pack.h"
#include "dilithium_poly.h"

/**
 * @brief pack_pk - Bit-pack public key pk = (rho, t1).
 *
 * @param pk [out] public key
 * @param rho [in] byte array containing rho
 * @param t1 [in] pointer to vector t1
 */
void pack_pk(struct lc_dilithium_pk *pk,
	     const uint8_t rho[LC_DILITHIUM_SEEDBYTES], const polyveck *t1)
{
	unsigned int i;
	uint8_t *pubkey = pk->pk;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		pubkey[i] = rho[i];
	pubkey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyt1_pack(pubkey + i * LC_DILITHIUM_POLYT1_PACKEDBYTES,
			    &t1->vec[i]);
}

/**
 * @brief unpack_pk - Unpack public key pk = (rho, t1).
 *
 * @param rho [out] output byte array for rho
 * @param t1 [out] pointer to output vector t1
 * @param pk [in] byte array containing bit-packed pk
 */
void unpack_pk(uint8_t rho[LC_DILITHIUM_SEEDBYTES], polyveck *t1,
	       const struct lc_dilithium_pk *pk)
{
	unsigned int i;
	const uint8_t *pubkey = pk->pk;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		rho[i] = pubkey[i];
	pubkey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyt1_unpack(&t1->vec[i],
			      pubkey + i * LC_DILITHIUM_POLYT1_PACKEDBYTES);
}

/**
 * @brief pack_sk - Bit-pack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * @param sk [out] secret key
 * @param rho [in] byte array containing rho
 * @param tr [in] byte array containing tr
 * @param key [in] byte array containing key
 * @param t0 [in] pointer to vector t0
 * @param s1 [in] pointer to vector s1
 * @param s2 [in] pointer to vector s2
 */
void pack_sk(struct lc_dilithium_sk *sk,
	     const uint8_t rho[LC_DILITHIUM_SEEDBYTES],
	     const uint8_t tr[LC_DILITHIUM_SEEDBYTES],
	     const uint8_t key[LC_DILITHIUM_SEEDBYTES], const polyveck *t0,
	     const polyvecl *s1, const polyveck *s2)
{
	unsigned int i;
	uint8_t *seckey = sk->sk;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		seckey[i] = rho[i];
	seckey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		seckey[i] = key[i];
	seckey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		seckey[i] = tr[i];
	seckey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		polyeta_pack(seckey + i * LC_DILITHIUM_POLYETA_PACKEDBYTES,
			     &s1->vec[i]);
	seckey += LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyeta_pack(seckey + i * LC_DILITHIUM_POLYETA_PACKEDBYTES,
			     &s2->vec[i]);
	seckey += LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyt0_pack(seckey + i * LC_DILITHIUM_POLYT0_PACKEDBYTES,
			    &t0->vec[i]);
}

/**
 * @brief unpack_sk - Unpack secret key sk = (rho, tr, key, t0, s1, s2).
 *
 * @param rho [out] output byte array for rho
 * @param tr [out] output byte array for tr
 * @param key [out] output byte array for key
 * @param t0 [out] pointer to output vector t0
 * @param s1 [out] pointer to output vector s1
 * @param s2 [out] pointer to output vector s2
 * @param sk [in] byte array containing bit-packed sk
 */
void unpack_sk(uint8_t rho[LC_DILITHIUM_SEEDBYTES],
	       uint8_t tr[LC_DILITHIUM_SEEDBYTES],
	       uint8_t key[LC_DILITHIUM_SEEDBYTES], polyveck *t0, polyvecl *s1,
	       polyveck *s2, const struct lc_dilithium_sk *sk)
{
	unsigned int i;
	const uint8_t *seckey = sk->sk;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		rho[i] = seckey[i];
	seckey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		key[i] = seckey[i];
	seckey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		tr[i] = seckey[i];
	seckey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		polyeta_unpack(&s1->vec[i],
			       seckey + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
	seckey += LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyeta_unpack(&s2->vec[i],
			       seckey + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
	seckey += LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyt0_unpack(&t0->vec[i],
			      seckey + i * LC_DILITHIUM_POLYT0_PACKEDBYTES);
}

/**
 * @brief unpack_sk_tr - Unpack tr only from secret key sk
 *
 * @param t0 [out] pointer to output vector t0
 * @param sk [in] byte array containing bit-packed sk
 */
void unpack_sk_tr(uint8_t tr[LC_DILITHIUM_SEEDBYTES],
		  const struct lc_dilithium_sk *sk)
{
	unsigned int i;
	const uint8_t *seckey = sk->sk + 2 * LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		tr[i] = seckey[i];
}

/**
 * @brief unpack_sk - Unpack secret key sk without tr = (rho, key, t0, s1, s2).
 *
 * @param rho [out] output byte array for rho
 * @param key [out] output byte array for key
 * @param t0 [out] pointer to output vector t0
 * @param s1 [out] pointer to output vector s1
 * @param s2 [out] pointer to output vector s2
 * @param sk [in] byte array containing bit-packed sk
 */
void unpack_sk_ex_tr(uint8_t rho[LC_DILITHIUM_SEEDBYTES],
		     uint8_t key[LC_DILITHIUM_SEEDBYTES], polyveck *t0,
		     polyvecl *s1, polyveck *s2,
		     const struct lc_dilithium_sk *sk)
{
	unsigned int i;
	const uint8_t *seckey = sk->sk;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		rho[i] = seckey[i];
	seckey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		key[i] = seckey[i];
	seckey += LC_DILITHIUM_SEEDBYTES;

	/* Skip tr */
	seckey += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		polyeta_unpack(&s1->vec[i],
			       seckey + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
	seckey += LC_DILITHIUM_L * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyeta_unpack(&s2->vec[i],
			       seckey + i * LC_DILITHIUM_POLYETA_PACKEDBYTES);
	seckey += LC_DILITHIUM_K * LC_DILITHIUM_POLYETA_PACKEDBYTES;

	for (i = 0; i < LC_DILITHIUM_K; ++i)
		polyt0_unpack(&t0->vec[i],
			      seckey + i * LC_DILITHIUM_POLYT0_PACKEDBYTES);
}

/**
 * @brief pack_sig - Bit-pack signature sig = (c, z, h).
 *
 * @param sig [out] signature
 * @param c [in] pointer to challenge hash length LC_DILITHIUM_SEEDBYTES
 * @param z [in] pointer to vector z
 * @param h [in] pointer to hint vector h
 */
void pack_sig(struct lc_dilithium_sig *sig,
	      const uint8_t c[LC_DILITHIUM_SEEDBYTES], const polyvecl *z,
	      const polyveck *h)
{
	unsigned int i, j, k;
	uint8_t *signature = sig->sig;

	BUILD_BUG_ON((1ULL << (sizeof(j) << 3)) < LC_DILITHIUM_N);
	BUILD_BUG_ON((1ULL << (sizeof(k) << 3)) < LC_DILITHIUM_N);

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		signature[i] = c[i];
	signature += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		polyz_pack(signature + i * LC_DILITHIUM_POLYZ_PACKEDBYTES,
			   &z->vec[i]);
	signature += LC_DILITHIUM_L * LC_DILITHIUM_POLYZ_PACKEDBYTES;

	/* Encode h */
	for (i = 0; i < LC_DILITHIUM_OMEGA + LC_DILITHIUM_K; ++i)
		signature[i] = 0;

	k = 0;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		for (j = 0; j < LC_DILITHIUM_N; ++j)
			if (h->vec[i].coeffs[j] != 0)
				signature[k++] = (uint8_t)j;

		signature[LC_DILITHIUM_OMEGA + i] = (uint8_t)k;
	}
}

/**
 * @brief unpack_sig - Unpack signature sig = (c, z, h).
 *
 * @param c [out] pointer to output challenge hash
 * @param z [out] pointer to output vector z
 * @param h [out] pointer to output hint vector h
 * @param sig [in] signature
 *
 * @return 1 in case of malformed signature; otherwise 0.
 */
int unpack_sig(uint8_t c[LC_DILITHIUM_SEEDBYTES], polyvecl *z, polyveck *h,
	       const struct lc_dilithium_sig *sig)
{
	unsigned int i, j, k;
	const uint8_t *signature = sig->sig;

	for (i = 0; i < LC_DILITHIUM_SEEDBYTES; ++i)
		c[i] = signature[i];
	signature += LC_DILITHIUM_SEEDBYTES;

	for (i = 0; i < LC_DILITHIUM_L; ++i)
		polyz_unpack(&z->vec[i],
			     signature + i * LC_DILITHIUM_POLYZ_PACKEDBYTES);
	signature += LC_DILITHIUM_L * LC_DILITHIUM_POLYZ_PACKEDBYTES;

	/* Decode h */
	k = 0;
	for (i = 0; i < LC_DILITHIUM_K; ++i) {
		for (j = 0; j < LC_DILITHIUM_N; ++j)
			h->vec[i].coeffs[j] = 0;

		if (signature[LC_DILITHIUM_OMEGA + i] < k ||
		    signature[LC_DILITHIUM_OMEGA + i] > LC_DILITHIUM_OMEGA)
			return 1;

		for (j = k; j < signature[LC_DILITHIUM_OMEGA + i]; ++j) {
			/* Coefficients are ordered for strong unforgeability */
			if (j > k && signature[j] <= signature[j - 1])
				return 1;
			h->vec[i].coeffs[signature[j]] = 1;
		}

		k = signature[LC_DILITHIUM_OMEGA + i];
	}

	/* Extra indices are zero for strong unforgeability */
	for (j = k; j < LC_DILITHIUM_OMEGA; ++j)
		if (signature[j])
			return 1;

	return 0;
}
