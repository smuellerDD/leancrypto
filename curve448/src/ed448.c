/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2015-2016 Cryptography Research, Inc.
 * Modifications Copyright 2020 David Schatz
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#include "build_bug_on.h"
#include "compare.h"
#include "ed448_composite.h"
#include "ed448_pct.h"
#include "ext_headers_internal.h"
#include "lc_ed448.h"
#include "lc_memcmp_secure.h"
#include "lc_sha3.h"
#include "point_448.h"
#include "ret_checkers.h"
#include "selftest_rng.h"
#include "signature_domain_separation.h"
#include "timecop.h"
#include "visibility.h"

#define EDDSA_USE_SIGMA_ISOGENY 0
#define COFACTOR 4
#define EDDSA_PREHASH_BYTES 64

static int lc_ed448_keypair_nocheck(struct lc_ed448_pk *pk,
				    struct lc_ed448_sk *sk,
				    struct lc_rng_ctx *rng_ctx);
static void lc_ed448_keypair_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t sk_exp[] = {
		0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d,
		0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85, 0x3e,
		0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88,
		0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66, 0xef, 0x26,
		0x3c, 0xb1, 0xee, 0xa9, 0x88, 0x00, 0x4b, 0x93,
		0x10, 0x3c, 0xfb, 0x0a, 0xee, 0xfd, 0x2a, 0x68,
		0x6e, 0x01, 0xfa, 0x4a, 0x58, 0xe8, 0xa3, 0x63,
		0x9c,
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t pk_exp[] = {
		0xec, 0x75, 0x70, 0x1e, 0xb4, 0xcd, 0x30, 0x2e,
		0x4f, 0x5f, 0x4b, 0xf5, 0x8f, 0xc7, 0xb4, 0x85,
		0xcc, 0x81, 0x78, 0xc2, 0xb2, 0x75, 0x68, 0x5d,
		0x9a, 0xe2, 0x25, 0x7a, 0xd6, 0x7f, 0x51, 0xf8,
	};
	struct lc_ed448_pk pk;
	struct lc_ed448_sk sk;
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	LC_SELFTEST_RUN(LC_ALG_STATUS_ED448_KEYGEN);

	lc_ed448_keypair_nocheck(&pk, &sk, selftest_rng);
	if (lc_compare_selftest(LC_ALG_STATUS_ED448_KEYGEN, pk.pk, pk_exp,
				sizeof(pk_exp), "ED448 keypair pubkey\n"))
		return;
	lc_compare_selftest(LC_ALG_STATUS_ED448_KEYGEN, sk.sk, sk_exp,
			    sizeof(sk.sk), "ED448 keypair seckey\n");
}

static int lc_ed448_sign_nocheck(struct lc_ed448_sig *sig,
				 const uint8_t *msg, size_t mlen,
				 const struct lc_ed448_sk *sk,
				 struct lc_rng_ctx *rng_ctx);
/* Test vector generated with libsodium using the ACVP parser tool */
static void lc_ed448_sign_tester(void)
{
	LC_FIPS_RODATA_SECTION
	static const struct lc_ed448_sk sk = {
		.sk = { 0xc4, 0xea, 0xb0, 0x5d, 0x35, 0x70, 0x07, 0xc6, 0x32,
			0xf3, 0xdb, 0xb4, 0x84, 0x89, 0x92, 0x4d, 0x55, 0x2b,
			0x08, 0xfe, 0x0c, 0x35, 0x3a, 0x0d, 0x4a, 0x1f, 0x00,
			0xac, 0xda, 0x2c, 0x46, 0x3a, 0xfb, 0xea, 0x67, 0xc5,
			0xe8, 0xd2, 0x87, 0x7c, 0x5e, 0x3b, 0xc3, 0x97, 0xa6,
			0x59, 0x94, 0x9e, 0xf8, 0x02, 0x1e, 0x95, 0x4e, 0x0a,
			0x12, 0x27, 0x4e }
	};
	LC_FIPS_RODATA_SECTION
	static const struct lc_ed448_sig exp_sig = {
		.sig = { 0x26, 0xb8, 0xf9, 0x17, 0x27, 0xbd, 0x62, 0x89, 0x7a,
			 0xf1, 0x5e, 0x41, 0xeb, 0x43, 0xc3, 0x77, 0xef, 0xb9,
			 0xc6, 0x10, 0xd4, 0x8f, 0x23, 0x35, 0xcb, 0x0b, 0xd0,
			 0x08, 0x78, 0x10, 0xf4, 0x35, 0x25, 0x41, 0xb1, 0x43,
			 0xc4, 0xb9, 0x81, 0xb7, 0xe1, 0x8f, 0x62, 0xde, 0x8c,
			 0xcd, 0xf6, 0x33, 0xfc, 0x1b, 0xf0, 0x37, 0xab, 0x7c,
			 0xd7, 0x79, 0x80, 0x5e, 0x0d, 0xbc, 0xc0, 0xaa, 0xe1,
			 0xcb, 0xce, 0xe1, 0xaf, 0xb2, 0xe0, 0x27, 0xdf, 0x36,
			 0xbc, 0x04, 0xdc, 0xec, 0xbf, 0x15, 0x43, 0x36, 0xc1,
			 0x9f, 0x0a, 0xf7, 0xe0, 0xa6, 0x47, 0x29, 0x05, 0xe7,
			 0x99, 0xf1, 0x95, 0x3d, 0x2a, 0x0f, 0xf3, 0x34, 0x8a,
			 0xb2, 0x1a, 0xa4, 0xad, 0xaf, 0xd1, 0xd2, 0x34, 0x44,
			 0x1c, 0xf8, 0x07, 0xc0, 0x3a, 0x00 }
	};
	static const uint8_t msg[] = { 0x03 };
	struct lc_ed448_sig sig;

	LC_SELFTEST_RUN(LC_ALG_STATUS_ED448_SIGGEN);

	if (lc_ed448_sign_nocheck(&sig, msg, sizeof(msg), &sk, NULL))
		return;
	lc_compare_selftest(LC_ALG_STATUS_ED448_SIGGEN, sig.sig, exp_sig.sig,
			    sizeof(exp_sig.sig),
			    "ED448 Signature generation\n");
}

static void curve448_clamp(uint8_t secret_scalar_ser[LC_ED448_SECRETKEYBYTES])
{
	/* Blarg */
	secret_scalar_ser[0] &= (uint8_t)-COFACTOR;
	uint8_t hibit = (1 << 0) >> 1;

	if (hibit == 0) {
		secret_scalar_ser[LC_ED448_SECRETKEYBYTES - 1] = 0;
		secret_scalar_ser[LC_ED448_SECRETKEYBYTES - 2] |= 0x80;
	} else {
		secret_scalar_ser[LC_ED448_SECRETKEYBYTES - 1] &= hibit - 1;
		secret_scalar_ser[LC_ED448_SECRETKEYBYTES - 1] |= hibit;
	}
}

#define DECAF_448_EDDSA_ENCODE_RATIO 4
static int
ed448_derive_public_key(uint8_t pubkey[LC_ED448_PUBLICKEYBYTES],
			const uint8_t privkey[LC_ED448_SECRETKEYBYTES])
{
	/* only this much used for keygen */
	uint8_t secret_scalar_ser[LC_ED448_SECRETKEYBYTES];
	int ret;

	CKINT(lc_xof(lc_shake256, privkey, LC_ED448_SECRETKEYBYTES,
		     secret_scalar_ser, sizeof(secret_scalar_ser)));
	curve448_clamp(secret_scalar_ser);

	curve448_scalar_t secret_scalar;
	curve448_scalar_decode_long(secret_scalar, secret_scalar_ser,
				    sizeof(secret_scalar_ser));

	/*
	 * Since we are going to mul_by_cofactor during encoding, divide by it
	 * here. However, the EdDSA base point is not the same as the decaf base
	 * point if the sigma isogeny is in use: the EdDSA base point is on
	 * Etwist_d/(1-d) and the decaf base point is on Etwist_d, and when
	 * converted it effectively picks up a factor of 2 from the isogenies.
	 * So we might start at 2 instead of 1.
	 */
	for (unsigned int c = 1; c < DECAF_448_EDDSA_ENCODE_RATIO; c <<= 1)
		curve448_scalar_halve(secret_scalar, secret_scalar);

	curve448_point_t p;
	curve448_precomputed_scalarmul(p, curve448_precomputed_base,
				       secret_scalar);

	curve448_point_mul_by_ratio_and_encode_like_eddsa(pubkey, p);

	/* Cleanup */
	curve448_scalar_destroy(secret_scalar);
	curve448_point_destroy(p);

out:
	lc_memset_secure(secret_scalar_ser, 0, sizeof(secret_scalar_ser));
	return ret;
}

static int lc_ed448_keypair_nocheck(struct lc_ed448_pk *pk,
				    struct lc_ed448_sk *sk,
				    struct lc_rng_ctx *rng_ctx)
{
	int ret;

	lc_rng_check(&rng_ctx);
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, sk->sk,
			      LC_ED448_SECRETKEYBYTES));

	/* Timecop: the random number is the sentitive data */
	poison(sk->sk, LC_ED448_SECRETKEYBYTES);

	ed448_derive_public_key(pk->pk, sk->sk);

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(sk->sk, LC_ED448_SECRETKEYBYTES);
	unpoison(pk->pk, LC_ED448_PUBLICKEYBYTES);

	CKINT(lc_ed448_pct_fips(pk, sk));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_ed448_keypair, struct lc_ed448_pk *pk,
		      struct lc_ed448_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	lc_ed448_keypair_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED448_KEYGEN);

	return lc_ed448_keypair_nocheck(pk, sk, rng_ctx);
}

static inline void lc_ed448_xof_final(struct lc_hash_ctx *xof_ctx,
				      uint8_t *digest, size_t digest_len)
{
	lc_hash_set_digestsize(xof_ctx, digest_len);
	lc_hash_final(xof_ctx, digest);
	lc_hash_zero(xof_ctx);
}

static int curveed448_hash_init_with_dom(struct lc_hash_ctx *hash_ctx,
					  uint8_t prehashed,
					  uint8_t for_prehash,
					  const uint8_t *context,
					  uint8_t context_len)
{
	static const char dom_s[] = "SigEd448";
	const uint8_t dom[2] = { (uint8_t)(2 + word_is_zero(prehashed) +
					   word_is_zero(for_prehash)),
				 context_len };
	int ret = lc_hash_init(hash_ctx);

	if (ret)
		return ret;
	lc_hash_update(hash_ctx, (const unsigned char *)dom_s, 8);
	lc_hash_update(hash_ctx, dom, 2);
	lc_hash_update(hash_ctx, context, context_len);

	return 0;
}

static int
curveed448_sign_internal(uint8_t signature[LC_ED448_SIGBYTES],
			 const uint8_t privkey[LC_ED448_SECRETKEYBYTES],
			 const uint8_t pubkey[LC_ED448_PUBLICKEYBYTES],
			 const uint8_t *message, size_t message_len,
			 uint8_t prehashed,
			 struct lc_dilithium_ed448_ctx *composite_ml_dsa_ctx)
{
	curve448_scalar_t secret_scalar, nonce_scalar, challenge_scalar;
	struct lc_dilithium_ctx *dilithium_ctx = NULL;
	uint8_t nonce_point[LC_ED448_PUBLICKEYBYTES] = { 0 };
	int ret = 0;
	LC_SHAKE_256_CTX_ON_STACK(shake256_ctx);

	if (composite_ml_dsa_ctx) {
		dilithium_ctx = &composite_ml_dsa_ctx->dilithium_ctx;

		if (!dilithium_ctx->nist_category)
			dilithium_ctx = NULL;
	}

	/* Timecop: mark the secret key as sensitive */
	poison(privkey, LC_ED448_SECRETKEYBYTES);

	{
		/* Schedule the secret key */
		struct {
			uint8_t secret_scalar_ser[LC_ED448_SECRETKEYBYTES];
			uint8_t seed[LC_ED448_SECRETKEYBYTES];
		} __attribute__((packed)) expanded;

		CKINT(lc_xof(lc_shake256, privkey, LC_ED448_SECRETKEYBYTES,
			     (uint8_t *)&expanded, sizeof(expanded)));

		/*
		 * Once the private key is hashed, you cannot deduct it from
		 * the message digest, thus unpoison it.
		 */
		unpoison(&expanded, sizeof(expanded));

		curve448_clamp(expanded.secret_scalar_ser);
		curve448_scalar_decode_long(secret_scalar,
					    expanded.secret_scalar_ser,
					    sizeof(expanded.secret_scalar_ser));

		/* Hash to create the nonce */
		CKINT(curveed448_hash_init_with_dom(shake256_ctx, prehashed, 0,
						    NULL, 0));
		lc_hash_update(shake256_ctx, expanded.seed,
			       sizeof(expanded.seed));
		lc_memset_secure(&expanded, 0, sizeof(expanded));

		/* If Composite ML-DSA is requested, apply domain separation */
		if (dilithium_ctx) {
			CKINT(composite_signature_domain_separation(
				shake256_ctx, dilithium_ctx->userctx,
				dilithium_ctx->userctxlen,
				dilithium_ctx->randomizer,
				dilithium_ctx->randomizerlen,
				dilithium_ctx->nist_category));
		}

		lc_hash_update(shake256_ctx, message, message_len);
	}

	/* Decode the nonce */
	{
		uint8_t nonce[2 * LC_ED448_SECRETKEYBYTES];

		lc_ed448_xof_final(shake256_ctx, nonce, sizeof(nonce));
		curve448_scalar_decode_long(nonce_scalar, nonce, sizeof(nonce));
		lc_memset_secure(nonce, 0, sizeof(nonce));
	}

	{
		/* Scalarmul to create the nonce-point */
		curve448_scalar_t nonce_scalar_2;

		curve448_scalar_halve(nonce_scalar_2, nonce_scalar);
		for (unsigned int c = 2; c < DECAF_448_EDDSA_ENCODE_RATIO;
		     c <<= 1) {
			curve448_scalar_halve(nonce_scalar_2, nonce_scalar_2);
		}

		curve448_point_t p;
		curve448_precomputed_scalarmul(p, curve448_precomputed_base,
					       nonce_scalar_2);
		curve448_point_mul_by_ratio_and_encode_like_eddsa(nonce_point,
								  p);
		curve448_point_destroy(p);
		curve448_scalar_destroy(nonce_scalar_2);
	}

	{
		/* Compute the challenge */
		CKINT(curveed448_hash_init_with_dom(shake256_ctx, prehashed, 0,
						    NULL, 0));
		lc_hash_update(shake256_ctx, nonce_point, sizeof(nonce_point));
		lc_hash_update(shake256_ctx, pubkey, LC_ED448_PUBLICKEYBYTES);

		/* If Composite ML-DSA is requested, apply domain separation */
		if (dilithium_ctx) {
			CKINT(composite_signature_domain_separation(
				shake256_ctx, dilithium_ctx->userctx,
				dilithium_ctx->userctxlen,
				dilithium_ctx->randomizer,
				dilithium_ctx->randomizerlen,
				dilithium_ctx->nist_category));
		}

		lc_hash_update(shake256_ctx, message, message_len);

		uint8_t challenge[2 * LC_ED448_SECRETKEYBYTES];
		lc_ed448_xof_final(shake256_ctx, challenge, sizeof(challenge));
		curve448_scalar_decode_long(challenge_scalar, challenge,
					    sizeof(challenge));
		lc_memset_secure(challenge, 0, sizeof(challenge));
	}

	curve448_scalar_mul(challenge_scalar, challenge_scalar, secret_scalar);
	curve448_scalar_add(challenge_scalar, challenge_scalar, nonce_scalar);

	lc_memset_secure(signature, 0, LC_ED448_SIGBYTES);
	BUILD_BUG_ON(LC_ED448_PUBLICKEYBYTES > LC_ED448_SIGBYTES);
	memcpy(signature, nonce_point, sizeof(nonce_point));
	curve448_scalar_encode(&signature[LC_ED448_PUBLICKEYBYTES],
			       challenge_scalar);

	/* Timecop: sig and sk are not relevant for side-channels any more. */
	unpoison(signature, LC_ED448_SIGBYTES);
	unpoison(privkey, LC_ED448_SECRETKEYBYTES);

out:
	curve448_scalar_destroy(secret_scalar);
	curve448_scalar_destroy(nonce_scalar);
	curve448_scalar_destroy(challenge_scalar);
	lc_memset_secure(nonce_point, 0, sizeof(nonce_point));
	lc_hash_zero(shake256_ctx);
	return ret;
}

static int lc_ed448_sign_nocheck(struct lc_ed448_sig *sig,
				 const uint8_t *msg, size_t mlen,
				 const struct lc_ed448_sk *sk,
				 struct lc_rng_ctx *rng_ctx)
{
	uint8_t rederived_pubkey[LC_ED448_PUBLICKEYBYTES];
	int ret = 0;

	(void)rng_ctx;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);

	ed448_derive_public_key(rederived_pubkey, sk->sk);
	CKINT(curveed448_sign_internal(sig->sig, sk->sk, rederived_pubkey, msg,
				       mlen, 0, NULL));

out:
	lc_memset_secure(rederived_pubkey, 0, sizeof(rederived_pubkey));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_ed448_sign, struct lc_ed448_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed448_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	lc_ed448_sign_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED448_SIGGEN);

	return lc_ed448_sign_nocheck(sig, msg, mlen, sk, rng_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_ed448ph_sign, struct lc_ed448_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed448_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	uint8_t rederived_pubkey[LC_ED448_PUBLICKEYBYTES];
	int ret = 0;

	(void)rng_ctx;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);

	lc_ed448_sign_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED448_SIGGEN);

	ed448_derive_public_key(rederived_pubkey, sk->sk);
	CKINT(curveed448_sign_internal(sig->sig, sk->sk, rederived_pubkey, msg,
				       mlen, 1, NULL));

out:
	lc_memset_secure(rederived_pubkey, 0, sizeof(rederived_pubkey));
	return ret;
}

int lc_ed448_sign_ctx(struct lc_ed448_sig *sig, const uint8_t *msg, size_t mlen,
		      const struct lc_ed448_sk *sk, struct lc_rng_ctx *rng_ctx,
		      struct lc_dilithium_ed448_ctx *composite_ml_dsa_ctx)
{
	uint8_t rederived_pubkey[LC_ED448_PUBLICKEYBYTES];
	int ret;

	(void)rng_ctx;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);

	ed448_derive_public_key(rederived_pubkey, sk->sk);
	CKINT(curveed448_sign_internal(sig->sig, sk->sk, rederived_pubkey, msg,
				       mlen, 0, composite_ml_dsa_ctx));

out:
	lc_memset_secure(rederived_pubkey, 0, sizeof(rederived_pubkey));
	return ret;
}

static int lc_ed448_verify_nocheck(const struct lc_ed448_sig *sig,
				   const uint8_t *msg, size_t mlen,
				   const struct lc_ed448_pk *pk);
/* Test vector obtained from NIST ACVP demo server */
static void lc_ed448_verify_tester(void)
{
	LC_FIPS_RODATA_SECTION
	static const struct lc_ed448_pk pk = {
		.pk = { 0x43, 0xba, 0x28, 0xf4, 0x30, 0xcd, 0xff, 0x45, 0x6a,
			0xe5, 0x31, 0x54, 0x5f, 0x7e, 0xcd, 0x0a, 0xc8, 0x34,
			0xa5, 0x5d, 0x93, 0x58, 0xc0, 0x37, 0x2b, 0xfa, 0x0c,
			0x6c, 0x67, 0x98, 0xc0, 0x86, 0x6a, 0xea, 0x01, 0xeb,
			0x00, 0x74, 0x28, 0x02, 0xb8, 0x43, 0x8e, 0xa4, 0xcb,
			0x82, 0x16, 0x9c, 0x23, 0x51, 0x60, 0x62, 0x7b, 0x4c,
			0x3a, 0x94, 0x80 }
	};
	LC_FIPS_RODATA_SECTION
	static const struct lc_ed448_sig sig = {
		.sig = { 0x26, 0xb8, 0xf9, 0x17, 0x27, 0xbd, 0x62, 0x89, 0x7a,
			 0xf1, 0x5e, 0x41, 0xeb, 0x43, 0xc3, 0x77, 0xef, 0xb9,
			 0xc6, 0x10, 0xd4, 0x8f, 0x23, 0x35, 0xcb, 0x0b, 0xd0,
			 0x08, 0x78, 0x10, 0xf4, 0x35, 0x25, 0x41, 0xb1, 0x43,
			 0xc4, 0xb9, 0x81, 0xb7, 0xe1, 0x8f, 0x62, 0xde, 0x8c,
			 0xcd, 0xf6, 0x33, 0xfc, 0x1b, 0xf0, 0x37, 0xab, 0x7c,
			 0xd7, 0x79, 0x80, 0x5e, 0x0d, 0xbc, 0xc0, 0xaa, 0xe1,
			 0xcb, 0xce, 0xe1, 0xaf, 0xb2, 0xe0, 0x27, 0xdf, 0x36,
			 0xbc, 0x04, 0xdc, 0xec, 0xbf, 0x15, 0x43, 0x36, 0xc1,
			 0x9f, 0x0a, 0xf7, 0xe0, 0xa6, 0x47, 0x29, 0x05, 0xe7,
			 0x99, 0xf1, 0x95, 0x3d, 0x2a, 0x0f, 0xf3, 0x34, 0x8a,
			 0xb2, 0x1a, 0xa4, 0xad, 0xaf, 0xd1, 0xd2, 0x34, 0x44,
			 0x1c, 0xf8, 0x07, 0xc0, 0x3a, 0x00 }
	};
	static const uint8_t msg[] = { 0x03 };
	int exp, ret;

	LC_SELFTEST_RUN(LC_ALG_STATUS_ED448_SIGVER);

	exp = 0;
	ret = lc_ed448_verify_nocheck(&sig, msg, sizeof(msg), &pk);
	lc_compare_selftest(LC_ALG_STATUS_ED448_SIGVER, (uint8_t *)&exp,
			    (uint8_t *)&ret, sizeof(exp),
			    "ED448 Signature verification\n");
}

static int
curveed448_verify(const uint8_t signature[LC_ED448_SIGBYTES],
		  const uint8_t pubkey[LC_ED448_PUBLICKEYBYTES],
		  const uint8_t *message, size_t message_len, uint8_t prehashed,
		  struct lc_dilithium_ed448_ctx *composite_ml_dsa_ctx)
{
	curve448_point_t pk_point, r_point;
	curve448_scalar_t challenge_scalar, response_scalar;
	struct lc_dilithium_ctx *dilithium_ctx = NULL;
	uint8_t challenge[2 * LC_ED448_SECRETKEYBYTES];
	int ret;
	LC_SHAKE_256_CTX_ON_STACK(shake256_ctx);

	if (composite_ml_dsa_ctx) {
		dilithium_ctx = &composite_ml_dsa_ctx->dilithium_ctx;

		if (!dilithium_ctx->nist_category)
			dilithium_ctx = NULL;
	}

	CKINT(curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point,
								pubkey));

	CKINT(curve448_point_decode_like_eddsa_and_mul_by_ratio(r_point,
								signature));

	/* Compute the challenge */
	CKINT(curveed448_hash_init_with_dom(shake256_ctx, prehashed, 0, NULL,
					    0));

	lc_hash_update(shake256_ctx, signature, LC_ED448_PUBLICKEYBYTES);
	lc_hash_update(shake256_ctx, pubkey, LC_ED448_PUBLICKEYBYTES);

	/* If Composite ML-DSA is requested, apply domain separation */
	if (dilithium_ctx) {
		CKINT(composite_signature_domain_separation(
			shake256_ctx, dilithium_ctx->userctx,
			dilithium_ctx->userctxlen, dilithium_ctx->randomizer,
			dilithium_ctx->randomizerlen,
			dilithium_ctx->nist_category));
	}

	lc_hash_update(shake256_ctx, message, message_len);

	lc_ed448_xof_final(shake256_ctx, challenge, sizeof(challenge));
	curve448_scalar_decode_long(challenge_scalar, challenge,
				    sizeof(challenge));

	curve448_scalar_sub(challenge_scalar, curve448_scalar_zero,
			    challenge_scalar);

	CKINT(curve448_scalar_decode(response_scalar,
				     &signature[LC_ED448_PUBLICKEYBYTES]));

	/* pk_point = -c(x(P)) + (cx + k)G = kG */
	CKINT(curve448_base_double_scalarmul_non_secret(
		pk_point, response_scalar, pk_point, challenge_scalar));

	ret = curve448_point_eq(pk_point, r_point) ? 0 : -EBADMSG;

out:
	lc_memset_secure(challenge, 0, sizeof(challenge));
	lc_hash_zero(shake256_ctx);
	return ret;
}

static int lc_ed448_verify_nocheck(const struct lc_ed448_sig *sig,
				   const uint8_t *msg, size_t mlen,
				   const struct lc_ed448_pk *pk)
{
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);

	CKINT(curveed448_verify(sig->sig, pk->pk, msg, mlen, 0, NULL));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_ed448_verify, const struct lc_ed448_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed448_pk *pk)
{
	lc_ed448_verify_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED448_SIGVER);

	return lc_ed448_verify_nocheck(sig, msg, mlen, pk);
}

LC_INTERFACE_FUNCTION(int, lc_ed448ph_verify, const struct lc_ed448_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed448_pk *pk)
{
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);

	CKINT(curveed448_verify(sig->sig, pk->pk, msg, mlen, 1, NULL));

out:
	return ret;
}

int lc_ed448_verify_ctx(const struct lc_ed448_sig *sig, const uint8_t *msg,
			size_t mlen, const struct lc_ed448_pk *pk,
			struct lc_dilithium_ed448_ctx *composite_ml_dsa_ctx)
{
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);

	CKINT(curveed448_verify(sig->sig, pk->pk, msg, mlen, 0,
				composite_ml_dsa_ctx));

out:
	return ret;
}
