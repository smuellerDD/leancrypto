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

#include "lc_ed448.h"
#include "lc_memcmp_secure.h"
#include "lc_sha3.h"
#include "point_448.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

#define EDDSA_USE_SIGMA_ISOGENY 0
#define COFACTOR 4
#define EDDSA_PREHASH_BYTES 64

static void clamp(uint8_t secret_scalar_ser[LC_ED448_SECRETKEYBYTES])
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

static void hash_init_with_dom(struct lc_hash_ctx *hash_ctx, uint8_t prehashed,
			       uint8_t for_prehash, const uint8_t *context,
			       uint8_t context_len)
{
	lc_hash_init(hash_ctx);

	const char *dom_s = "SigEd448";
	const uint8_t dom[2] = { (uint8_t)(2 + word_is_zero(prehashed) +
					   word_is_zero(for_prehash)),
				 context_len };
	lc_hash_update(hash_ctx, (const unsigned char *)dom_s, strlen(dom_s));
	lc_hash_update(hash_ctx, dom, 2);
	lc_hash_update(hash_ctx, context, context_len);
}

#define DECAF_448_EDDSA_ENCODE_RATIO 4
static void
ed448_derive_public_key(uint8_t pubkey[LC_ED448_PUBLICKEYBYTES],
			const uint8_t privkey[LC_ED448_SECRETKEYBYTES])
{
	/* only this much used for keygen */
	uint8_t secret_scalar_ser[LC_ED448_SECRETKEYBYTES];

	lc_xof(lc_shake256, privkey, LC_ED448_SECRETKEYBYTES, secret_scalar_ser,
	       sizeof(secret_scalar_ser));
	clamp(secret_scalar_ser);

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
	lc_memset_secure(secret_scalar_ser, 0, sizeof(secret_scalar_ser));
}

LC_INTERFACE_FUNCTION(int, lc_ed448_keypair, struct lc_ed448_pk *pk,
		      struct lc_ed448_sk *sk, struct lc_rng_ctx *rng_ctx)
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

out:
	return ret;
}

static inline void lc_ed448_xof_final(struct lc_hash_ctx *xof_ctx,
				      uint8_t *digest, size_t digest_len)
{
	lc_hash_set_digestsize(xof_ctx, digest_len);
	lc_hash_final(xof_ctx, digest);
	lc_hash_zero(xof_ctx);
}

static void
curveed448_sign_internal(uint8_t signature[LC_ED448_SIGBYTES],
			 const uint8_t privkey[LC_ED448_SECRETKEYBYTES],
			 const uint8_t pubkey[LC_ED448_PUBLICKEYBYTES],
			 const uint8_t *message, size_t message_len,
			 uint8_t prehashed, const uint8_t *context,
			 uint8_t context_len)
{
	curve448_scalar_t secret_scalar;
	LC_SHAKE_256_CTX_ON_STACK(shake256_ctx);

	/* Timecop: mark the secret key as sensitive */
	poison(privkey, LC_ED448_SECRETKEYBYTES);

	{
		/* Schedule the secret key */
		struct {
			uint8_t secret_scalar_ser[LC_ED448_SECRETKEYBYTES];
			uint8_t seed[LC_ED448_SECRETKEYBYTES];
		} __attribute__((packed)) expanded;

		lc_hash_init(shake256_ctx);
		lc_hash_update(shake256_ctx, privkey, LC_ED448_SECRETKEYBYTES);
		lc_ed448_xof_final(shake256_ctx, (uint8_t *)&expanded,
				   sizeof(expanded));

		/*
		 * Once the private key is hashed, you cannot deduct it from
		 * the message digest, thus unpoison it.
		 */
		unpoison(&expanded, sizeof(expanded));

		clamp(expanded.secret_scalar_ser);
		curve448_scalar_decode_long(secret_scalar,
					    expanded.secret_scalar_ser,
					    sizeof(expanded.secret_scalar_ser));

		/* Hash to create the nonce */
		hash_init_with_dom(shake256_ctx, prehashed, 0, context,
				   context_len);
		lc_hash_update(shake256_ctx, expanded.seed,
			       sizeof(expanded.seed));
		lc_hash_update(shake256_ctx, message, message_len);
		lc_memset_secure(&expanded, 0, sizeof(expanded));
	}

	/* Decode the nonce */
	curve448_scalar_t nonce_scalar;
	{
		uint8_t nonce[2 * LC_ED448_SECRETKEYBYTES];
		lc_ed448_xof_final(shake256_ctx, nonce, sizeof(nonce));
		curve448_scalar_decode_long(nonce_scalar, nonce, sizeof(nonce));
		lc_memset_secure(nonce, 0, sizeof(nonce));
	}

	uint8_t nonce_point[LC_ED448_PUBLICKEYBYTES] = { 0 };
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

	curve448_scalar_t challenge_scalar;
	{
		/* Compute the challenge */
		hash_init_with_dom(shake256_ctx, prehashed, 0, context,
				   context_len);
		lc_hash_update(shake256_ctx, nonce_point, sizeof(nonce_point));
		lc_hash_update(shake256_ctx, pubkey, LC_ED448_PUBLICKEYBYTES);
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
	memcpy(signature, nonce_point, sizeof(nonce_point));
	curve448_scalar_encode(&signature[LC_ED448_PUBLICKEYBYTES],
			       challenge_scalar);

	curve448_scalar_destroy(secret_scalar);
	curve448_scalar_destroy(nonce_scalar);
	curve448_scalar_destroy(challenge_scalar);

	/* Timecop: sig and sk are not relevant for side-channels any more. */
	unpoison(signature, LC_ED448_SIGBYTES);
	unpoison(privkey, LC_ED448_SECRETKEYBYTES);
}

LC_INTERFACE_FUNCTION(int, lc_ed448_sign, struct lc_ed448_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed448_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	uint8_t rederived_pubkey[LC_ED448_PUBLICKEYBYTES];
	int ret = 0;

	(void)rng_ctx;

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);

	ed448_derive_public_key(rederived_pubkey, sk->sk);
	curveed448_sign_internal(sig->sig, sk->sk, rederived_pubkey, msg, mlen,
				 0, NULL, 0);

out:
	return ret;
}

#if 0
void curveed448_keypair_sign_prehash (
    uint8_t signature[LC_ED448_SIGBYTES],
    const curveeddsa_448_keypair_t keypair,
    const curveed448_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) {
    uint8_t hash_output[EDDSA_PREHASH_BYTES];
    {
        curveed448_prehash_ctx_t hash_too;
        memcpy(hash_too,hash,sizeof(hash_too));
        hash_final(hash_too,hash_output,sizeof(hash_output));
        hash_destroy(hash_too);
    }

    curveed448_sign_internal(signature,keypair->privkey,keypair->pubkey,hash_output,
        sizeof(hash_output),1,context,context_len);
    curvebzero(hash_output,sizeof(hash_output));
}
#endif

static int curveed448_verify(const uint8_t signature[LC_ED448_SIGBYTES],
			     const uint8_t pubkey[LC_ED448_PUBLICKEYBYTES],
			     const uint8_t *message, size_t message_len,
			     uint8_t prehashed, const uint8_t *context,
			     uint8_t context_len)
{
	curve448_point_t pk_point, r_point;
	int ret;

	CKINT(curve448_point_decode_like_eddsa_and_mul_by_ratio(pk_point,
								pubkey));

	CKINT(curve448_point_decode_like_eddsa_and_mul_by_ratio(r_point,
								signature));

	curve448_scalar_t challenge_scalar;
	{
		/* Compute the challenge */
		LC_SHAKE_256_CTX_ON_STACK(shake256_ctx);
		hash_init_with_dom(shake256_ctx, prehashed, 0, context,
				   context_len);
		lc_hash_update(shake256_ctx, signature,
			       LC_ED448_PUBLICKEYBYTES);
		lc_hash_update(shake256_ctx, pubkey, LC_ED448_PUBLICKEYBYTES);
		lc_hash_update(shake256_ctx, message, message_len);
		uint8_t challenge[2 * LC_ED448_SECRETKEYBYTES];
		lc_ed448_xof_final(shake256_ctx, challenge, sizeof(challenge));
		curve448_scalar_decode_long(challenge_scalar, challenge,
					    sizeof(challenge));
		lc_memset_secure(challenge, 0, sizeof(challenge));
	}
	curve448_scalar_sub(challenge_scalar, curve448_scalar_zero,
			    challenge_scalar);

	curve448_scalar_t response_scalar;
	CKINT(curve448_scalar_decode(response_scalar,
				     &signature[LC_ED448_PUBLICKEYBYTES]));

#if 0
#if DECAF_448_SCALAR_BYTES < LC_ED448_SECRETKEYBYTES
	for (unsigned i = DECAF_448_SCALAR_BYTES; i < LC_ED448_SECRETKEYBYTES;
	     i++) {
		if (signature[LC_ED448_PUBLICKEYBYTES + i] != 0x00) {
			return DECAF_FAILURE;
		}
	}
#endif
#endif
#define DECAF_448_EDDSA_DECODE_RATIO (4 / 4)
	for (unsigned c = 1; c < DECAF_448_EDDSA_DECODE_RATIO; c <<= 1) {
		curve448_scalar_add(response_scalar, response_scalar,
				    response_scalar);
	}

	/* pk_point = -c(x(P)) + (cx + k)G = kG */
	curve448_base_double_scalarmul_non_secret(pk_point, response_scalar,
						  pk_point, challenge_scalar);

	ret = curve448_point_eq(pk_point, r_point) ? 0 : -EFAULT;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_ed448_verify, const struct lc_ed448_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed448_pk *pk)
{
	int ret;

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);

	if (!curveed448_verify(sig->sig, pk->pk, msg, mlen, 0, NULL, 0))
		return 0;

	ret = -EBADMSG;

out:
	return ret;
}

#if 0
curveerror_t curveed448_verify_prehash (
    const uint8_t signature[LC_ED448_SIGBYTES],
    const uint8_t pubkey[LC_ED448_PUBLICKEYBYTES],
    const curveed448_prehash_ctx_t hash,
    const uint8_t *context,
    uint8_t context_len
) {
    curveerror_t ret;

    uint8_t hash_output[EDDSA_PREHASH_BYTES];
    {
        curveed448_prehash_ctx_t hash_too;
        memcpy(hash_too,hash,sizeof(hash_too));
        hash_final(hash_too,hash_output,sizeof(hash_output));
        hash_destroy(hash_too);
    }

    ret = curveed448_verify(signature,pubkey,hash_output,sizeof(hash_output),1,context,context_len);

    return ret;
}
#endif
