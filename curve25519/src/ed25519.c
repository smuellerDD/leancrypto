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
 * This code is derived in parts from the code distribution provided with
 * https://github.com/jedisct1/libsodium.git
 *
 * That code is released under ISC License
 *
 * Copyright (c) 2013-2023 - 2025
 * Frank Denis <j at pureftpd dot org>
 */

#include "compare.h"
#include "ed25519_composite.h"
#include "ed25519_pct.h"
#include "fips_mode.h"
#include "lc_ed25519.h"
#include "ed25519_ref10.h"
#include "ext_headers_internal.h"
#include "lc_sha512.h"
#include "ret_checkers.h"
#include "selftest_rng.h"
#include "signature_domain_separation.h"
#include "timecop.h"
#include "visibility.h"

static int lc_ed25519_keypair_nocheck(struct lc_ed25519_pk *pk,
				      struct lc_ed25519_sk *sk,
				      struct lc_rng_ctx *rng_ctx);
static void lc_ed25519_keypair_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const uint8_t sk_exp[] = { FIPS140_MOD(0x7f),
					  0x9c,
					  0x2b,
					  0xa4,
					  0xe8,
					  0x8f,
					  0x82,
					  0x7d,
					  0x61,
					  0x60,
					  0x45,
					  0x50,
					  0x76,
					  0x05,
					  0x85,
					  0x3e,
					  0xd7,
					  0x3b,
					  0x80,
					  0x93,
					  0xf6,
					  0xef,
					  0xbc,
					  0x88,
					  0xeb,
					  0x1a,
					  0x6e,
					  0xac,
					  0xfa,
					  0x66,
					  0xef,
					  0x26,
					  0xa1,
					  0xa6,
					  0xe4,
					  0xd8,
					  0x85,
					  0xce,
					  0x8e,
					  0x12,
					  0x05,
					  0x02,
					  0xb0,
					  0x19,
					  0x08,
					  0x1b,
					  0xd3,
					  0x1b,
					  0x24,
					  0x82,
					  0x0b,
					  0xac,
					  0x05,
					  0xa7,
					  0xc8,
					  0xf3,
					  0x64,
					  0x86,
					  0x2b,
					  0xb5,
					  0x31,
					  0x96,
					  0x3c,
					  0x8d };
	LC_FIPS_RODATA_SECTION
	static const uint8_t pk_exp[] = { 0xa1, 0xa6, 0xe4, 0xd8, 0x85, 0xce,
					  0x8e, 0x12, 0x05, 0x02, 0xb0, 0x19,
					  0x08, 0x1b, 0xd3, 0x1b, 0x24, 0x82,
					  0x0b, 0xac, 0x05, 0xa7, 0xc8, 0xf3,
					  0x64, 0x86, 0x2b, 0xb5, 0x31, 0x96,
					  0x3c, 0x8d };
	struct lc_ed25519_pk pk;
	struct lc_ed25519_sk sk;
	int ret;
	LC_SELFTEST_DRNG_CTX_ON_STACK(selftest_rng);

	LC_SELFTEST_RUN(LC_ALG_STATUS_ED25519_KEYGEN);

	lc_ed25519_keypair_nocheck(&pk, &sk, selftest_rng);
	if (lc_compare_selftest(LC_ALG_STATUS_ED25519_KEYGEN, pk.pk, pk_exp,
				sizeof(pk_exp), "ED25519 keypair pubkey\n"))
		return;

out:
	lc_compare_selftest(LC_ALG_STATUS_ED25519_KEYGEN, sk.sk, sk_exp,
			    sizeof(sk_exp), "ED25519 keypair seckey\n");
}

static int lc_ed25519_keypair_nocheck(struct lc_ed25519_pk *pk,
				      struct lc_ed25519_sk *sk,
				      struct lc_rng_ctx *rng_ctx)
{
	ge25519_p3 A;
	uint8_t tmp[LC_SHA512_SIZE_DIGEST];
	int ret;

	CKNULL(sk, -EINVAL);
	CKNULL(pk, -EINVAL);

	lc_rng_check(&rng_ctx);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, sk->sk, 32));

	/* Timecop: the random number is the sentitive data */
	poison(sk->sk, 32);

	CKINT(lc_hash(lc_sha512, sk->sk, 32, tmp));
	tmp[0] &= 248;
	tmp[31] &= 127;
	tmp[31] |= 64;

	ge25519_scalarmult_base(&A, tmp);
	lc_memset_secure(tmp, 0, sizeof(tmp));
	ge25519_p3_tobytes(pk->pk, &A);

	memcpy(sk->sk + 32, pk->pk, 32);

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(sk->sk, sizeof(sk->sk));
	unpoison(pk->pk, sizeof(pk->pk));

	CKINT(lc_ed25519_pct_fips(pk, sk));

out:
	lc_memset_secure(&A, 0, sizeof(A));
	lc_memset_secure(tmp, 0, sizeof(tmp));
	return ret;
}

/* Export for test purposes */
LC_INTERFACE_FUNCTION(int, lc_ed25519_keypair, struct lc_ed25519_pk *pk,
		      struct lc_ed25519_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	lc_ed25519_keypair_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED25519_KEYGEN);

	return lc_ed25519_keypair_nocheck(pk, sk, rng_ctx);
}

static int lc_ed25519_sign_internal(
	struct lc_ed25519_sig *sig, int prehash, const uint8_t *msg,
	size_t mlen, const struct lc_ed25519_sk *sk, struct lc_rng_ctx *rng_ctx,
	struct lc_dilithium_ed25519_ctx *composite_ml_dsa_ctx);
/* Test vector generated with libsodium using the ACVP parser tool */
static void lc_ed25519_sign_tester(void)
{
	LC_FIPS_RODATA_SECTION
	static const struct lc_ed25519_sk sk = { .sk = { FIPS140_MOD(0x42),
							 0x58,
							 0x0d,
							 0x49,
							 0xbe,
							 0x95,
							 0x1f,
							 0x95,
							 0xdf,
							 0xca,
							 0x13,
							 0x60,
							 0xda,
							 0x43,
							 0x09,
							 0x58,
							 0xd9,
							 0x30,
							 0xc7,
							 0xa1,
							 0x71,
							 0xbd,
							 0xa0,
							 0x99,
							 0x92,
							 0x5a,
							 0xb5,
							 0xb7,
							 0xcd,
							 0x88,
							 0x51,
							 0xae,
							 0x5d,
							 0x10,
							 0xd0,
							 0x95,
							 0x66,
							 0xa2,
							 0xd8,
							 0x75,
							 0xea,
							 0xcf,
							 0xa0,
							 0x87,
							 0x73,
							 0x9a,
							 0xcd,
							 0xb9,
							 0x5c,
							 0xfb,
							 0xfa,
							 0x94,
							 0x05,
							 0x5a,
							 0x14,
							 0xd7,
							 0x59,
							 0x0b,
							 0xd4,
							 0xb1,
							 0x06,
							 0xe8,
							 0x09,
							 0xbd } };
	LC_FIPS_RODATA_SECTION
	static const struct lc_ed25519_sig exp_sig = {
		.sig = { 0xb6, 0x53, 0xe0, 0x0b, 0xf2, 0x07, 0xd1, 0x83,
			 0xdd, 0x7b, 0xef, 0x59, 0xaa, 0x7b, 0x23, 0xb5,
			 0xfe, 0x76, 0x9c, 0x2a, 0x6b, 0xf2, 0x10, 0xd6,
			 0xa7, 0xa2, 0x17, 0xf2, 0xb1, 0xa5, 0x5d, 0xd6,
			 0x92, 0xdf, 0xec, 0x22, 0xf0, 0x18, 0xac, 0x7f,
			 0x21, 0x9c, 0xe1, 0xb8, 0x74, 0x30, 0x9d, 0xe9,
			 0xa4, 0x2d, 0x1b, 0x89, 0x1c, 0xb3, 0xb9, 0x47,
			 0xb8, 0xc6, 0xbb, 0xd4, 0xcf, 0xb7, 0xa4, 0x0b }
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t msg[] = {
		0x67, 0xB1, 0x9B, 0xA7, 0x05, 0xCF, 0xEE, 0x74, 0x82, 0x10,
		0xCC, 0xB6, 0x98, 0xFF, 0x84, 0xBC, 0x8C, 0x59, 0x8E, 0x45,
		0x26, 0x2C, 0x39, 0xDF, 0xB7, 0x8B, 0xAA, 0x9A, 0x4E, 0xA9,
		0x6C, 0x83, 0x46, 0x65, 0x84, 0x92, 0x7E, 0xD2, 0x90, 0xB3,
		0x9E, 0x80, 0x18, 0xC8, 0x4B, 0xEB, 0x84, 0x24, 0x82, 0x00,
		0x83, 0x2F, 0xC4, 0x69, 0xE1, 0xEC, 0x44, 0x19, 0x7A, 0x96,
		0x82, 0x8C, 0xF4, 0x9B, 0xD9, 0x18, 0xA2, 0x1D, 0x24, 0x07,
		0xBC, 0x0F, 0x89, 0x53, 0xAE, 0x07, 0x18, 0x7D, 0xF9, 0x31,
		0x21, 0x2D, 0x26, 0x43, 0x45, 0x46, 0x9B, 0xE9, 0x82, 0xA8,
		0x99, 0x3A, 0xE2, 0x19, 0x06, 0x4C, 0x87, 0x31, 0x46, 0x44,
		0x1D, 0xA5, 0x51, 0xA9, 0x43, 0xC8, 0x75, 0x60, 0x52, 0x63,
		0x94, 0xDD, 0x54, 0x5C, 0xAF, 0x88, 0xD9, 0x7C, 0xCD, 0x1F,
		0x5D, 0xC0, 0xC3, 0x76, 0xB0, 0x00, 0xD7, 0xFE
	};
	struct lc_ed25519_sig sig;

	LC_SELFTEST_RUN(LC_ALG_STATUS_ED25519_SIGGEN);

	lc_ed25519_sign_internal(&sig, 0, msg, sizeof(msg), &sk, NULL, NULL);
	lc_compare_selftest(LC_ALG_STATUS_ED25519_SIGGEN, sig.sig, exp_sig.sig,
			    sizeof(exp_sig.sig),
			    "ED25519 Signature generation\n");
}

static inline void lc_ed25519_dom2(struct lc_hash_ctx *hash_ctx, int prehash)
{
	/* Label + phflag = 1 + size of context */
	LC_FIPS_RODATA_SECTION
	static const uint8_t label[] = { 'S', 'i', 'g', 'E', 'd', '2', '5',
					 '5', '1', '9', ' ', 'n', 'o', ' ',
					 'E', 'd', '2', '5', '5', '1', '9',
					 ' ', 'c', 'o', 'l', 'l', 'i', 's',
					 'i', 'o', 'n', 's', 1,	  0 };

	if (!prehash)
		return;

	lc_hash_update(hash_ctx, label, sizeof(label));
}

static int lc_ed25519_sign_internal(
	struct lc_ed25519_sig *sig, int prehash, const uint8_t *msg,
	size_t mlen, const struct lc_ed25519_sk *sk, struct lc_rng_ctx *rng_ctx,
	struct lc_dilithium_ed25519_ctx *composite_ml_dsa_ctx)
{
	uint8_t az[LC_SHA512_SIZE_DIGEST];
	uint8_t nonce[LC_SHA512_SIZE_DIGEST];
	uint8_t hram[LC_SHA512_SIZE_DIGEST];
	ge25519_p3 R;
	struct lc_dilithium_ctx *dilithium_ctx = NULL;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha512);

	CKNULL(sig, -EINVAL);
	CKNULL(sk, -EINVAL);

	if (composite_ml_dsa_ctx) {
		dilithium_ctx = &composite_ml_dsa_ctx->dilithium_ctx;

		if (!dilithium_ctx->nist_category)
			dilithium_ctx = NULL;
	}

	/* Timecop: mark the secret key as sensitive */
	poison(sk->sk, sizeof(sk->sk));

	CKINT(lc_hash(lc_sha512, sk->sk, 32, az));

	CKINT(lc_hash_init(hash_ctx));
	lc_ed25519_dom2(hash_ctx, prehash);

	if (rng_ctx) {
		/* r = hash(k || K || noise || pad || M) (mod q) */
		lc_hash_update(hash_ctx, az, LC_SHA512_SIZE_DIGEST);
		CKINT(lc_rng_generate(rng_ctx, NULL, 0, nonce, 32));
		memset(nonce + 32, 0, 32);
		lc_hash_update(hash_ctx, nonce, sizeof(nonce));
	} else {
		lc_hash_update(hash_ctx, az + 32, 32);
	}

	/* If Composite ML-DSA is requested, apply domain separation */
	if (dilithium_ctx) {
		CKINT(composite_signature_domain_separation(
			hash_ctx, dilithium_ctx->userctx,
			dilithium_ctx->userctxlen, dilithium_ctx->randomizer,
			dilithium_ctx->randomizerlen,
			dilithium_ctx->nist_category));
	}

	lc_hash_update(hash_ctx, msg, mlen);
	lc_hash_final(hash_ctx, nonce);

	memcpy(sig->sig + 32, sk->sk + 32, 32);

	sc25519_reduce(nonce);
	ge25519_scalarmult_base(&R, nonce);
	ge25519_p3_tobytes(sig->sig, &R);

	CKINT(lc_hash_init(hash_ctx));
	lc_ed25519_dom2(hash_ctx, prehash);
	lc_hash_update(hash_ctx, sig->sig, LC_ED25519_SIGBYTES);

	/* If Composite ML-DSA is requested, apply domain separation */
	if (dilithium_ctx) {
		CKINT(composite_signature_domain_separation(
			hash_ctx, dilithium_ctx->userctx,
			dilithium_ctx->userctxlen, dilithium_ctx->randomizer,
			dilithium_ctx->randomizerlen,
			dilithium_ctx->nist_category));
	}

	lc_hash_update(hash_ctx, msg, mlen);
	lc_hash_final(hash_ctx, hram);

	sc25519_reduce(hram);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	sc25519_muladd(sig->sig + 32, hram, az, nonce);

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(sig->sig, LC_ED25519_SIGBYTES);

out:
	lc_memset_secure(az, 0, sizeof(az));
	lc_memset_secure(nonce, 0, sizeof(nonce));
	lc_memset_secure(hram, 0, sizeof(hram));
	lc_memset_secure(&R, 0, sizeof(R));
	lc_hash_zero(hash_ctx);
	return ret;
}

int lc_ed25519_sign_ctx(struct lc_ed25519_sig *sig, const uint8_t *msg,
			size_t mlen, const struct lc_ed25519_sk *sk,
			struct lc_rng_ctx *rng_ctx,
			struct lc_dilithium_ed25519_ctx *composite_ml_dsa_ctx)
{
	lc_ed25519_sign_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED25519_SIGGEN);

	return lc_ed25519_sign_internal(sig, 0, msg, mlen, sk, rng_ctx,
					composite_ml_dsa_ctx);
}

/* Export for test purposes */
LC_INTERFACE_FUNCTION(int, lc_ed25519_sign, struct lc_ed25519_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	lc_ed25519_sign_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED25519_SIGGEN);

	return lc_ed25519_sign_internal(sig, 0, msg, mlen, sk, rng_ctx, NULL);
}

LC_INTERFACE_FUNCTION(int, lc_ed25519ph_sign, struct lc_ed25519_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed25519_sk *sk,
		      struct lc_rng_ctx *rng_ctx)
{
	lc_ed25519_sign_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED25519_SIGGEN);

	return lc_ed25519_sign_internal(sig, 1, msg, mlen, sk, rng_ctx, NULL);
}

static int lc_ed25519_verify_internal(
	const struct lc_ed25519_sig *sig, int prehash, const uint8_t *msg,
	size_t mlen, const struct lc_ed25519_pk *pk,
	struct lc_dilithium_ed25519_ctx *composite_ml_dsa_ctx);
/* Test vector obtained from NIST ACVP demo server */
static void lc_ed25519_verify_tester(void)
{
	LC_FIPS_RODATA_SECTION
	static const struct lc_ed25519_pk pk = { .pk = { FIPS140_MOD(0xDE),
							 0xE0,
							 0x76,
							 0xAD,
							 0x68,
							 0xDC,
							 0x56,
							 0x56,
							 0xAA,
							 0x3E,
							 0xF7,
							 0x93,
							 0x37,
							 0xFD,
							 0xFD,
							 0x3E,
							 0x4F,
							 0x8D,
							 0xB9,
							 0x4A,
							 0xFF,
							 0xEE,
							 0xF4,
							 0xEA,
							 0xDA,
							 0xA8,
							 0x08,
							 0x1D,
							 0x00,
							 0x6E,
							 0x5A,
							 0xC0 } };
	LC_FIPS_RODATA_SECTION
	static const struct lc_ed25519_sig sig = {
		.sig = { 0x9F, 0xB9, 0x57, 0x68, 0xE6, 0x87, 0x91, 0xFC,
			 0xD6, 0x04, 0xF0, 0x68, 0x5F, 0x57, 0xC4, 0x33,
			 0xEF, 0xBE, 0x0A, 0xE6, 0x6F, 0x89, 0x90, 0xA1,
			 0xB1, 0xFF, 0x62, 0xA2, 0x50, 0x7F, 0xB2, 0xA0,
			 0xEA, 0xB7, 0x6C, 0xDD, 0x37, 0x3B, 0x9C, 0x20,
			 0x5E, 0x15, 0x63, 0xF4, 0xA9, 0xAE, 0xCB, 0x25,
			 0x61, 0xDF, 0xAD, 0x89, 0x61, 0xC5, 0x73, 0xB8,
			 0xC8, 0x34, 0x24, 0xF6, 0x47, 0x56, 0x79, 0x08 }
	};
	LC_FIPS_RODATA_SECTION
	static const uint8_t msg[] = {
		0xA6, 0x3D, 0xEB, 0x88, 0x01, 0x0E, 0xFD, 0x0B, 0x43, 0x92,
		0x48, 0x38, 0x12, 0xF5, 0x03, 0xA9, 0xD1, 0x99, 0xA9, 0xCF,
		0xA7, 0x08, 0x5F, 0x68, 0x31, 0xFE, 0xE3, 0x21, 0xA9, 0x28,
		0x46, 0x8E, 0x55, 0x74, 0x26, 0x7E, 0xB2, 0xBD, 0x9C, 0xB8,
		0x1E, 0xD3, 0x7A, 0x88, 0xF2, 0x18, 0x0D, 0x8D, 0x6A, 0x07,
		0xD9, 0xC5, 0x87, 0xFF, 0xB1, 0xCD, 0xBB, 0x9E, 0x46, 0x9D,
		0xC6, 0x1C, 0xDE, 0xBE, 0x1A, 0x3A, 0x51, 0x1F, 0x82, 0x6E,
		0xB0, 0xAA, 0x5F, 0x30, 0xCF, 0x58, 0xD5, 0x1B, 0x06, 0x77,
		0x9C, 0xAA, 0x3D, 0x88, 0xE6, 0x61, 0xC9, 0xA6, 0x94, 0xA9,
		0xEC, 0x63, 0x68, 0xFB, 0xE9, 0xEE, 0x2C, 0x4F, 0xA3, 0xF9,
		0x8F, 0xAA, 0x38, 0xA7, 0x8F, 0xBF, 0x26, 0x50, 0xA6, 0x45,
		0x76, 0xA7, 0x01, 0xAE, 0x99, 0xB0, 0x0A, 0x0A, 0x0D, 0xBE,
		0x34, 0xE1, 0xC9, 0xBB, 0x15, 0x40, 0x6A, 0x86
	};
	int exp, ret;

	LC_SELFTEST_RUN(LC_ALG_STATUS_ED25519_SIGVER);

	exp = 0;
	ret = lc_ed25519_verify_internal(&sig, 0, msg, sizeof(msg), &pk, NULL);
	lc_compare_selftest(LC_ALG_STATUS_ED25519_SIGVER, (uint8_t *)&exp,
			    (uint8_t *)&ret, sizeof(exp),
			    "ED25519 Signature verification\n");
}

static int lc_ed25519_verify_internal(
	const struct lc_ed25519_sig *sig, int prehash, const uint8_t *msg,
	size_t mlen, const struct lc_ed25519_pk *pk,
	struct lc_dilithium_ed25519_ctx *composite_ml_dsa_ctx)
{
	uint8_t h[LC_SHA512_SIZE_DIGEST];
	ge25519_p3 check;
	ge25519_p3 expected_r;
	ge25519_p3 A;
	ge25519_p3 sb_ah;
	ge25519_p2 sb_ah_p2;
	struct lc_dilithium_ctx *dilithium_ctx = NULL;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha512);

	CKNULL(sig, -EINVAL);
	CKNULL(pk, -EINVAL);

	if (composite_ml_dsa_ctx) {
		dilithium_ctx = &composite_ml_dsa_ctx->dilithium_ctx;

		if (!dilithium_ctx->nist_category)
			dilithium_ctx = NULL;
	}

#if 0
	//ED25519_COMPAT
	if (sig->sig[63] & 224) {
		ret = -EINVAL;
		goto out;
	}
#else
	if ((sig->sig[63] & 240) != 0 &&
	    sc25519_is_canonical(sig->sig + 32) == 0) {
		ret = -EINVAL;
		goto out;
	}
	if (ge25519_is_canonical(pk->pk) == 0) {
		ret = -EINVAL;
		goto out;
	}
#endif
	if (ge25519_frombytes_negate_vartime(&A, pk->pk) != 0 ||
	    ge25519_has_small_order(&A) != 0) {
		ret = -EINVAL;
		goto out;
	}
	if (ge25519_frombytes(&expected_r, sig->sig) != 0 ||
	    ge25519_has_small_order(&expected_r) != 0) {
		ret = -EINVAL;
		goto out;
	}

	CKINT(lc_hash_init(hash_ctx));
	lc_ed25519_dom2(hash_ctx, prehash);
	lc_hash_update(hash_ctx, sig->sig, 32);
	lc_hash_update(hash_ctx, pk->pk, LC_ED25519_PUBLICKEYBYTES);

	/* If Composite ML-DSA is requested, apply domain separation */
	if (dilithium_ctx) {
		CKINT(composite_signature_domain_separation(
			hash_ctx, dilithium_ctx->userctx,
			dilithium_ctx->userctxlen, dilithium_ctx->randomizer,
			dilithium_ctx->randomizerlen,
			dilithium_ctx->nist_category));
	}

	lc_hash_update(hash_ctx, msg, mlen);
	lc_hash_final(hash_ctx, h);
	lc_hash_zero(hash_ctx);
	sc25519_reduce(h);

	ge25519_double_scalarmult_vartime(&sb_ah_p2, h, &A, sig->sig + 32);
	ge25519_p2_to_p3(&sb_ah, &sb_ah_p2);
	ge25519_p3_sub(&check, &expected_r, &sb_ah);

	if ((ge25519_has_small_order(&check) - 1) != 0)
		ret = -EBADMSG;

out:
	lc_memset_secure(h, 0, sizeof(h));
	lc_memset_secure(&check, 0, sizeof(check));
	lc_memset_secure(&expected_r, 0, sizeof(expected_r));
	lc_memset_secure(&A, 0, sizeof(A));
	lc_memset_secure(&sb_ah, 0, sizeof(sb_ah));
	lc_memset_secure(&sb_ah_p2, 0, sizeof(sb_ah_p2));
	lc_hash_zero(hash_ctx);
	return ret;
}

int lc_ed25519_verify_ctx(const struct lc_ed25519_sig *sig, const uint8_t *msg,
			  size_t mlen, const struct lc_ed25519_pk *pk,
			  struct lc_dilithium_ed25519_ctx *composite_ml_dsa_ctx)
{
	lc_ed25519_verify_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED25519_SIGVER);

	return lc_ed25519_verify_internal(sig, 0, msg, mlen, pk,
					  composite_ml_dsa_ctx);
}

/* Export for test purposes */
LC_INTERFACE_FUNCTION(int, lc_ed25519_verify, const struct lc_ed25519_sig *sig,
		      const uint8_t *msg, size_t mlen,
		      const struct lc_ed25519_pk *pk)
{
	lc_ed25519_verify_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED25519_SIGVER);

	return lc_ed25519_verify_internal(sig, 0, msg, mlen, pk, NULL);
}

LC_INTERFACE_FUNCTION(int, lc_ed25519ph_verify,
		      const struct lc_ed25519_sig *sig, const uint8_t *msg,
		      size_t mlen, const struct lc_ed25519_pk *pk)
{
	lc_ed25519_verify_tester();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_ED25519_SIGVER);

	return lc_ed25519_verify_internal(sig, 1, msg, mlen, pk, NULL);
}
