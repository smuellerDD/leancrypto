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

#include "compare.h"
#include "ext_headers_internal.h"
#include "fips_mode.h"
#include "lc_x448.h"
#include "ret_checkers.h"
#include "static_rng.h"
#include "timecop.h"
#include "visibility.h"
#include "x448_scalarmult.h"

static int lc_x448_keypair_nocheck(struct lc_x448_pk *pk,
				   struct lc_x448_sk *sk,
				   struct lc_rng_ctx *rng_ctx);
static void lc_x448_keypair_selftest(void)
{
	/* Test vector obtained from RFC 7748 section 6.2. */
	LC_FIPS_RODATA_SECTION
	static const struct lc_x448_sk sk_orig = {
		.sk = { 0x9a, FIPS140_MOD(0x8f), 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57,
			0x75, 0xcf, 0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4,
			0xee, 0x9e, 0xe8, 0xba, 0xe8, 0xbc, 0x55, 0x65,
			0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9, 0xba, 0xf5,
			0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
			0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d,
			0x9a, 0xc2, 0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b }
	};
	LC_FIPS_RODATA_SECTION
	static const struct lc_x448_pk pk_orig = {
		.pk = { 0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6,
			0x7d, 0x22, 0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a,
			0x27, 0x3b, 0xd2, 0xb8, 0x3d, 0xe0, 0x9c, 0x63,
			0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5, 0xd9, 0xbb,
			0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
			0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53,
			0x17, 0x7f, 0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0 }
	};
	struct lc_static_rng_data static_data = {
		.seed = sk_orig.sk,
		.seedlen = LC_X448_SECRETKEYBYTES,
	};
	LC_STATIC_DRNG_ON_STACK(static_drng, &static_data);
	struct lc_x448_pk pk;
	struct lc_x448_sk sk;

	LC_SELFTEST_RUN(LC_ALG_STATUS_X448_KEYGEN);

	if (lc_x448_keypair_nocheck(&pk, &sk, &static_drng))
		goto out;

	if (lc_compare_selftest(LC_ALG_STATUS_X448_KEYGEN, sk.sk, sk_orig.sk,
				sizeof(sk.sk),
				"X448 key generation secret key\n"))
		return;

out:
	lc_compare_selftest(LC_ALG_STATUS_X448_KEYGEN, pk.pk, pk_orig.pk,
			    sizeof(pk.pk),
			    "X448 key generation public key\n");
}

static int lc_x448_keypair_nocheck(struct lc_x448_pk *pk,
				   struct lc_x448_sk *sk,
				   struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKNULL(sk, -EINVAL);
	CKNULL(pk, -EINVAL);

	lc_rng_check(&rng_ctx);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, sk->sk,
			      LC_X448_SECRETKEYBYTES));

	/* Timecop: the random number is the sentitive data */
	poison(sk->sk, LC_X448_SECRETKEYBYTES);

	CKINT(x448_derive_public_key(pk->pk, sk->sk));

	/* Timecop: pk and sk are not relevant for side-channels any more. */
	unpoison(sk->sk, LC_X448_SECRETKEYBYTES);
	unpoison(pk->pk, LC_X448_PUBLICKEYBYTES);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x448_keypair, struct lc_x448_pk *pk,
		      struct lc_x448_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	lc_x448_keypair_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_X448_KEYGEN);

	return lc_x448_keypair_nocheck(pk, sk, rng_ctx);
}

static int lc_x448_ss_nocheck(struct lc_x448_ss *ss,
			      const struct lc_x448_pk *pk,
			      const struct lc_x448_sk *sk);
static void lc_x448_ss_selftest(void)
{
	LC_FIPS_RODATA_SECTION
	static const struct lc_x448_pk pk = {
		.pk = { FIPS140_MOD(0x06), 0xfc, 0xe6, 0x40, 0xfa, 0x34, 0x87, 0xbf,
			0xda, 0x5f, 0x6c, 0xf2, 0xd5, 0x26, 0x3f, 0x8a,
			0xad, 0x88, 0x33, 0x4c, 0xbd, 0x07, 0x43, 0x7f,
			0x02, 0x0f, 0x08, 0xf9, 0x81, 0x4d, 0xc0, 0x31,
			0xdd, 0xbd, 0xc3, 0x8c, 0x19, 0xc6, 0xda, 0x25,
			0x83, 0xfa, 0x54, 0x29, 0xdb, 0x94, 0xad, 0xa1,
			0x8a, 0xa7, 0xa7, 0xfb, 0x4e, 0xf8, 0xa0, 0x86 }
	};
	LC_FIPS_RODATA_SECTION
	static const struct lc_x448_sk sk = {
		.sk = { 0x3d, 0x26, 0x2f, 0xdd, 0xf9, 0xec, 0x8e, 0x88,
			0x49, 0x52, 0x66, 0xfe, 0xa1, 0x9a, 0x34, 0xd2,
			0x88, 0x82, 0xac, 0xef, 0x04, 0x51, 0x04, 0xd0,
			0xd1, 0xaa, 0xe1, 0x21, 0x70, 0x0a, 0x77, 0x9c,
			0x98, 0x4c, 0x24, 0xf8, 0xcd, 0xd7, 0x8f, 0xbf,
			0xf4, 0x49, 0x43, 0xeb, 0xa3, 0x68, 0xf5, 0x4b,
			0x29, 0x25, 0x9a, 0x4f, 0x1c, 0x60, 0x0a, 0xd3 }
	};
	LC_FIPS_RODATA_SECTION
	static const struct lc_x448_ss ss = {
		.ss = { 0xce, 0x3e, 0x4f, 0xf9, 0x5a, 0x60, 0xdc, 0x66,
			0x97, 0xda, 0x1d, 0xb1, 0xd8, 0x5e, 0x6a, 0xfb,
			0xdf, 0x79, 0xb5, 0x0a, 0x24, 0x12, 0xd7, 0x54,
			0x6d, 0x5f, 0x23, 0x9f, 0xe1, 0x4f, 0xba, 0xad,
			0xeb, 0x44, 0x5f, 0xc6, 0x6a, 0x01, 0xb0, 0x77,
			0x9d, 0x98, 0x22, 0x39, 0x61, 0x11, 0x1e, 0x21,
			0x76, 0x62, 0x82, 0xf7, 0x3d, 0xd9, 0x6b, 0x6f }
	};
	struct lc_x448_ss act;

	LC_SELFTEST_RUN(LC_ALG_STATUS_X448_SS);

	if (lc_x448_ss_nocheck(&act, &pk, &sk))
		return;
	lc_compare_selftest(LC_ALG_STATUS_X448_SS, act.ss, ss.ss, sizeof(ss.ss),
			    "X448 scalar multiplication\n");
}

static int lc_x448_ss_nocheck(struct lc_x448_ss *ss,
			      const struct lc_x448_pk *pk,
			      const struct lc_x448_sk *sk)
{
	int ret;

	CKNULL(sk, -EINVAL);
	CKNULL(pk, -EINVAL);
	CKNULL(ss, -EINVAL);

	/* Timecop: mark the secret key as sensitive */
	poison(sk->sk, LC_X448_SECRETKEYBYTES);

	CKINT(x448_scalarmult(ss->ss, pk->pk, sk->sk));

	/* Timecop: ss and sk are not relevant for side-channels any more. */
	unpoison(sk->sk, LC_X448_SECRETKEYBYTES);
	unpoison(ss->ss, LC_X448_SSBYTES);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x448_ss, struct lc_x448_ss *ss,
		      const struct lc_x448_pk *pk, const struct lc_x448_sk *sk)
{
	lc_x448_ss_selftest();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_X448_SS);

	return lc_x448_ss_nocheck(ss, pk, sk);
}
