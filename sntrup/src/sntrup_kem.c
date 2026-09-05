/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
 * The SNTRUP code is derived in parts from the code base
 * https://libntruprime.cr.yp.to/ which uses the following license:
 *
 * Copyright (C) 2024 Free Software Foundation, Inc.; This is free software;
 * see the source for copying conditions. There is NO; warranty; not even for
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * SPDX-License-Identifier: LicenseRef-PD-hp OR CC0-1.0 OR 0BSD OR MIT-0 OR MIT
 */

#include "build_bug_on.h"
#include "compare.h"
#include "cpufeatures.h"
#include "helper.h"
#include "lc_rng.h"
#include "lc_sha512.h"
#include "params.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "sntrup_kem.h"
#include "sntrup_pct.h"
#include "sntrup_sort_uint32.h"
#include "timecop.h"
#include "visibility.h"

struct lc_sntrup_accel {
	void (*core_inv3)(uint8_t *outbytes, const uint8_t *inbytes,
			  const uint8_t *kbytes, const uint8_t *cbytes,
			  struct ws_core_inv3 *ws);
	int (*verify)(const uint8_t *x, const uint8_t *y);
};

static const struct lc_sntrup_accel f_ctx_c = {
	.core_inv3 = sntrup_core_inv3,
	.verify = sntrup_verify_clen,
};

static const struct lc_sntrup_accel f_ctx_avx2 __maybe_unused = {
	.core_inv3 = sntrup_core_inv3_avx2,
	.verify = sntrup_verify_clen_avx2,
};

static const struct lc_sntrup_accel *sntrup_get_accel(void)
{
#ifdef LC_HOST_X86_64
	if (lc_cpu_feature_available() & LC_CPU_FEATURE_INTEL_AVX2)
		return &f_ctx_avx2;
#endif /* LC_HOST_X86_64 */
	return &f_ctx_c;
}

/* ----- arithmetic mod q */

/* always represented as -(q-1)/2...(q-1)/2 */

/* ----- small polynomials */

/* R3_fromR(R_fromRq(r)) */
static void R3_fromRq(small *out, const Fq *r)
{
	sntrup_encode_pxfreeze3((uint8_t *)out, (uint8_t *)r);
}

/* h = f*g in the ring R3 */
static void R3_mult(small *h, const small *f, const small *g,
		    struct ws_core_mutl3 *ws)
{
	sntrup_core_mult3((uint8_t *)h, (const uint8_t *)f, (const uint8_t *)g,
			  0, ws);
}

/* ----- polynomials mod q */

/* h = h*g in the ring Rq */
static void Rq_mult_small(Fq *h, const small *g, struct ws_core_mult *ws)
{
	sntrup_encode_pxint16((uint8_t *)h, h);
	sntrup_core_mult((uint8_t *)h, (const uint8_t *)h, (const uint8_t *)g,
			 0, ws);
	sntrup_decode_pxint16(h, (const uint8_t *)h);
}

/* h = 3f in Rq */
static void Rq_mult3(Fq *h, const Fq *f, struct ws_core_scale3 *ws)
{
	sntrup_encode_pxint16((uint8_t *)h, f);
	sntrup_core_scale3((uint8_t *)h, (const uint8_t *)h, 0, 0, ws);
	sntrup_decode_pxint16(h, (const uint8_t *)h);
}

/* out = 1/(3*in) in Rq */
/* caller must have 2p+1 bytes free in out, not just 2p */
static void Rq_recip3(Fq *out, const small *in, struct ws_core_inv *ws)
{
	sntrup_core_inv((uint8_t *)out, (const uint8_t *)in, 0, 0, ws);
	/* could check byte 2*p for failure; but, in context, inv always works */
	sntrup_decode_pxint16(out, (uint8_t *)out);
}

/* ----- underlying hash function */

#define Hash_bytes 32

static void Hash(uint8_t *out, const uint8_t *in, size_t inlen)
{
	uint8_t h[LC_SHA_MAX_SIZE_DIGEST];
	unsigned int i;
	lc_hash(lc_sha512, in, inlen, h);
	for (i = 0; i < 32; ++i)
		out[i] = h[i];
}

/* ----- higher-level randomness */

struct ws_short_random {
	uint32_t L[ppadsort];
};
static void Short_random(small *out, struct lc_rng_ctx *rng_ctx,
			 struct ws_short_random *ws)
{
	unsigned int i;

	lc_rng_generate(rng_ctx, NULL, 0, (uint8_t *)ws->L, 4 * p);
	sntrup_decode_pxint32(ws->L, (uint8_t *)ws->L);
	for (i = 0; i < w; ++i)
		ws->L[i] = ws->L[i] & (uint32_t)-2;
	for (i = w; i < p; ++i)
		ws->L[i] = (ws->L[i] & (uint32_t)-3) | 1;
	for (i = p; i < ppadsort; ++i)
		ws->L[i] = 0xffffffff;
	sntrup_sort_uint32(ws->L, ppadsort);
	for (i = 0; i < p; ++i)
		out[i] = (small)((ws->L[i] & 3) - 1);
}

struct ws_small_random {
	uint32_t L[p];
};
static void Small_random(small *out, struct lc_rng_ctx *rng_ctx,
			 struct ws_small_random *ws)
{
	int i;

	lc_rng_generate(rng_ctx, NULL, 0, (uint8_t *)ws->L, sizeof(ws->L));
	sntrup_decode_pxint32(ws->L, (uint8_t *)ws->L);
	for (i = 0; i < p; ++i)
		out[i] = (small)((((ws->L[i] & 0x3fffffff) * 3) >> 30) - 1);
}

/* ----- Streamlined NTRU Prime */

typedef small Inputs[p]; /* passed by reference */
#define Ciphertexts_bytes Rounded_bytes
#define SecretKeys_bytes (2 * Small_bytes)
#define PublicKeys_bytes Rq_bytes
#define Confirm_bytes 32

struct ws_hide {
	Fq h[p];
};
/* c,r_enc[1:] = Hide(r,pk,cache); cache is Hash4(pk) */
/* also set r_enc[0]=3 */
/* also set x[0]=2, and x[1:1+Hash_bytes] = Hash3(r_enc) */
/* also overwrite x[1+Hash_bytes:1+2*Hash_bytes] */
static void Hide(uint8_t *x, uint8_t *c, uint8_t *r_enc, const Inputs r,
		 const uint8_t *pk, const uint8_t *cache,
		 struct ws_core_mult *ws_core_mult, struct ws_hide *ws_hide,
		 struct ws_round_encode *ws_round_encode)
{
	unsigned int i;

	Small_encode(r_enc + 1, r);
	Rq_decode(ws_hide->h, pk);
	Rq_mult_small(ws_hide->h, r, ws_core_mult);
	Round_and_encode(c, ws_hide->h, ws_round_encode);
	r_enc[0] = 3;
	Hash(x + 1, r_enc, 1 + Small_bytes);
	for (i = 0; i < Hash_bytes; ++i)
		x[1 + Hash_bytes + i] = cache[i];
	x[0] = 2;
	Hash(c + Ciphertexts_bytes, x, 1 + Hash_bytes * 2);
}

int sntrup_kem_keypair_internal(struct CRYPTO_NAMESPACE(pk) * pk,
				struct CRYPTO_NAMESPACE(sk) * sk,
				struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		union {
			struct ws_core_mult ws_core_mult;
			struct ws_core_inv ws_core_inv;
			struct ws_core_inv3 ws_core_inv3;
			struct ws_small_random ws_small_random;
			struct ws_short_random ws_short_random;
		} u;
		Fq h[p + 1];
		small g[p];
		union {
			small v[p + 1];
			small f[p];
		} v;
	};
	const struct lc_sntrup_accel *sntrup_accel = sntrup_get_accel();
	/* Alignment for AVX2 variables */
	LC_DECLARE_MEM(ws, struct workspace, 32);
	int ret;

	BUILD_BUG_ON(sizeof(struct CRYPTO_NAMESPACE(sk)) !=
		     sntrup_kem_SECRETKEYBYTES);
	BUILD_BUG_ON(sizeof(struct CRYPTO_NAMESPACE(pk)) !=
		     sntrup_kem_PUBLICKEYBYTES);

	for (;;) {
		Small_random(ws->g, rng_ctx, &ws->u.ws_small_random);
		{
			small vp;

			sntrup_accel->core_inv3((uint8_t *)ws->v.v,
						(const uint8_t *)ws->g, 0, 0,
						&ws->u.ws_core_inv3);
			vp = ws->v.v[p];
			unpoison(&vp, sizeof(vp));
			if (vp == 0) {
				Small_encode(sk->sk + Small_bytes, ws->v.v);
				break;
			}
		}
	}
	{
		Short_random(ws->v.f, rng_ctx, &ws->u.ws_short_random);
		Small_encode(sk->sk, ws->v.f);
		{
			/* always works */
			Rq_recip3(ws->h, ws->v.f, &ws->u.ws_core_inv);
			Rq_mult_small(ws->h, ws->g, &ws->u.ws_core_mult);
			Rq_encode(pk->pk, ws->h);
		}
	}
	{
		unsigned int i;
		uint8_t sksave = sk->sk[SecretKeys_bytes - 1];

		for (i = 0; i < PublicKeys_bytes; ++i)
			sk->sk[SecretKeys_bytes + i] = pk->pk[i];
		sk->sk[SecretKeys_bytes - 1] = 4;
		Hash(sk->sk + SecretKeys_bytes + PublicKeys_bytes + Small_bytes,
		     sk->sk + SecretKeys_bytes - 1, 1 + PublicKeys_bytes);
		sk->sk[SecretKeys_bytes - 1] = sksave;
		CKINT(lc_rng_generate(rng_ctx, NULL, 0,
				      sk->sk + SecretKeys_bytes +
					      PublicKeys_bytes,
				      Small_bytes));
	}

	CKINT(lc_sntrup_pct_fips(pk, sk));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, sntrup_kem_keypair, struct CRYPTO_NAMESPACE(pk) * pk,
		      struct CRYPTO_NAMESPACE(sk) * sk,
		      struct lc_rng_ctx *rng_ctx)
{
	sntrup_selftest_keygen();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SNTRUP_KEYGEN);

	return sntrup_kem_keypair_internal(pk, sk, rng_ctx);
}

int sntrup_kem_enc_internal(struct CRYPTO_NAMESPACE(ct) * ct,
			    struct CRYPTO_NAMESPACE(ss) * ss,
			    const struct CRYPTO_NAMESPACE(pk) * pk,
			    struct lc_rng_ctx *rng_ctx)
{
	struct workspace {
		union {
			struct ws_core_mult ws_core_mult;
			struct ws_short_random ws_short_random;
		} u;
		struct ws_hide ws_hide;
		struct ws_round_encode ws_round_encode;
		uint8_t cache[Hash_bytes];
		union {
			/* XXX: can eliminate with incremental hashing */
			uint8_t y[1 + PublicKeys_bytes];
			Inputs r;
		} union_v;
		uint8_t r_enc[Small_bytes + 1];
		uint8_t x[1 + Hash_bytes + Ciphertexts_bytes + Confirm_bytes];
	};
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	unsigned int i;

	BUILD_BUG_ON(sizeof(struct CRYPTO_NAMESPACE(ct)) !=
		     sntrup_kem_CIPHERTEXTBYTES);
	BUILD_BUG_ON(sizeof(struct CRYPTO_NAMESPACE(ss)) != sntrup_kem_BYTES);

	{
		for (i = 0; i < PublicKeys_bytes; ++i)
			ws->union_v.y[1 + i] = pk->pk[i];
		ws->union_v.y[0] = 4;
		Hash(ws->cache, ws->union_v.y, sizeof(ws->union_v.y));
	}
	{
		Short_random(ws->union_v.r, rng_ctx, &ws->u.ws_short_random);
		{
			Hide(ws->x, ct->ct, ws->r_enc, ws->union_v.r, pk->pk,
			     ws->cache, &ws->u.ws_core_mult, &ws->ws_hide,
			     &ws->ws_round_encode);
			for (i = 0; i < Ciphertexts_bytes + Confirm_bytes; ++i)
				ws->x[1 + Hash_bytes + i] = ct->ct[i];
			ws->x[0] = 1;
			Hash(ss->ss, ws->x, sizeof(ws->x));
		}
	}

	LC_RELEASE_MEM(ws);
	return 0;
}

LC_INTERFACE_FUNCTION(int, sntrup_kem_enc, struct CRYPTO_NAMESPACE(ct) * ct,
		      struct CRYPTO_NAMESPACE(ss) * ss,
		      const struct CRYPTO_NAMESPACE(pk) * pk)
{
	sntrup_selftest_enc();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SNTRUP_ENC);

	return sntrup_kem_enc_internal(ct, ss, pk, lc_seeded_rng);
}

int sntrup_kem_dec_internal(struct CRYPTO_NAMESPACE(ss) * ss,
			    const struct CRYPTO_NAMESPACE(ct) * ct,
			    const struct CRYPTO_NAMESPACE(sk) * sk)
{
	const uint8_t *pk = sk->sk + SecretKeys_bytes;
	const uint8_t *rho = pk + PublicKeys_bytes;
	const uint8_t *cache = rho + Small_bytes;
	struct workspace {
		union {
			struct ws_core_mult ws_core_mult;
			struct ws_core_mutl3 ws_core_mult3;
			struct ws_core_scale3 ws_core_scale3;
		} u;
		struct ws_hide ws_hide;
		struct ws_round_encode ws_round_encode;
		Fq d[p];
		union {
			small f[p];
			small e[p];
			uint8_t cnew[Ciphertexts_bytes + Confirm_bytes];
		} union_v;
		union {
			small v[p];
			uint8_t r_enc[1 + Small_bytes];
		} union_x;

		Inputs r;
		uint8_t x[1 + Hash_bytes + Ciphertexts_bytes + Confirm_bytes];
	};
	const struct lc_sntrup_accel *sntrup_accel = sntrup_get_accel();
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));
	unsigned int i;
	int mask;

	{
		Rounded_decode(ws->d, ct->ct);
		{
			Small_decode(ws->union_v.f, sk->sk);
			Rq_mult_small(ws->d, ws->union_v.f,
				      &ws->u.ws_core_mult);
			Rq_mult3(ws->d, ws->d, &ws->u.ws_core_scale3);
		}
		{
			R3_fromRq(ws->union_v.e, ws->d);
			Small_decode(ws->union_x.v, sk->sk + Small_bytes);
			R3_mult(ws->r, ws->union_v.e, ws->union_x.v,
				&ws->u.ws_core_mult3);
		}
		sntrup_core_wforce((uint8_t *)ws->r, (uint8_t *)ws->r, 0, 0);
	}
	{
		/* XXX: can use incremental hashing to reduce x size */
		Hide(ws->x, ws->union_v.cnew, ws->union_x.r_enc, ws->r, pk,
		     cache, &ws->u.ws_core_mult, &ws->ws_hide,
		     &ws->ws_round_encode);
		mask = sntrup_accel->verify(ct->ct, ws->union_v.cnew);
		for (i = 0; i < Small_bytes; ++i)
			ws->union_x.r_enc[i + 1] ^=
				(uint8_t)(mask &
					  (ws->union_x.r_enc[i + 1] ^ rho[i]));
		Hash(ws->x + 1, ws->union_x.r_enc,
		     1 + Small_bytes); /* XXX: can instead do cmov on cached hash of rho */
		for (i = 0; i < Ciphertexts_bytes + Confirm_bytes; ++i)
			ws->x[1 + Hash_bytes + i] = ct->ct[i];
		ws->x[0] = (uint8_t)(1 + mask);
		Hash(ss->ss, ws->x, sizeof(ws->x));
	}

	LC_RELEASE_MEM(ws);
	return 0;
}

LC_INTERFACE_FUNCTION(int, sntrup_kem_dec, struct CRYPTO_NAMESPACE(ss) * ss,
		      const struct CRYPTO_NAMESPACE(ct) * ct,
		      const struct CRYPTO_NAMESPACE(sk) * sk)
{
	sntrup_selftest_dec();
	LC_SELFTEST_COMPLETED(LC_ALG_STATUS_SNTRUP_DEC);

	return sntrup_kem_dec_internal(ss, ct, sk);
}
