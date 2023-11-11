/*
 * Copyright (C) 2023, Stephan Mueller <smueller@chronox.de>
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
 * Copyright (c) 2013-2023
 * Frank Denis <j at pureftpd dot org>
 */

#include "ed25519.h"
#include "ed25519_ref10.h"
#include "ext_headers.h"
#include "lc_sha512.h"
#include "ret_checkers.h"

int lc_ed25519_keypair(struct lc_ed25519_pk *pk, struct lc_ed25519_sk *sk,
		       struct lc_rng_ctx *rng_ctx)
{
	ge25519_p3 A;
	uint8_t tmp[LC_SHA512_SIZE_DIGEST];
	int ret;

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, sk->sk, 32));
	lc_hash(lc_sha512, sk->sk, 32, tmp);
	tmp[0] &= 248;
	tmp[31] &= 127;
	tmp[31] |= 64;

	ge25519_scalarmult_base(&A, tmp);
	lc_memset_secure(tmp, 0, sizeof(tmp));
	ge25519_p3_tobytes(pk->pk, &A);

	memcpy(sk->sk + 32, pk->pk, 32);

out:
	return ret;
}

int lc_ed25519_sign(struct lc_ed25519_sig *sig, const uint8_t *msg, size_t mlen,
		    const struct lc_ed25519_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	uint8_t az[LC_SHA512_SIZE_DIGEST];
	uint8_t nonce[LC_SHA512_SIZE_DIGEST];
	uint8_t hram[LC_SHA512_SIZE_DIGEST];
	ge25519_p3 R;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha512);

	lc_hash(lc_sha512, sk->sk, 32, az);

	lc_hash_init(hash_ctx);

	if (rng_ctx) {
		/* r = hash(k || K || noise || pad || M) (mod q) */
		lc_hash_update(hash_ctx, az, LC_SHA512_SIZE_DIGEST);
		CKINT(lc_rng_generate(rng_ctx, NULL, 0, nonce, 32));
		memset(nonce + 32, 0, 32);
		lc_hash_update(hash_ctx, nonce, sizeof(nonce));
	} else {
		lc_hash_update(hash_ctx, az + 32, 32);
	}

	lc_hash_update(hash_ctx, msg, mlen);
	lc_hash_final(hash_ctx, nonce);

	memcpy(sig->sig + 32, sk->sk + 32, 32);

	sc25519_reduce(nonce);
	ge25519_scalarmult_base(&R, nonce);
	ge25519_p3_tobytes(sig->sig, &R);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, sig->sig, LC_ED25519_SIGBYTES);
	lc_hash_update(hash_ctx, msg, mlen);
	lc_hash_final(hash_ctx, hram);

	sc25519_reduce(hram);
	az[0] &= 248;
	az[31] &= 127;
	az[31] |= 64;
	sc25519_muladd(sig->sig + 32, hram, az, nonce);

out:
	lc_memset_secure(az, 0, sizeof(az));
	lc_memset_secure(nonce, 0, sizeof(nonce));
	lc_memset_secure(hram, 0, sizeof(hram));
	lc_hash_zero(hash_ctx);
	return ret;
}

int lc_ed25519_verify(const struct lc_ed25519_sig *sig, const uint8_t *msg,
		      size_t mlen, const struct lc_ed25519_pk *pk)
{
	uint8_t h[LC_SHA512_SIZE_DIGEST];
	ge25519_p3 check;
	ge25519_p3 expected_r;
	ge25519_p3 A;
	ge25519_p3 sb_ah;
	ge25519_p2 sb_ah_p2;
	LC_HASH_CTX_ON_STACK(hash_ctx, lc_sha512);

#if 0
	//ED25519_COMPAT
	if (sig->sig[63] & 224) {
		return -EINVAL;
	}
#else
	if ((sig->sig[63] & 240) != 0 &&
	    sc25519_is_canonical(sig->sig + 32) == 0) {
		return -EINVAL;
	}
	if (ge25519_is_canonical(pk->pk) == 0) {
		return -EINVAL;
	}
#endif
	if (ge25519_frombytes_negate_vartime(&A, pk->pk) != 0 ||
	    ge25519_has_small_order(&A) != 0) {
		return -EINVAL;
	}
	if (ge25519_frombytes(&expected_r, sig->sig) != 0 ||
	    ge25519_has_small_order(&expected_r) != 0) {
		return -EINVAL;
	}

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, sig->sig, 32);
	lc_hash_update(hash_ctx, pk->pk, LC_ED25519_PUBLICKEYBYTES);
	lc_hash_update(hash_ctx, msg, mlen);
	lc_hash_final(hash_ctx, h);
	lc_hash_zero(hash_ctx);
	sc25519_reduce(h);

	ge25519_double_scalarmult_vartime(&sb_ah_p2, h, &A, sig->sig + 32);
	ge25519_p2_to_p3(&sb_ah, &sb_ah_p2);
	ge25519_p3_sub(&check, &expected_r, &sb_ah);

	if ((ge25519_has_small_order(&check) - 1) != 0)
		return -EBADMSG;
	return 0;
}
