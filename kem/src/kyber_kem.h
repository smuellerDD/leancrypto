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

#ifndef KYBER_KEM_H
#define KYBER_KEM_H

#include "kyber_verify.h"
#include "lc_hash.h"
#include "lc_kyber.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "visibility.h"

#ifdef __cplusplus
extern "C"
{
#endif

static inline int _lc_kyber_keypair(
	struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
	struct lc_rng_ctx *rng_ctx,
	int (*indcpa_keypair_f)(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
				uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
				struct lc_rng_ctx *rng_ctx))
{
	int ret;

	if (!pk || !sk || !rng_ctx)
		return -EINVAL;

	ret = indcpa_keypair_f(pk->pk, sk->sk, rng_ctx);
	if (ret)
		return ret;

	memcpy(&sk->sk[LC_KYBER_INDCPA_SECRETKEYBYTES], pk->pk,
	       LC_KYBER_INDCPA_PUBLICKEYBYTES);

	lc_hash(lc_sha3_256, pk->pk, LC_KYBER_PUBLICKEYBYTES,
		sk->sk + LC_KYBER_SECRETKEYBYTES - 2 * LC_KYBER_SYMBYTES);

	/* Value z for pseudo-random output on reject */
	return lc_rng_generate(
		rng_ctx, NULL, 0,
		sk->sk + LC_KYBER_SECRETKEYBYTES - LC_KYBER_SYMBYTES,
		LC_KYBER_SYMBYTES);
}

static inline int _lc_kyber_enc(
	struct lc_kyber_ct *ct, uint8_t *ss, size_t ss_len,
	const struct lc_kyber_pk *pk, struct lc_rng_ctx *rng_ctx,
	int (*indcpa_enc_f)(uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			    const uint8_t coins[LC_KYBER_SYMBYTES]))
{
	uint8_t buf[2 * LC_KYBER_SYMBYTES];
	/* Will contain key, coins */
	uint8_t kr[2 * LC_KYBER_SYMBYTES];
	int ret;

	if (!ct || !ss || !pk || !rng_ctx)
		return -EINVAL;

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, buf, LC_KYBER_SYMBYTES));

	/* Multitarget countermeasure for coins + contributory KEM */
	lc_hash(lc_sha3_256, pk->pk, LC_KYBER_PUBLICKEYBYTES,
		buf + LC_KYBER_SYMBYTES);
	lc_hash(lc_sha3_512, buf, sizeof(buf), kr);

	/* coins are in kr+KYBER_SYMBYTES */
	CKINT(indcpa_enc_f(ct->ct, buf, pk->pk, kr + LC_KYBER_SYMBYTES));

	/* overwrite coins in kr with H(c) */
	lc_hash(lc_sha3_256, ct->ct, LC_KYBER_CIPHERTEXTBYTES,
		kr + LC_KYBER_SYMBYTES);
	/* hash concatenation of pre-k and H(c) to k */
	lc_shake(lc_shake256, kr, sizeof(kr), ss, ss_len);

out:
	lc_memset_secure(buf, 0, sizeof(buf));
	lc_memset_secure(kr, 0, sizeof(kr));
	return ret;
}

static inline int _lc_kyber_dec(
	uint8_t *ss, size_t ss_len, const struct lc_kyber_ct *ct,
	const struct lc_kyber_sk *sk,
	int (*indcpa_dec_f)(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES]),
	int (*indcpa_enc_f)(uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			    const uint8_t coins[LC_KYBER_SYMBYTES]))
{
	struct workspace {
		uint8_t buf[2 * LC_KYBER_SYMBYTES];
		/* Will contain key, coins */
		uint8_t kr[2 * LC_KYBER_SYMBYTES];
		uint8_t cmp[LC_KYBER_CIPHERTEXTBYTES];
	};
	const uint8_t *pk;
	uint8_t fail;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (!ss || !ct || !sk) {
		ret = -EINVAL;
		goto out;
	}

	pk = sk->sk + LC_KYBER_INDCPA_SECRETKEYBYTES;

	CKINT(indcpa_dec_f(ws->buf, ct->ct, sk->sk));

	/* Multitarget countermeasure for coins + contributory KEM */
	memcpy(&ws->buf[LC_KYBER_SYMBYTES],
	       &sk->sk[LC_KYBER_SECRETKEYBYTES - 2 * LC_KYBER_SYMBYTES],
	       LC_KYBER_SYMBYTES);
	lc_hash(lc_sha3_512, ws->buf, sizeof(ws->buf), ws->kr);

	/* coins are in kr + KYBER_SYMBYTES */
	CKINT(indcpa_enc_f(ws->cmp, ws->buf, pk, ws->kr + LC_KYBER_SYMBYTES));

	fail = verify(ct->ct, ws->cmp, LC_KYBER_CIPHERTEXTBYTES);

	/* overwrite coins in kr with H(c) */
	lc_hash(lc_sha3_256, ct->ct, LC_KYBER_CIPHERTEXTBYTES,
		ws->kr + LC_KYBER_SYMBYTES);

	/* Overwrite pre-k with z on re-encryption failure */
	cmov(ws->kr, sk->sk + LC_KYBER_SECRETKEYBYTES - LC_KYBER_SYMBYTES,
	     LC_KYBER_SYMBYTES, fail);

	/* hash concatenation of pre-k and H(c) to k */
	lc_shake(lc_shake256, ws->kr, sizeof(ws->kr), ss, ss_len);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

#ifdef __cplusplus
}
#endif

#endif /* KYBER_KEM_H */
