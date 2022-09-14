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

#include "kyber_indcpa.h"
#include "kyber_verify.h"

#include "lc_hash.h"
#include "lc_kyber.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "visibility.h"

DSO_PUBLIC
int lc_kyber_keypair(struct lc_kyber_pk *pk,
		     struct lc_kyber_sk *sk,
		     struct lc_rng_ctx *rng_ctx)
{
	if (!pk || !sk || !rng_ctx)
		return -EINVAL;

	indcpa_keypair(pk->pk, sk->sk, rng_ctx);

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

int kyber_enc(struct lc_kyber_ct *ct,
	      uint8_t *ss, size_t ss_len,
	      const struct lc_kyber_pk *pk,
	      struct lc_rng_ctx *rng_ctx)
{
	uint8_t buf[2 * LC_KYBER_SYMBYTES];
	/* Will contain key, coins */
	uint8_t kr[2 * LC_KYBER_SYMBYTES];
	int ret;

	if (!ct || !ss || !pk || !rng_ctx)
		return -EINVAL;

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, buf, LC_KYBER_SYMBYTES));
	/* TODO: remove that - Don't release system RNG output */
	lc_hash(lc_sha3_256, buf, LC_KYBER_SYMBYTES, buf);

	/* Multitarget countermeasure for coins + contributory KEM */
	lc_hash(lc_sha3_256, pk->pk, LC_KYBER_PUBLICKEYBYTES,
		buf + LC_KYBER_SYMBYTES);
	lc_hash(lc_sha3_512, buf, sizeof(buf), kr);

	/* coins are in kr+KYBER_SYMBYTES */
	indcpa_enc(ct->ct, buf, pk->pk, kr + LC_KYBER_SYMBYTES);

	/* overwrite coins in kr with H(c) */
	lc_hash(lc_sha3_256, ct->ct, LC_KYBER_CIPHERTEXTBYTES,
		kr + LC_KYBER_SYMBYTES);
	/* hash concatenation of pre-k and H(c) to k */
	lc_shake(lc_shake256, kr, sizeof(kr), ss, ss_len);

out:
	memset_secure(buf, 0, sizeof(buf));
	memset_secure(kr, 0, sizeof(kr));
	return ret;
}

int kyber_dec(uint8_t *ss, size_t ss_len,
	      const struct lc_kyber_ct *ct,
	      const struct lc_kyber_sk *sk)
{
	uint8_t buf[2 * LC_KYBER_SYMBYTES];
	/* Will contain key, coins */
	uint8_t kr[2 * LC_KYBER_SYMBYTES];
	uint8_t cmp[LC_KYBER_CIPHERTEXTBYTES];
	const uint8_t *pk = sk->sk + LC_KYBER_INDCPA_SECRETKEYBYTES;
	uint8_t fail;

	if (!ss || !ct || !sk)
		return -EINVAL;

	indcpa_dec(buf, ct->ct, sk->sk);

	/* Multitarget countermeasure for coins + contributory KEM */
	memcpy(&buf[LC_KYBER_SYMBYTES],
	       &sk->sk[LC_KYBER_SECRETKEYBYTES - 2 * LC_KYBER_SYMBYTES],
	       LC_KYBER_SYMBYTES);
	lc_hash(lc_sha3_512, buf, sizeof(buf), kr);

	/* coins are in kr + KYBER_SYMBYTES */
	indcpa_enc(cmp, buf, pk, kr + LC_KYBER_SYMBYTES);

	fail = verify(ct->ct, cmp, LC_KYBER_CIPHERTEXTBYTES);

	/* overwrite coins in kr with H(c) */
	lc_hash(lc_sha3_256, ct->ct, LC_KYBER_CIPHERTEXTBYTES,
		kr + LC_KYBER_SYMBYTES);

	/* Overwrite pre-k with z on re-encryption failure */
	cmov(kr, sk->sk + LC_KYBER_SECRETKEYBYTES - LC_KYBER_SYMBYTES,
	     LC_KYBER_SYMBYTES, fail);

	/* hash concatenation of pre-k and H(c) to k */
	lc_shake(lc_shake256, kr, sizeof(kr), ss, ss_len);

	memset_secure(buf, 0, sizeof(buf));
	memset_secure(kr, 0, sizeof(kr));
	memset_secure(cmp, 0, sizeof(cmp));
	return 0;
}

DSO_PUBLIC
int lc_kyber_enc(struct lc_kyber_ct *ct,
		 struct lc_kyber_ss *ss,
		 const struct lc_kyber_pk *pk,
		 struct lc_rng_ctx *rng_ctx)
{
	return kyber_enc(ct, ss->ss, LC_KYBER_SSBYTES, pk, rng_ctx);
}

DSO_PUBLIC
int lc_kyber_dec(struct lc_kyber_ss *ss,
		 const struct lc_kyber_ct *ct,
		 const struct lc_kyber_sk *sk)
{
	return kyber_dec(ss->ss, LC_KYBER_SSBYTES, ct, sk);
}
