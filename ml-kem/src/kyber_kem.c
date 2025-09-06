/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "kyber_type.h"

#include "kyber_debug.h"
#include "kyber_kdf.h"
#include "kyber_kem.h"
#include "kyber_pct.h"
#include "lc_hash.h"
#include "lc_memcmp_secure.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "sidechannel_resistantce.h"
#include "small_stack_support.h"
#include "static_rng.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"

int _lc_kyber_keypair_from_seed(
	struct lc_kyber_pk *pk, struct lc_kyber_sk *sk, const uint8_t *seed,
	size_t seedlen,
	int (*indcpa_keypair_f)(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
				uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
				struct lc_rng_ctx *rng_ctx))
{
	struct lc_static_rng_data s_rng_state;
	LC_STATIC_DRNG_ON_STACK(s_drng, &s_rng_state);
	int ret;

	if (seedlen != 2 * LC_KYBER_SYMBYTES)
		return -EINVAL;

	s_rng_state.seed = seed;
	s_rng_state.seedlen = seedlen;

	CKINT(indcpa_keypair_f(pk->pk, sk->sk, &s_drng));

	memcpy(&sk->sk[LC_KYBER_INDCPA_SECRETKEYBYTES], pk->pk,
	       LC_KYBER_INDCPA_PUBLICKEYBYTES);

	CKINT(lc_hash(lc_sha3_256, pk->pk, LC_KYBER_PUBLICKEYBYTES,
		      sk->sk + LC_KYBER_SECRETKEYBYTES - 2 * LC_KYBER_SYMBYTES));

	/* Value z for pseudo-random output on reject */
	CKINT(lc_rng_generate(&s_drng, NULL, 0,
			      sk->sk + LC_KYBER_SECRETKEYBYTES -
				      LC_KYBER_SYMBYTES,
			      LC_KYBER_SYMBYTES));
	kyber_print_buffer(sk->sk + LC_KYBER_SECRETKEYBYTES - LC_KYBER_SYMBYTES,
			   LC_KYBER_SYMBYTES, "Keygen: z");
	kyber_print_buffer(pk->pk, LC_KYBER_PUBLICKEYBYTES,
			   "======Keygen output: pk");
	kyber_print_buffer(sk->sk, LC_KYBER_SECRETKEYBYTES,
			   "======Keygen output: sk");

	CKINT(lc_kyber_pct_fips(pk, sk));

out:
	return ret;
}

int _lc_kyber_keypair(
	struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
	struct lc_rng_ctx *rng_ctx,
	int (*indcpa_keypair_f)(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
				uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
				struct lc_rng_ctx *rng_ctx))
{
	uint8_t rnd[2 * LC_KYBER_SYMBYTES];
	int ret;

	if (!pk || !sk)
		return -EINVAL;

	lc_rng_check(&rng_ctx);

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, rnd, sizeof(rnd)));
	CKINT(_lc_kyber_keypair_from_seed(pk, sk, rnd, sizeof(rnd),
					  indcpa_keypair_f));

out:
	lc_memset_secure(rnd, 0, sizeof(rnd));
	return ret;
}

int _lc_kyber_enc(
	struct lc_kyber_ct *ct, struct lc_kyber_ss *ss,
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

	if (!ct || !ss || !pk)
		return -EINVAL;

	lc_rng_check(&rng_ctx);

	kyber_print_buffer(pk->pk, LC_KYBER_PUBLICKEYBYTES,
			   "======Encapsulation input: pk");

	/*
	 * FIPS 203 input validation: pk type check not needed, because
	 * struct lc_kyber_pk ensures that the input is of required length.
	 */

	/* Timecop: buf contains the secret message to be protected */
	poison(buf, 2 * LC_KYBER_SYMBYTES);
	CKINT(lc_rng_generate(rng_ctx, NULL, 0, buf, LC_KYBER_SYMBYTES));
	kyber_print_buffer(buf, LC_KYBER_SYMBYTES, "Encapsulation: m");

	/* Multitarget countermeasure for coins + contributory KEM */
	CKINT(lc_hash(lc_sha3_256, pk->pk, LC_KYBER_PUBLICKEYBYTES,
		      buf + LC_KYBER_SYMBYTES));
	CKINT(lc_hash(lc_sha3_512, buf, sizeof(buf), kr));
	poison(kr, sizeof(kr));
	kyber_print_buffer(buf + LC_KYBER_SYMBYTES, LC_KYBER_SYMBYTES,
			   "Encapsulation: H(ek)");
	kyber_print_buffer(kr, LC_KYBER_SYMBYTES,
			   "Encapsulation: shared secret key K");
	kyber_print_buffer(kr + LC_KYBER_SYMBYTES, LC_KYBER_SYMBYTES,
			   "Encapsulation: randomness r");

	/* coins are in kr+KYBER_SYMBYTES */
	CKINT(indcpa_enc_f(ct->ct, buf, pk->pk, kr + LC_KYBER_SYMBYTES));

	memcpy(ss->ss, kr, LC_KYBER_SSBYTES);
	kyber_print_buffer(ss->ss, LC_KYBER_SSBYTES,
			   "======Encapsulation output: ss");
	kyber_print_buffer(ct->ct, LC_CRYPTO_CIPHERTEXTBYTES,
			   "======Encapsulation output: ct");

	/* Timecop: the Kyber CT is secured and can be freely processed */
	unpoison(ct->ct, LC_CRYPTO_CIPHERTEXTBYTES);

out:
	lc_memset_secure(buf, 0, sizeof(buf));
	lc_memset_secure(kr, 0, sizeof(kr));
	return ret;
}

int _lc_kyber_enc_kdf(
	struct lc_kyber_ct *ct, uint8_t *ss, size_t ss_len,
	const struct lc_kyber_pk *pk, struct lc_rng_ctx *rng_ctx,
	int (*indcpa_enc_f)(uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			    const uint8_t coins[LC_KYBER_SYMBYTES]))
{
	struct lc_kyber_ss kyber_ss;
	int ret;

	CKINT(_lc_kyber_enc(ct, &kyber_ss, pk, rng_ctx, indcpa_enc_f));

	CKINT(kyber_ss_kdf(ss, ss_len, ct, kyber_ss.ss));

out:
	lc_memset_secure(&kyber_ss, 0, sizeof(kyber_ss));
	return ret;
}

/**
 * @brief kyber_kem_iv_sk - Check consistency of Kyber secret key
 *
 * FIPS 203: Mandatory check verifying the hash of the encapsulation key matches
 * the encapsulation key which both are stored in the decapsulation key.
 *
 * @param [in]  sk Secret key (dk)
 *
 * @return 0 on success, < 0 on error
 */
static int kyber_kem_iv_sk(const struct lc_kyber_sk *sk)
{
	uint8_t kr[LC_KYBER_SYMBYTES];
	int ret = 0;

	/*
	 * The sk is defined as sk <- (dkpke || pk || H(pk) || z)
	 *
	 * The check verifies that the pk and H(pk) correspond by hashing the
	 * pk and comparing it to H(pk).
	 */
	CKINT(lc_hash(lc_sha3_256, &sk->sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
		      LC_KYBER_PUBLICKEYBYTES, kr));

	if (lc_memcmp_secure(sk->sk + LC_KYBER_SECRETKEYBYTES -
				     2 * LC_KYBER_SYMBYTES,
			     LC_KYBER_SYMBYTES, kr, sizeof(kr)))
		ret = -EINVAL;

out:
	lc_memset_secure(kr, 0, sizeof(kr));
	return ret;
}

int _lc_kyber_dec(
	struct lc_kyber_ss *ss, const struct lc_kyber_ct *ct,
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
	int fail, ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (!ss || !ct || !sk) {
		ret = -EINVAL;
		goto out;
	}

	/* Timecop: Mark the secret part of the secret key. */
	poison(sk->sk, LC_KYBER_INDCPA_SECRETKEYBYTES);

	kyber_print_buffer(ct->ct, LC_CRYPTO_CIPHERTEXTBYTES,
			   "======Decapsulation input: ct");
	kyber_print_buffer(sk->sk, LC_KYBER_SECRETKEYBYTES,
			   "======Decapsulation input: sk");

	/*
	 * FIPS 203 input validation: ct type check not needed, because
	 * struct lc_kyber_ct ensures that the input is of required length.
	 *
	 * FIPS 203 input validation: sk type check not needed, because
	 * struct lc_kyber_sk ensures that the input is of required length.
	 */

	CKINT(kyber_kem_iv_sk(sk));

	pk = sk->sk + LC_KYBER_INDCPA_SECRETKEYBYTES;

	CKINT(indcpa_dec_f(ws->buf, ct->ct, sk->sk));
	kyber_print_buffer(ws->buf, LC_KYBER_INDCPA_MSGBYTES,
			   "Decapsulation: m'");

	/* Multitarget countermeasure for coins + contributory KEM */
	memcpy(&ws->buf[LC_KYBER_SYMBYTES],
	       &sk->sk[LC_KYBER_SECRETKEYBYTES - 2 * LC_KYBER_SYMBYTES],
	       LC_KYBER_SYMBYTES);
	CKINT(lc_hash(lc_sha3_512, ws->buf, sizeof(ws->buf), ws->kr));
	kyber_print_buffer(ws->kr, LC_KYBER_SYMBYTES, "Decapsulation: K'");
	kyber_print_buffer(ws->kr + LC_KYBER_SYMBYTES, LC_KYBER_SYMBYTES,
			   "Decapsulation: r'");

	/* coins are in kr + KYBER_SYMBYTES */
	CKINT(indcpa_enc_f(ws->cmp, ws->buf, pk, ws->kr + LC_KYBER_SYMBYTES));
	kyber_print_buffer(ws->cmp, LC_KYBER_CIPHERTEXTBYTES,
			   "Decapsulation: c'");

	fail = lc_memcmp_secure(ct->ct, LC_KYBER_CIPHERTEXTBYTES, ws->cmp,
				LC_KYBER_CIPHERTEXTBYTES);

	/* Compute rejection key */
	CKINT(kyber_shake256_rkprf(
		ss->ss, sk->sk + LC_KYBER_SECRETKEYBYTES - LC_KYBER_SYMBYTES,
		ct->ct));
	kyber_print_buffer(ss->ss, LC_KYBER_SYMBYTES, "Decapsulation: Kdash");

	/* Copy true key to return buffer if fail is false */
	cmov(ss->ss, ws->kr, LC_KYBER_SSBYTES, (uint8_t)(1 - fail));
	kyber_print_buffer(ss->ss, LC_KYBER_SSBYTES,
			   "======Decapsulation output: ss");

	unpoison(sk->sk, LC_KYBER_INDCPA_SECRETKEYBYTES);

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

int _lc_kyber_dec_kdf(
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
	struct lc_kyber_ss kyber_ss;
	int ret;

	CKINT(_lc_kyber_dec(&kyber_ss, ct, sk, indcpa_dec_f, indcpa_enc_f));

	CKINT(kyber_ss_kdf(ss, ss_len, ct, kyber_ss.ss));

out:
	lc_memset_secure(&kyber_ss, 0, sizeof(kyber_ss));
	return ret;
}
