/*
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "kyber_debug.h"
#include "kyber_kdf.h"
#include "kyber_kem.h"
#include "kyber_verify.h"
#include "lc_hash.h"
#include "lc_kyber.h"
#include "lc_memcmp_secure.h"
#include "lc_sha3.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

int _lc_kyber_keypair(
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
	ret = lc_rng_generate(rng_ctx, NULL, 0,
			      sk->sk + LC_KYBER_SECRETKEYBYTES -
				      LC_KYBER_SYMBYTES,
			      LC_KYBER_SYMBYTES);
	kyber_print_buffer(sk->sk + LC_KYBER_SECRETKEYBYTES - LC_KYBER_SYMBYTES,
			   LC_KYBER_SYMBYTES, "Keygen: z");
	kyber_print_buffer(pk->pk, LC_KYBER_PUBLICKEYBYTES,
			   "======Keygen output: pk");
	kyber_print_buffer(sk->sk, LC_KYBER_SECRETKEYBYTES,
			   "======Keygen output: sk");
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

	if (!ct || !ss || !pk || !rng_ctx)
		return -EINVAL;

	kyber_print_buffer(pk->pk, LC_KYBER_PUBLICKEYBYTES,
			   "======Encapsulation input: pk");

	/*
	 * FIPS 203 input validation: pk type check not needed, because
	 * struct lc_kyber_pk ensures that the input is of required length.
	 */

	CKINT(lc_rng_generate(rng_ctx, NULL, 0, buf, LC_KYBER_SYMBYTES));
	kyber_print_buffer(buf, LC_KYBER_SYMBYTES, "Encapsulation: m");

	/* Multitarget countermeasure for coins + contributory KEM */
	lc_hash(lc_sha3_256, pk->pk, LC_KYBER_PUBLICKEYBYTES,
		buf + LC_KYBER_SYMBYTES);
	lc_hash(lc_sha3_512, buf, sizeof(buf), kr);
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

	kyber_ss_kdf(ss, ss_len, ct, kyber_ss.ss);

out:
	lc_memset_secure(&kyber_ss, 0, sizeof(kyber_ss));
	return ret;
}

/**
 * @brief kyber_kem_iv_sk - Check consistency of Kyber secret key
 *
 * FIPS 203: Optional check
 *
 * @param  [in] sk Secret key (dk)
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
	lc_hash(lc_sha3_256, &sk->sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
		LC_KYBER_PUBLICKEYBYTES, kr);

	if (lc_memcmp_secure(sk->sk + LC_KYBER_SECRETKEYBYTES -
				     2 * LC_KYBER_SYMBYTES,
			     LC_KYBER_SYMBYTES, kr, sizeof(kr)))
		ret = -EINVAL;

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
	uint8_t fail;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (!ss || !ct || !sk) {
		ret = -EINVAL;
		goto out;
	}

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

	/*
	 * Additional input validation - it may be disabled as it is may be
	 * viewed as not useful, because the public key and the SHA3-512 hash of
	 * (m || H(pk)) is processed with the indcpa_enc function. But for
	 * high-security use cases, it may be useful to counter any potential
	 * flaws present in indcpa_enc.
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
	lc_hash(lc_sha3_512, ws->buf, sizeof(ws->buf), ws->kr);
	kyber_print_buffer(ws->kr, LC_KYBER_SYMBYTES, "Decapsulation: K'");
	kyber_print_buffer(ws->kr + LC_KYBER_SYMBYTES, LC_KYBER_SYMBYTES,
			   "Decapsulation: r'");

	/* coins are in kr + KYBER_SYMBYTES */
	CKINT(indcpa_enc_f(ws->cmp, ws->buf, pk, ws->kr + LC_KYBER_SYMBYTES));
	kyber_print_buffer(ws->cmp, LC_KYBER_CIPHERTEXTBYTES,
			   "Decapsulation: c'");

	fail = verify(ct->ct, ws->cmp, LC_KYBER_CIPHERTEXTBYTES);

	/* Compute rejection key */
	kyber_shake256_rkprf(
		ss->ss, sk->sk + LC_KYBER_SECRETKEYBYTES - LC_KYBER_SYMBYTES,
		ct->ct);
	kyber_print_buffer(ss->ss, LC_KYBER_SYMBYTES, "Decapsulation: Kdash");

	/* Copy true key to return buffer if fail is false */
	cmov(ss->ss, ws->kr, LC_KYBER_SSBYTES, (uint8_t)(1 - fail));
	kyber_print_buffer(ss->ss, LC_KYBER_SSBYTES,
			   "======Decapsulation output: ss");

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

	kyber_ss_kdf(ss, ss_len, ct, kyber_ss.ss);

out:
	lc_memset_secure(&kyber_ss, 0, sizeof(kyber_ss));
	return ret;
}
