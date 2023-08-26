/*
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
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

#ifndef KYBER_KEM_H
#define KYBER_KEM_H

#include "lc_kyber.h"

#ifdef __cplusplus
extern "C" {
#endif

int _lc_kyber_keypair(
	struct lc_kyber_pk *pk, struct lc_kyber_sk *sk,
	struct lc_rng_ctx *rng_ctx,
	int (*indcpa_keypair_f)(uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
				uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES],
				struct lc_rng_ctx *rng_ctx));

int _lc_kyber_enc(
	struct lc_kyber_ct *ct, uint8_t ss[LC_KYBER_SSBYTES],
	const struct lc_kyber_pk *pk, struct lc_rng_ctx *rng_ctx,
	int (*indcpa_enc_f)(uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			    const uint8_t coins[LC_KYBER_SYMBYTES]));
int _lc_kyber_enc_kdf(
	struct lc_kyber_ct *ct, uint8_t *ss, size_t ss_len,
	const struct lc_kyber_pk *pk, struct lc_rng_ctx *rng_ctx,
	int (*indcpa_enc_f)(uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			    const uint8_t coins[LC_KYBER_SYMBYTES]));

int _lc_kyber_dec(
	uint8_t ss[LC_KYBER_SSBYTES], const struct lc_kyber_ct *ct,
	const struct lc_kyber_sk *sk,
	int (*indcpa_dec_f)(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES]),
	int (*indcpa_enc_f)(uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			    const uint8_t coins[LC_KYBER_SYMBYTES]));
int _lc_kyber_dec_kdf(
	uint8_t *ss, size_t ss_len, const struct lc_kyber_ct *ct,
	const struct lc_kyber_sk *sk,
	int (*indcpa_dec_f)(uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t sk[LC_KYBER_INDCPA_SECRETKEYBYTES]),
	int (*indcpa_enc_f)(uint8_t c[LC_KYBER_INDCPA_BYTES],
			    const uint8_t m[LC_KYBER_INDCPA_MSGBYTES],
			    const uint8_t pk[LC_KYBER_INDCPA_PUBLICKEYBYTES],
			    const uint8_t coins[LC_KYBER_SYMBYTES]));

#ifdef __cplusplus
}
#endif

#endif /* KYBER_KEM_H */
