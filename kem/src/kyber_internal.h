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

#ifndef KYBER_INTERNAL_H
#define KYBER_INTERNAL_H

#include "lc_kyber.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_kyber_enc_internal(struct lc_kyber_ct *ct, struct lc_kyber_ss *ss,
			  const struct lc_kyber_pk *pk,
			  struct lc_rng_ctx *rng_ctx);
int lc_kyber_x25519_enc_internal(struct lc_kyber_x25519_ct *ct,
				 struct lc_kyber_x25519_ss *ss,
				 const struct lc_kyber_x25519_pk *pk,
				 struct lc_rng_ctx *rng_ctx);
int lc_kyber_x25519_dec_internal(struct lc_kyber_x25519_ss *ss,
				 const struct lc_kyber_x25519_ct *ct,
				 const struct lc_kyber_x25519_sk *sk);

int lc_kyber_enc_kdf_internal(struct lc_kyber_ct *ct, uint8_t *ss,
			      size_t ss_len, const struct lc_kyber_pk *pk,
			      struct lc_rng_ctx *rng_ctx);

int lc_kyber_x25519_enc_kdf_internal(struct lc_kyber_x25519_ct *ct, uint8_t *ss,
				     size_t ss_len,
				     const struct lc_kyber_x25519_pk *pk,
				     struct lc_rng_ctx *rng_ctx);

int lc_kex_uake_initiator_init_internal(struct lc_kyber_pk *pk_e_r,
					struct lc_kyber_ct *ct_e_r,
					struct lc_kyber_ss *tk,
					struct lc_kyber_sk *sk_e,
					const struct lc_kyber_pk *pk_i,
					struct lc_rng_ctx *rng_ctx);

int lc_kex_x25519_uake_initiator_init_internal(
	struct lc_kyber_x25519_pk *pk_e_i, struct lc_kyber_x25519_ct *ct_e_i,
	struct lc_kyber_x25519_ss *tk, struct lc_kyber_x25519_sk *sk_e,
	const struct lc_kyber_x25519_pk *pk_r, struct lc_rng_ctx *rng_ctx);

int lc_kex_uake_responder_ss_internal(
	struct lc_kyber_ct *ct_e_i, uint8_t *shared_secret,
	size_t shared_secret_len, const uint8_t *kdf_nonce,
	size_t kdf_nonce_len, const struct lc_kyber_pk *pk_e_r,
	const struct lc_kyber_ct *ct_e_r, const struct lc_kyber_sk *sk_i,
	struct lc_rng_ctx *rng_ctx);

int lc_kex_x25519_uake_responder_ss_internal(
	struct lc_kyber_x25519_ct *ct_e_r, uint8_t *shared_secret,
	size_t shared_secret_len, const uint8_t *kdf_nonce,
	size_t kdf_nonce_len, const struct lc_kyber_x25519_pk *pk_e_i,
	const struct lc_kyber_x25519_ct *ct_e_i,
	const struct lc_kyber_x25519_sk *sk_r, struct lc_rng_ctx *rng_ctx);

int lc_kex_ake_initiator_init_internal(struct lc_kyber_pk *pk_e_r,
				       struct lc_kyber_ct *ct_e_r,
				       struct lc_kyber_ss *tk,
				       struct lc_kyber_sk *sk_e,
				       const struct lc_kyber_pk *pk_i,
				       struct lc_rng_ctx *rng_ctx);

int lc_kex_x25519_ake_initiator_init_internal(
	struct lc_kyber_x25519_pk *pk_e_i, struct lc_kyber_x25519_ct *ct_e_i,
	struct lc_kyber_x25519_ss *tk, struct lc_kyber_x25519_sk *sk_e,
	const struct lc_kyber_x25519_pk *pk_r, struct lc_rng_ctx *rng_ctx);

int lc_kex_ake_responder_ss_internal(
	struct lc_kyber_ct *ct_e_i_1, struct lc_kyber_ct *ct_e_i_2,
	uint8_t *shared_secret, size_t shared_secret_len,
	const uint8_t *kdf_nonce, size_t kdf_nonce_len,
	const struct lc_kyber_pk *pk_e_r, const struct lc_kyber_ct *ct_e_r,
	const struct lc_kyber_sk *sk_i, const struct lc_kyber_pk *pk_r,
	struct lc_rng_ctx *rng_ctx);

int lc_kex_x25519_ake_responder_ss_internal(
	struct lc_kyber_x25519_ct *ct_e_r_1,
	struct lc_kyber_x25519_ct *ct_e_r_2, uint8_t *shared_secret,
	size_t shared_secret_len, const uint8_t *kdf_nonce,
	size_t kdf_nonce_len, const struct lc_kyber_x25519_pk *pk_e_i,
	const struct lc_kyber_x25519_ct *ct_e_i,
	const struct lc_kyber_x25519_sk *sk_r,
	const struct lc_kyber_x25519_pk *pk_i, struct lc_rng_ctx *rng_ctx);

int lc_kyber_ies_enc_internal(const struct lc_kyber_pk *pk,
			      struct lc_kyber_ct *ct, const uint8_t *plaintext,
			      uint8_t *ciphertext, size_t datalen,
			      const uint8_t *aad, size_t aadlen, uint8_t *tag,
			      size_t taglen, struct lc_aead_ctx *aead,
			      struct lc_rng_ctx *rng_ctx);

int lc_kyber_ies_enc_init_internal(struct lc_aead_ctx *aead,
				   const struct lc_kyber_pk *pk,
				   struct lc_kyber_ct *ct,
				   struct lc_rng_ctx *rng_ctx);

#ifdef __cplusplus
}
#endif

#endif /* KYBER_INTERNAL_H */
