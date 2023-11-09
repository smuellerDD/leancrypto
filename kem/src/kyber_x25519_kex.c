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
/*
 * This code is derived in parts from the code distribution provided with
 * https://github.com/pq-crystals/kyber
 *
 * That code is released under Public Domain
 * (https://creativecommons.org/share-your-work/public-domain/cc0/).
 */

#include "kyber_internal.h"
#include "kyber_kdf.h"

#include "lc_memset_secure.h"
#include "lc_kyber.h"
#include "ret_checkers.h"
#include "visibility.h"

int lc_kex_x25519_uake_initiator_init_internal(
	struct lc_kyber_x25519_pk *pk_e_i, struct lc_kyber_x25519_ct *ct_e_i,
	struct lc_kyber_x25519_ss *tk, struct lc_kyber_x25519_sk *sk_e,
	const struct lc_kyber_x25519_pk *pk_r, struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKINT(lc_kyber_x25519_keypair(pk_e_i, sk_e, rng_ctx));
	CKINT(lc_kyber_x25519_enc_internal(ct_e_i, tk, pk_r, rng_ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_uake_initiator_init,
		      struct lc_kyber_x25519_pk *pk_e_i,
		      struct lc_kyber_x25519_ct *ct_e_i,
		      struct lc_kyber_x25519_ss *tk,
		      struct lc_kyber_x25519_sk *sk_e,
		      const struct lc_kyber_x25519_pk *pk_r)
{
	return lc_kex_x25519_uake_initiator_init_internal(
		pk_e_i, ct_e_i, tk, sk_e, pk_r, lc_seeded_rng);
}

/**
 * @brief Kyber-X25519 KDF
 *
 * SS <- KMAC256(K = Kyber-SS || X25519-SS from ephemeral key 1,
 *		 X = Kyber-SS || X25519-SS from static key ||
 * 		     Nonce,
 *		 L = requested SS length,
 *		 S = "Kyber X25519 KEM 3-way SS")
 *
 * @param [in] ss0 SS0
 * @param [in] ss1 SS1
 * @param [in] in3 input buffer 3
 * @param [in] inlen3 length of input buffer 3
 * @param [out] out output buffer of size
 * @param [out] outlen output buffer length
 */
static inline void kyber_x25519_kdf3(const struct lc_kyber_x25519_ss *ss0,
				     const struct lc_kyber_x25519_ss *ss1,
				     const uint8_t *in3, size_t inlen3,
				     uint8_t *out, size_t outlen)
{
	static const uint8_t kyber_x25519_ss_label[] =
		"Kyber X25519 KEM 3-way SS";
	LC_KMAC_CTX_ON_STACK(kmac_ctx, lc_cshake256);

	/*
	 * NOTE: this only works because struct lc_kyber_x25519_ss contqains
	 * Kyber SS || X25519 SS in memory. If this structure changes,
	 * change this KDF invocation.
	 */
	lc_kmac_init(kmac_ctx, (uint8_t *)ss0,
		     sizeof(struct lc_kyber_x25519_ss), kyber_x25519_ss_label,
		     sizeof(kyber_x25519_ss_label) - 1);
	lc_kmac_update(kmac_ctx, (uint8_t *)ss1,
		       sizeof(struct lc_kyber_x25519_ss));
	lc_kmac_update(kmac_ctx, in3, inlen3);
	lc_kmac_final(kmac_ctx, out, outlen);

	lc_kmac_zero(kmac_ctx);
}

int lc_kex_x25519_uake_responder_ss_internal(
	struct lc_kyber_x25519_ct *ct_e_r, uint8_t *shared_secret,
	size_t shared_secret_len, const uint8_t *kdf_nonce,
	size_t kdf_nonce_len, const struct lc_kyber_x25519_pk *pk_e_i,
	const struct lc_kyber_x25519_ct *ct_e_i,
	const struct lc_kyber_x25519_sk *sk_r, struct lc_rng_ctx *rng_ctx)
{
	struct lc_kyber_x25519_ss ss[2];
	int ret;

	CKINT(lc_kyber_x25519_enc_internal(ct_e_r, &ss[0], pk_e_i, rng_ctx));
	CKINT(lc_kyber_x25519_dec_internal(&ss[1], ct_e_i, sk_r));

	kyber_x25519_kdf3(&ss[0], &ss[1], kdf_nonce, kdf_nonce_len,
			  shared_secret, shared_secret_len);

out:
	lc_memset_secure(ss, 0, sizeof(ss));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_uake_responder_ss,
		      struct lc_kyber_x25519_ct *ct_e_r, uint8_t *shared_secret,
		      size_t shared_secret_len, const uint8_t *kdf_nonce,
		      size_t kdf_nonce_len,
		      const struct lc_kyber_x25519_pk *pk_e_i,
		      const struct lc_kyber_x25519_ct *ct_e_i,
		      const struct lc_kyber_x25519_sk *sk_r)
{
	return lc_kex_x25519_uake_responder_ss_internal(
		ct_e_r, shared_secret, shared_secret_len, kdf_nonce,
		kdf_nonce_len, pk_e_i, ct_e_i, sk_r, lc_seeded_rng);
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_uake_initiator_ss,
		      uint8_t *shared_secret, size_t shared_secret_len,
		      const uint8_t *kdf_nonce, size_t kdf_nonce_len,
		      const struct lc_kyber_x25519_ct *ct_e_r,
		      const struct lc_kyber_x25519_ss *tk,
		      const struct lc_kyber_x25519_sk *sk_e)
{
	struct lc_kyber_x25519_ss ss;
	int ret;

	CKINT(lc_kyber_x25519_dec_internal(&ss, ct_e_r, sk_e));
	kyber_x25519_kdf3(&ss, tk, kdf_nonce, kdf_nonce_len, shared_secret,
			  shared_secret_len);

out:
	lc_memset_secure(&ss, 0, sizeof(ss));
	return ret;
}

int lc_kex_x25519_ake_initiator_init_internal(
	struct lc_kyber_x25519_pk *pk_e_i, struct lc_kyber_x25519_ct *ct_e_i,
	struct lc_kyber_x25519_ss *tk, struct lc_kyber_x25519_sk *sk_e,
	const struct lc_kyber_x25519_pk *pk_r, struct lc_rng_ctx *rng_ctx)
{
	int ret;

	CKINT(lc_kyber_x25519_keypair(pk_e_i, sk_e, rng_ctx));
	CKINT(lc_kyber_x25519_enc_internal(ct_e_i, tk, pk_r, rng_ctx));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_ake_initiator_init,
		      struct lc_kyber_x25519_pk *pk_e_i,
		      struct lc_kyber_x25519_ct *ct_e_i,
		      struct lc_kyber_x25519_ss *tk,
		      struct lc_kyber_x25519_sk *sk_e,
		      const struct lc_kyber_x25519_pk *pk_r)
{
	return lc_kex_x25519_ake_initiator_init_internal(
		pk_e_i, ct_e_i, tk, sk_e, pk_r, lc_seeded_rng);
}

/**
 * @brief Kyber-X25519 KDF
 *
 * SS <- KMAC256(K = Kyber-SS || X25519-SS from ephemeral key 1,
 *		 X = Kyber-SS || X25519-SS from ephemeral key 2 ||
 *		     Kyber-SS || X25519-SS from static key ||
 * 		     Nonce,
 *		 L = requested SS length,
 *		 S = "Kyber X25519 KEM 4-way SS")
 *
 * @param [in] ss0 SS0
 * @param [in] ss1 SS1
 * @param [in] ss2 SS2
 * @param [in] in4 input buffer 4
 * @param [in] inlen4 length of input buffer 4
 * @param [out] out output buffer of size
 * @param [out] outlen output buffer length
 */
static inline void kyber_x25519_kdf4(const struct lc_kyber_x25519_ss *ss0,
				     const struct lc_kyber_x25519_ss *ss1,
				     const struct lc_kyber_x25519_ss *ss2,
				     const uint8_t *in4, size_t inlen4,
				     uint8_t *out, size_t outlen)
{
	static const uint8_t kyber_x25519_ss_label[] =
		"Kyber X25519 KEM 4-way SS";
	LC_KMAC_CTX_ON_STACK(kmac_ctx, lc_cshake256);

	/*
	 * NOTE: this only works because struct lc_kyber_x25519_ss contqains
	 * Kyber SS || X25519 SS in memory. If this structure changes,
	 * change this KDF invocation.
	 */
	lc_kmac_init(kmac_ctx, (uint8_t *)ss0,
		     sizeof(struct lc_kyber_x25519_ss), kyber_x25519_ss_label,
		     sizeof(kyber_x25519_ss_label) - 1);
	lc_kmac_update(kmac_ctx, (uint8_t *)ss1,
		       sizeof(struct lc_kyber_x25519_ss));
	lc_kmac_update(kmac_ctx, (uint8_t *)ss2,
		       sizeof(struct lc_kyber_x25519_ss));
	lc_kmac_update(kmac_ctx, in4, inlen4);
	lc_kmac_final(kmac_ctx, out, outlen);

	lc_kmac_zero(kmac_ctx);
}

int lc_kex_x25519_ake_responder_ss_internal(
	struct lc_kyber_x25519_ct *ct_e_r_1,
	struct lc_kyber_x25519_ct *ct_e_r_2, uint8_t *shared_secret,
	size_t shared_secret_len, const uint8_t *kdf_nonce,
	size_t kdf_nonce_len, const struct lc_kyber_x25519_pk *pk_e_i,
	const struct lc_kyber_x25519_ct *ct_e_i,
	const struct lc_kyber_x25519_sk *sk_r,
	const struct lc_kyber_x25519_pk *pk_i, struct lc_rng_ctx *rng_ctx)
{
	struct lc_kyber_x25519_ss ss[3];
	int ret;

	CKINT(lc_kyber_x25519_enc_internal(ct_e_r_1, &ss[0], pk_e_i, rng_ctx));
	CKINT(lc_kyber_x25519_enc_internal(ct_e_r_2, &ss[1], pk_i, rng_ctx));
	CKINT(lc_kyber_x25519_dec_internal(&ss[2], ct_e_i, sk_r));
	kyber_x25519_kdf4(&ss[0], &ss[1], &ss[2], kdf_nonce, kdf_nonce_len,
			  shared_secret, shared_secret_len);

out:
	lc_memset_secure(ss, 0, sizeof(ss));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_ake_responder_ss,
		      struct lc_kyber_x25519_ct *ct_e_r_1,
		      struct lc_kyber_x25519_ct *ct_e_r_2,
		      uint8_t *shared_secret, size_t shared_secret_len,
		      const uint8_t *kdf_nonce, size_t kdf_nonce_len,
		      const struct lc_kyber_x25519_pk *pk_e_i,
		      const struct lc_kyber_x25519_ct *ct_e_i,
		      const struct lc_kyber_x25519_sk *sk_r,
		      const struct lc_kyber_x25519_pk *pk_i)
{
	return lc_kex_x25519_ake_responder_ss_internal(
		ct_e_r_1, ct_e_r_2, shared_secret, shared_secret_len, kdf_nonce,
		kdf_nonce_len, pk_e_i, ct_e_i, sk_r, pk_i, lc_seeded_rng);
}

LC_INTERFACE_FUNCTION(int, lc_kex_x25519_ake_initiator_ss,
		      uint8_t *shared_secret, size_t shared_secret_len,
		      const uint8_t *kdf_nonce, size_t kdf_nonce_len,
		      const struct lc_kyber_x25519_ct *ct_e_r_1,
		      const struct lc_kyber_x25519_ct *ct_e_r_2,
		      const struct lc_kyber_x25519_ss *tk,
		      const struct lc_kyber_x25519_sk *sk_e,
		      const struct lc_kyber_x25519_sk *sk_i)
{
	struct lc_kyber_x25519_ss ss[2];
	int ret;

	CKINT(lc_kyber_x25519_dec_internal(&ss[0], ct_e_r_1, sk_e));
	CKINT(lc_kyber_x25519_dec_internal(&ss[1], ct_e_r_2, sk_i));
	kyber_x25519_kdf4(&ss[0], &ss[1], tk, kdf_nonce, kdf_nonce_len,
			  shared_secret, shared_secret_len);

out:
	lc_memset_secure(ss, 0, sizeof(ss));
	return ret;
}
