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

#include "hqc_internal_avx2.h"
#include "hqc_avx2.h"
#include "hqc_kem_avx2.h"
#include "../hqc_kem_impl.h"
#include "visibility.h"

/**
 * @brief Keygen of the HQC_KEM IND_CCA2 scheme
 *
 * The public key is composed of the syndrome <b>s</b> as well as the seed used
 * to generate the vector <b>h</b>.
 *
 * The secret key is composed of the seed used to generate vectors <b>x</b> and
 * <b>y</b>. As a technicality, the public key is appended to the secret key in
 * order to respect NIST API.
 *
 * @param[out] pk String containing the public key
 * @param[out] sk String containing the secret key
 *
 * @returns 0 if keygen is successful
 */
LC_INTERFACE_FUNCTION(int, lc_hqc_keypair_avx2, struct lc_hqc_pk *pk,
		      struct lc_hqc_sk *sk, struct lc_rng_ctx *rng_ctx)
{
	return lc_hqc_keypair_impl(pk, sk, rng_ctx, hqc_pke_keygen_avx2);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_keypair_from_seed_avx2, struct lc_hqc_pk *pk,
		      struct lc_hqc_sk *sk, const uint8_t *seed, size_t seedlen)
{
	return lc_hqc_keypair_from_seed_impl(pk, sk, seed, seedlen,
					     hqc_pke_keygen_avx2);
}

/**
 * @brief Encapsulation of the HQC_KEM IND_CAA2 scheme
 *
 * @param[out] ct String containing the ciphertext
 * @param[out] ss String containing the shared secret
 * @param[in] pk String containing the public key
 * @returns 0 if encapsulation is successful
 */
LC_INTERFACE_FUNCTION(int, lc_hqc_enc_internal_avx2, struct lc_hqc_ct *ct,
		      struct lc_hqc_ss *ss, const struct lc_hqc_pk *pk,
		      struct lc_rng_ctx *rng_ctx)
{
	return lc_hqc_enc_internal_impl(ct, ss, pk, rng_ctx,
					hqc_pke_encrypt_avx2);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc_avx2, struct lc_hqc_ct *ct,
		      struct lc_hqc_ss *ss, const struct lc_hqc_pk *pk)
{
	return lc_hqc_enc_impl(ct, ss, pk, hqc_pke_encrypt_avx2);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_enc_kdf_avx2, struct lc_hqc_ct *ct,
		      uint8_t *ss, size_t ss_len, const struct lc_hqc_pk *pk)
{
	return lc_hqc_enc_kdf_impl(ct, ss, ss_len, pk, hqc_pke_encrypt_avx2);
}

/**
 * @brief Decapsulation of the HQC_KEM IND_CAA2 scheme
 *
 * @param[out] ss String containing the shared secret
 * @param[in] ct String containing the cipĥertext
 * @param[in] sk String containing the secret key
 * @returns 0 if decapsulation is successful, -1 otherwise
 */
LC_INTERFACE_FUNCTION(int, lc_hqc_dec_avx2, struct lc_hqc_ss *ss,
		      const struct lc_hqc_ct *ct, const struct lc_hqc_sk *sk)
{
	return lc_hqc_dec_impl(ss, ct, sk, hqc_pke_encrypt_avx2,
			       hqc_pke_decrypt_avx2);
}

LC_INTERFACE_FUNCTION(int, lc_hqc_dec_kdf_avx2, uint8_t *ss, size_t ss_len,
		      const struct lc_hqc_ct *ct, const struct lc_hqc_sk *sk)
{
	return lc_hqc_dec_kdf_impl(ss, ss_len, ct, sk, hqc_pke_encrypt_avx2,
				   hqc_pke_decrypt_avx2);
}
