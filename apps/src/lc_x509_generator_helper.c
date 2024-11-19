/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "lc_x509_generator.h"
#include "lc_x509_generator_helper.h"
#include "lc_x509_parser.h"
#include "ret_checkers.h"

/**
 * @brief Set the signer X.509 certificate for a X.509 certificate
 *
 * @param [out] signed_x509 Signed X.509 certificate data structure to be filled
 * @param [out] signer_key_input_data Buffer that holds the loaded key data
 *				      where the buffer must have the same
 *				      lifetime as \p x509
 * @param [in] signer_x509 Signer X.509 certificate data that shall sign the
 *			   \p signed_x509
 * @param [in] sk_data Buffer with associated secret key
 * @param [in] sk_data_len Length of secret key buffer
 *
 * @return 0 on success, < 0 on error
 */
int lc_x509_cert_set_signer(struct lc_x509_certificate *signed_x509,
			    struct lc_x509_key_input_data *signer_key_input_data,
			    struct lc_x509_certificate *signer_x509,
			    const uint8_t *sk_data, size_t sk_data_len)
{
	size_t pk_len;
	const uint8_t *pk_ptr;
	enum lc_sig_types pkey_type;
	int ret;

	/* Get the signature type based on the signer key */
	CKINT(lc_x509_cert_get_pubkey(signer_x509, &pk_ptr, &pk_len,
				      &pkey_type));

	switch (pkey_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT_LOG(lc_dilithium_pk_load(
				  &signer_key_input_data->pk.dilithium_pk,
				  pk_ptr, pk_len),
			  "Loading X.509 signer public key from certificate\n");
		CKINT_LOG(lc_dilithium_sk_load(
				  &signer_key_input_data->sk.dilithium_sk,
				  sk_data, sk_data_len),
			  "Loading X.509 signer private key from file\n");
		CKINT_LOG(lc_x509_cert_set_signer_keypair_dilithium(
				  signed_x509,
				  &signer_key_input_data->pk.dilithium_pk,
				  &signer_key_input_data->sk.dilithium_sk),
			  "Setting X.509 key pair for signing\n");
		break;

	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_256F:
		CKINT_LOG(lc_sphincs_pk_load(
				  &signer_key_input_data->pk.sphincs_pk, pk_ptr,
				  pk_len),
			  "Loading X.509 signer public key from certificate\n");
		CKINT(lc_sphincs_pk_set_keytype_fast(
			&signer_key_input_data->pk.sphincs_pk));
		CKINT_LOG(lc_sphincs_sk_load(
				  &signer_key_input_data->sk.sphincs_sk,
				  sk_data, sk_data_len),
			  "Loading X.509 signer private key from file\n");
		CKINT(lc_sphincs_sk_set_keytype_fast(
			&signer_key_input_data->sk.sphincs_sk));
		goto load_sphincs;
		break;
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT_LOG(lc_sphincs_pk_load(
				  &signer_key_input_data->pk.sphincs_pk, pk_ptr,
				  pk_len),
			  "Loading X.509 signer public key from certificate\n");
		CKINT(lc_sphincs_pk_set_keytype_small(
			&signer_key_input_data->pk.sphincs_pk));
		CKINT_LOG(lc_sphincs_sk_load(
				  &signer_key_input_data->sk.sphincs_sk,
				  sk_data, sk_data_len),
			  "Loading X.509 signer private key from file\n");
		CKINT(lc_sphincs_sk_set_keytype_small(
			&signer_key_input_data->sk.sphincs_sk));
	load_sphincs:
		CKINT_LOG(lc_x509_cert_set_signer_keypair_sphincs(
				  signed_x509,
				  &signer_key_input_data->pk.sphincs_pk,
				  &signer_key_input_data->sk.sphincs_sk),
			  "Setting X.509 key pair for signing\n");
		break;

	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT_LOG(
			lc_x509_cert_load_pk_dilithium_ed25519(
				&signer_key_input_data->pk.dilithium_ed25519_pk,
				pk_ptr, pk_len),
			"Loading X.509 signer public key from certificate\n");
		CKINT_LOG(
			lc_dilithium_ed25519_sk_load(
				&signer_key_input_data->sk.dilithium_ed25519_sk,
				sk_data,
				sk_data_len - LC_ED25519_SECRETKEYBYTES,
				sk_data + sk_data_len -
					LC_ED25519_SECRETKEYBYTES,
				LC_ED25519_SECRETKEYBYTES),
			"Loading X.509 signer private key from file\n");
		CKINT_LOG(
			lc_x509_cert_set_signer_keypair_dilithium_ed25519(
				signed_x509,
				&signer_key_input_data->pk.dilithium_ed25519_pk,
				&signer_key_input_data->sk.dilithium_ed25519_sk),
			"Setting X.509 key pair for signing\n");
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_SM2:
	case LC_SIG_UNKNOWN:
	default:
		return -ENOPKG;
	}

out:
	return ret;
}
