/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "asn1.h"
#include "asn1_debug.h"
#include "asym_key_dilithium.h"
#include "asym_key_dilithium_ed25519.h"
#include "asym_key_sphincs.h"
#include "ext_headers.h"
#include "lc_dilithium.h"
#include "lc_hash.h"
#include "lc_sphincs.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_algorithm_mapper.h"

/*
 * Zeroize a public key signature.
 */
void public_key_signature_clear(struct lc_public_key_signature *sig)
{
	if (!sig)
		return;

	lc_memset_secure(sig, 0, sizeof(struct lc_public_key_signature));
}

/*
 * Zeroize a public key algorithm key.
 */
void public_key_clear(struct lc_public_key *key)
{
	if (!key)
		return;

	lc_memset_secure(key, 0, sizeof(struct lc_public_key));
}

/*
 * Verify a signature using a public key.
 */
int public_key_verify_signature(const struct lc_public_key *pkey,
				const struct lc_public_key_signature *sig)
{
	int ret;

	printf_debug("==>%s()\n", __func__);

	CKNULL(pkey, -EFAULT);
	CKNULL(sig, -EFAULT);
	if (!sig->s)
		return -EFAULT;

	/*
	 * If the signature specifies a public key algorithm, it *must* match
	 * the key's actual public key algorithm.
	 */
	if (sig->pkey_algo > LC_SIG_UNKNOWN &&
	    (pkey->pkey_algo != sig->pkey_algo))
		return -EKEYREJECTED;

	/*
	 * Check that the used hashing algorithm is of sufficient size.
	 * But that check is only needed if we received a hash algorithm.
	 */
	if (sig->hash_algo)
		CKINT(lc_x509_sig_check_hash(pkey->pkey_algo, sig->hash_algo));

	switch (pkey->pkey_algo) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(public_key_verify_signature_dilithium(pkey, sig));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(public_key_verify_signature_dilithium_ed25519(pkey, sig));
		break;
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_256F:
		CKINT(public_key_verify_signature_sphincs(pkey, sig, 1));
		break;
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT(public_key_verify_signature_sphincs(pkey, sig, 0));
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_SM2:
	case LC_SIG_UNKNOWN:
		printf_debug("Unimplemented asymmetric algorithm %u\n",
			     pkey->pkey_algo);
		fallthrough;
	default:
		/* Unknown public key algorithm */
		ret = -ENOPKG;
	}

out:
	printf_debug("<==%s() = %d\n", __func__, ret);
	return ret;
}

/*
 * Generate a signature using a secret key.
 */
int public_key_generate_signature(const struct lc_x509_key_data *key,
				  const struct lc_public_key_signature *sig,
				  uint8_t *sig_data, size_t *available_len)
{
	int ret;

	printf_debug("==>%s()\n", __func__);

	CKNULL(key, -EFAULT);
	CKNULL(sig, -EFAULT);
	CKNULL(sig_data, -EFAULT);
	CKNULL(available_len, -EFAULT);

	switch (key->sig_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(public_key_generate_signature_dilithium(
			key, sig, sig_data, available_len));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(public_key_generate_signature_dilithium_ed25519(
			key, sig, sig_data, available_len));
		break;
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_256F:
		CKINT(public_key_generate_signature_sphincs(key, sig, sig_data,
							    available_len, 1));
		break;
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT(public_key_generate_signature_sphincs(key, sig, sig_data,
							    available_len, 0));
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_SM2:
	case LC_SIG_UNKNOWN:
		printf_debug("Unimplemented asymmetric algorithm %u\n",
			     key->sig_type);
		fallthrough;
	default:
		/* Unknown public key algorithm */
		ret = -ENOPKG;
	}

out:
	printf_debug("<==%s() = %d\n", __func__, ret);
	return ret;
}

/*
 * Find the location of the public key in the X.509 data stream and store them
 * in the context.
 *
 * NOTE, only pointers to the DER data stream are set.
 */
int public_key_extract(struct x509_generate_context *ctx, uint8_t *dst_data,
		       size_t *available_len)
{
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_x509_key_data *keys = &cert->pub_gen_data;
	size_t pklen = 0;
	uint8_t *ptr;
	int ret;

	switch (keys->sig_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(lc_dilithium_pk_ptr(&ptr, &pklen, keys->pk.dilithium_pk));
		break;
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT(lc_sphincs_pk_ptr(&ptr, &pklen, keys->pk.sphincs_pk));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(public_key_encode_dilithium_ed25519(dst_data,
							  available_len, ctx));
		goto out;
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

	CKINT(x509_sufficient_size(available_len, pklen));

	/* Set the BIT STRING metadata */
	if (pklen) {
		memcpy(dst_data, ptr, pklen);
		*available_len -= pklen;
	}

out:
	return ret;
}

/*
 * Return the signature size of a given signature type
 */
int public_key_signature_size(size_t *siglen, enum lc_sig_types sig_type)
{
	int ret = 0;

	switch (sig_type) {
	case LC_SIG_DILITHIUM_44:
		*siglen = lc_dilithium_sig_size(LC_DILITHIUM_44);
		break;
	case LC_SIG_DILITHIUM_65:
		*siglen = lc_dilithium_sig_size(LC_DILITHIUM_65);
		break;
	case LC_SIG_DILITHIUM_87:
		*siglen = lc_dilithium_sig_size(LC_DILITHIUM_87);
		break;

	case LC_SIG_SPINCS_SHAKE_128F:
		*siglen = lc_sphincs_sig_size(LC_SPHINCS_SHAKE_128f);
		break;
	case LC_SIG_SPINCS_SHAKE_128S:
		*siglen = lc_sphincs_sig_size(LC_SPHINCS_SHAKE_128s);
		break;
	case LC_SIG_SPINCS_SHAKE_192F:
		*siglen = lc_sphincs_sig_size(LC_SPHINCS_SHAKE_192f);
		break;
	case LC_SIG_SPINCS_SHAKE_192S:
		*siglen = lc_sphincs_sig_size(LC_SPHINCS_SHAKE_192s);
		break;
	case LC_SIG_SPINCS_SHAKE_256F:
		*siglen = lc_sphincs_sig_size(LC_SPHINCS_SHAKE_256f);
		break;
	case LC_SIG_SPINCS_SHAKE_256S:
		*siglen = lc_sphincs_sig_size(LC_SPHINCS_SHAKE_256s);
		break;

	case LC_SIG_DILITHIUM_44_ED25519:
		CKINT(public_key_signature_size_dilithium_ed25519(
			LC_DILITHIUM_44, siglen));
		break;
	case LC_SIG_DILITHIUM_65_ED25519:
		CKINT(public_key_signature_size_dilithium_ed25519(
			LC_DILITHIUM_65, siglen));
		break;
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(public_key_signature_size_dilithium_ed25519(
			LC_DILITHIUM_87, siglen));
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

/*
 * Encode a private key into DER
 */
int privkey_key_encode(struct x509_generate_privkey_context *ctx,
		       uint8_t *dst_data, size_t *available_len)
{
	const struct lc_x509_key_data *keys = ctx->keys;
	int ret = 0;

	switch (keys->sig_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(private_key_encode_dilithium(dst_data, available_len,
						   ctx));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(private_key_encode_dilithium_ed25519(dst_data,
							   available_len, ctx));
		break;
	case LC_SIG_SPINCS_SHAKE_256S:
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_128F:
		CKINT(private_key_encode_sphincs(dst_data, available_len, ctx));
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_SM2:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_UNKNOWN:
		ret = -ENOPKG;
		goto out;
	}

out:
	return ret;
}

/*
 * Decode a private key from DER into the internal data buffer
 *
 * NOTE, only pointers to the DER data stream are set.
 */
int privkey_key_decode(struct lc_x509_key_data *keys, const uint8_t *data,
		       size_t datalen)
{
	int ret = 0;

	switch (keys->sig_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(private_key_decode_dilithium(keys, data, datalen));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(private_key_decode_dilithium_ed25519(keys, data,
							   datalen));
		break;
	case LC_SIG_SPINCS_SHAKE_256S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_128S:
		CKINT(private_key_decode_sphincs(keys, data, datalen));
		CKINT(lc_sphincs_sk_set_keytype_small(keys->sk.sphincs_sk));
		break;
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_128F:
		CKINT(private_key_decode_sphincs(keys, data, datalen));
		CKINT(lc_sphincs_sk_set_keytype_fast(keys->sk.sphincs_sk));
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_SM2:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_UNKNOWN:
		ret = -ENOPKG;
		goto out;
	}

out:
	return ret;
}

/*
 * Decode a public key from DER into the internal data buffer
 *
 * NOTE, only pointers to the DER data stream are set.
 */
int pubkey_key_decode(struct lc_x509_key_data *keys, const uint8_t *data,
		      size_t datalen)
{
	int ret = 0;

	switch (keys->sig_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(lc_dilithium_pk_load(keys->pk.dilithium_pk, data,
					   datalen));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(lc_dilithium_ed25519_pk_load(
			keys->pk.dilithium_ed25519_pk, data,
			datalen - LC_ED25519_PUBLICKEYBYTES,
			data + LC_ED25519_PUBLICKEYBYTES,
			LC_ED25519_PUBLICKEYBYTES));
		break;
	case LC_SIG_SPINCS_SHAKE_256S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_128S:
		CKINT(lc_sphincs_pk_load(keys->pk.sphincs_pk, data, datalen));
		CKINT(lc_sphincs_pk_set_keytype_small(keys->pk.sphincs_pk));
		break;
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_128F:
		CKINT(lc_sphincs_pk_load(keys->pk.sphincs_pk, data, datalen));
		CKINT(lc_sphincs_pk_set_keytype_fast(keys->pk.sphincs_pk));
		break;

	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_SM2:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_UNKNOWN:
		ret = -ENOPKG;
		goto out;
	}

out:
	return ret;
}

/*
 * Set a signer to a certificate
 *
 * @param [out] signed_x509 X.509 certificate that shall be signed by the
 *		signer
 * @param [in] signer_key_data Private key of the signer
 * @param [in] signer_x509 X.509 certificate of the signer
 */
int asym_set_signer(struct lc_x509_certificate *signed_x509,
		    const struct lc_x509_key_data *signer_key_data,
		    const struct lc_x509_certificate *signer_x509)
{
	size_t pk_len;
	const uint8_t *pk_ptr;
	enum lc_sig_types pkey_type;
	int ret;

	/* Get the signature type based on the signer key */
	CKINT(lc_x509_cert_get_pubkey(signer_x509, &pk_ptr, &pk_len,
				      &pkey_type));

	signed_x509->sig.pkey_algo = signer_key_data->sig_type;

	switch (pkey_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT_LOG(
			lc_dilithium_pk_load(signer_key_data->pk.dilithium_pk,
					     pk_ptr, pk_len),
			"Loading X.509 signer public key from certificate failed: %d\n",
			ret);
		CKINT_LOG(asym_set_dilithium_keypair(
				  &signed_x509->sig_gen_data,
				  signer_key_data->pk.dilithium_pk,
				  signer_key_data->sk.dilithium_sk),
			  "Setting X.509 key pair for signing failed: %d\n",
			  ret);
		break;

	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_256F:
		CKINT_LOG(
			lc_sphincs_pk_load(signer_key_data->pk.sphincs_pk,
					   pk_ptr, pk_len),
			"Loading X.509 signer public key from certificate failed: %d\n",
			ret);
		CKINT(lc_sphincs_pk_set_keytype_fast(
			signer_key_data->pk.sphincs_pk));
		goto load_sphincs;
		break;
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT_LOG(
			lc_sphincs_pk_load(signer_key_data->pk.sphincs_pk,
					   pk_ptr, pk_len),
			"Loading X.509 signer public key from certificate failed: %d\n",
			ret);
		CKINT(lc_sphincs_pk_set_keytype_small(
			signer_key_data->pk.sphincs_pk));
	load_sphincs:
		CKINT_LOG(asym_set_sphincs_keypair(
				  &signed_x509->sig_gen_data,
				  signer_key_data->pk.sphincs_pk,
				  signer_key_data->sk.sphincs_sk),
			  "Setting X.509 key pair for signing\n");
		break;

	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT_LOG(
			lc_x509_cert_load_pk_dilithium_ed25519(
				signer_key_data->pk.dilithium_ed25519_pk,
				pk_ptr, pk_len),
			"Loading X.509 signer public key from certificate failed: %d\n",
			ret);
		CKINT_LOG(asym_set_dilithium_ed25519_keypair(
				  &signed_x509->sig_gen_data,
				  signer_key_data->pk.dilithium_ed25519_pk,
				  signer_key_data->sk.dilithium_ed25519_sk),
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

/*
 * Generate key pair and set it to the X.509 certificate structure. This implies
 * that when generating a signature, the certificate would be self-signed.
 */
int asym_keypair_gen(struct lc_x509_certificate *cert,
		     struct lc_x509_key_data *keys,
		     enum lc_sig_types create_keypair_algo)
{
	int ret;

	switch (create_keypair_algo) {
	case LC_SIG_DILITHIUM_44:
		CKINT(lc_dilithium_keypair(keys->pk.dilithium_pk,
					   keys->sk.dilithium_sk, lc_seeded_rng,
					   LC_DILITHIUM_44));
		goto load_dilithium;
		break;
	case LC_SIG_DILITHIUM_65:
		CKINT(lc_dilithium_keypair(keys->pk.dilithium_pk,
					   keys->sk.dilithium_sk, lc_seeded_rng,
					   LC_DILITHIUM_65));
		goto load_dilithium;
		break;
	case LC_SIG_DILITHIUM_87:
		CKINT(lc_dilithium_keypair(keys->pk.dilithium_pk,
					   keys->sk.dilithium_sk, lc_seeded_rng,
					   LC_DILITHIUM_87));
	load_dilithium:
		CKINT(asym_set_dilithium_keypair(&cert->sig_gen_data,
						 keys->pk.dilithium_pk,
						 keys->sk.dilithium_sk));
		CKINT(asym_set_dilithium_keypair(&cert->pub_gen_data,
						 keys->pk.dilithium_pk, NULL));
		break;
	case LC_SIG_SPINCS_SHAKE_128F:
		CKINT(lc_sphincs_keypair(keys->pk.sphincs_pk,
					 keys->sk.sphincs_sk, lc_seeded_rng,
					 LC_SPHINCS_SHAKE_128f));
		goto load_sphincs;
		break;
	case LC_SIG_SPINCS_SHAKE_128S:
		CKINT(lc_sphincs_keypair(keys->pk.sphincs_pk,
					 keys->sk.sphincs_sk, lc_seeded_rng,
					 LC_SPHINCS_SHAKE_128s));
		goto load_sphincs;
		break;
	case LC_SIG_SPINCS_SHAKE_192F:
		CKINT(lc_sphincs_keypair(keys->pk.sphincs_pk,
					 keys->sk.sphincs_sk, lc_seeded_rng,
					 LC_SPHINCS_SHAKE_192f));
		goto load_sphincs;
		break;
	case LC_SIG_SPINCS_SHAKE_192S:
		CKINT(lc_sphincs_keypair(keys->pk.sphincs_pk,
					 keys->sk.sphincs_sk, lc_seeded_rng,
					 LC_SPHINCS_SHAKE_192s));
		goto load_sphincs;
		break;
	case LC_SIG_SPINCS_SHAKE_256F:
		CKINT(lc_sphincs_keypair(keys->pk.sphincs_pk,
					 keys->sk.sphincs_sk, lc_seeded_rng,
					 LC_SPHINCS_SHAKE_256f));
		goto load_sphincs;
		break;
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT(lc_sphincs_keypair(keys->pk.sphincs_pk,
					 keys->sk.sphincs_sk, lc_seeded_rng,
					 LC_SPHINCS_SHAKE_256s));
	load_sphincs:
		CKINT(asym_set_sphincs_keypair(&cert->sig_gen_data,
					       keys->pk.sphincs_pk,
					       keys->sk.sphincs_sk));
		CKINT(asym_set_sphincs_keypair(&cert->pub_gen_data,
					       keys->pk.sphincs_pk, NULL));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
		CKINT(lc_dilithium_ed25519_keypair(
			keys->pk.dilithium_ed25519_pk,
			keys->sk.dilithium_ed25519_sk, lc_seeded_rng,
			LC_DILITHIUM_44));
		goto load_dilithium_ed25519;
		break;
	case LC_SIG_DILITHIUM_65_ED25519:
		CKINT(lc_dilithium_ed25519_keypair(
			keys->pk.dilithium_ed25519_pk,
			keys->sk.dilithium_ed25519_sk, lc_seeded_rng,
			LC_DILITHIUM_65));
		goto load_dilithium_ed25519;
		break;
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(lc_dilithium_ed25519_keypair(
			keys->pk.dilithium_ed25519_pk,
			keys->sk.dilithium_ed25519_sk, lc_seeded_rng,
			LC_DILITHIUM_87));
	load_dilithium_ed25519:
		CKINT(asym_set_dilithium_ed25519_keypair(
			&cert->sig_gen_data, keys->pk.dilithium_ed25519_pk,
			keys->sk.dilithium_ed25519_sk));
		CKINT(asym_set_dilithium_ed25519_keypair(
			&cert->pub_gen_data, keys->pk.dilithium_ed25519_pk,
			NULL));
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

	cert->sig.pkey_algo = create_keypair_algo;
	cert->pub.pkey_algo = create_keypair_algo;
	keys->sig_type = create_keypair_algo;

out:
	return ret;
}

/*
 * Load an externally provided key pair into the certificate. This implies
 * that when generating a signature, the certificate would be self-signed.
 */
int asym_keypair_load(struct lc_x509_certificate *cert,
		      const struct lc_x509_key_data *keys)
{
	int ret;

	switch (keys->sig_type) {
	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_87:
		CKINT(asym_set_dilithium_keypair(&cert->sig_gen_data,
						 keys->pk.dilithium_pk,
						 keys->sk.dilithium_sk));
		break;
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256S:
		CKINT(asym_set_sphincs_keypair(&cert->sig_gen_data,
					       keys->pk.sphincs_pk,
					       keys->sk.sphincs_sk));
		break;
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87_ED25519:
		CKINT(asym_set_dilithium_ed25519_keypair(
			&cert->sig_gen_data, keys->pk.dilithium_ed25519_pk,
			keys->sk.dilithium_ed25519_sk));
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

	cert->sig.pkey_algo = keys->sig_type;
	cert->pub.pkey_algo = keys->sig_type;

out:
	return ret;
}
