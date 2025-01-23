/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_X509_GENERATOR_H
#define LC_X509_GENERATOR_H

#include "lc_dilithium.h"
#include "lc_sphincs.h"
#include "lc_x509_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup X509Gen X.509 Certificate Generate Handling
 *
 * Concept of X.509 certificate generate handling in leancrypto
 *
 * The leancrypto library provides an X.509 generator which can create
 * X.509 certificates. The generator does not enforce any X.509 limitations and
 * thus allows the caller to generate any combination of field offered by the
 * X.509 specification. To appropriately use the X.509 parser, please consider
 * the following rules:
 *
 * 1. The generated X.509 data blob is independent of the original X.509
 *    certificate data structure.
 *
 * 2. The generator does not allocate any memory. All memory MUST be provided
 *    by the caller. Thus, if the caller provides insufficient memory, the
 *    generator will return -EOVERFLOW.
 *
 * 3. Before invoking the X.509 generator, the caller must allocate an
 *    \p lc_x509_certificate data structure (e.g. on stack) and fill it with the
 *    numerous setter functions to add data.
 */

/**
 * @ingroup X509Gen
 * @brief Encode an X.509 certificate
 *
 * The function generates an X.509 data blob from the filled X.509 data
 * structure.
 *
 * This function also performs the signature generation to sign the X.509
 * data with the provided signer.
 *
 * @param [in] x509 The data structure that is filled by the caller before this
 *		    invocation using the various setter functions.
 * @param [in,out] data Raw X.509 data blob in DER / BER format - the caller
 *			must provide the memory
 * @param [in,out] avail_datalen Length of the raw X.509 certificate buffer that
 *				 is free (the input value must be equal to the
 * 				 \p data buffer size, the output refers to how
 *				 many bytes are unused)
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_encode(const struct lc_x509_certificate *x509, uint8_t *data,
			size_t *avail_datalen);

/**
 * @ingroup X509Gen
 * @brief Encode a private key DER structure
 *
 * The function generates a DER data blob from the private keys
 *
 * @param [in] gendata The data structure holding the private keys
 * @param [in,out] data Raw X.509 data blob in DER / BER format - the caller
 *			must provide the memory
 * @param [in,out] avail_datalen Length of the raw DER structure buffer that
 *				 is free (the input value must be equal to the
 * 				 \p data buffer size, the output refers to how
 *				 many bytes are unused)
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_sk_encode(const struct lc_x509_key_data *gendata, uint8_t *data,
		      size_t *avail_datalen);

/**
 * @ingroup X509Gen
 * @brief Return signature size derived from private key information
 *
 * @param [out] siglen Signature size
 * @param [in] keys The data structure holding the private keys
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_get_signature_size_from_sk(size_t *siglen,
				       const struct lc_x509_key_data *keys);

/**
 * @ingroup X509Gen
 * @brief Return signature size derived from certificate information
 *
 * @param [out] siglen Signature size
 * @param [in] cert The certificate data structure with the available public key
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_get_signature_size_from_cert(
	size_t *siglen, const struct lc_x509_certificate *cert);

/**
 * @ingroup X509Gen
 * @brief Generate signature over user-supplied data
 *
 * @param [out] sig_data Caller-supplied buffer with signature (it needs to be
 * 			 at least as large as reported by
 * 			 \p lc_x509_get_signature_size_from_sk or
 *			 \p lc_x509_get_signature_size_from_cert)
 * @param [in,out] siglen Length of the \p sig_data buffer, the value will be
 *			  updated such that it reflects the length of the
 *			  signature.
 * @param [in] keys The data structure holding the private keys
 * @param [in] m Message to be signed
 * @param [in] mlen Length of message
 * @param [in] prehash_algo It is permissible that the message is prehashed. If
 *			    so, it is indicated by this parameter which points
 *			    to the used message digest the caller used to
 *			    generate the prehashed message digest. This
 *			    forces the use of the Hash[ML|SLH|Composite]-DSA.
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_signature_gen(uint8_t *sig_data, size_t *siglen,
			  const struct lc_x509_key_data *keys, const uint8_t *m,
			  size_t mlen, const struct lc_hash *prehash_algo);

/**
 * @ingroup X509Gen
 * @brief Generate keypair and set it to the X.509 certificate
 *
 * \note After this call, the X.509 certificate acts as a self-signed
 * certificate. If another signer is to be used, use \p lc_x509_cert_set_signer.
 *
 * @param [out] cert X.509 certificate data structure to be filled
 * @param [out] keys Buffer that is filled with the newly generated key data
 *		     where the buffer must have the same lifetime as \p cert
 * @param [in] create_keypair_algo Algorithm to generate the key pair for
 *
 * @return 0 on success, < 0 on error
 */
int lc_x509_keypair_gen(struct lc_x509_certificate *cert,
			struct lc_x509_key_data *keys,
			enum lc_sig_types create_keypair_algo);

/**
 * @ingroup X509Gen
 * @brief Load key pair it to the X.509 certificate
 *
 * This call allows secret and / or public keys to be loaded. If only one of
 * the types is loaded, the respective other type is not touched. For example,
 * such freedom is needed when decoding an X.509 certificate and wanting to
 * add the associated private key.
 *
 * \note If this call is used to load a full key pair, the X.509 certificate
 * acts as a self-signed certificate. If another signer is to be used,
 * use \p lc_x509_cert_set_signer.
 *
 * @param [out] cert X.509 certificate data structure to be filled
 * @param [in] keys Buffer that holds the loaded key data where the buffer must
 *		     have the same lifetime as \p cert
 *
 * @return 0 on success, < 0 on error
 */
int lc_x509_keypair_load(struct lc_x509_certificate *cert,
			 const struct lc_x509_key_data *keys);

/**
 * @ingroup X509Gen
 * @brief Set the signer X.509 certificate for a X.509 certificate
 *
 * \note This call also sets the issuer name components in the \p signed_x509
 * from the \p signer_x509. Thus, when invoking this call, ensure that
 * all name components in \p signer_x509 are properly set. If this cannot be
 * guaranteed, the issuer information needs to be set with a sequence of
 * \p lc_x509_cert_get_subject_*(signer_x509) and
 * \p lc_x509_cert_set_issuer_*(signed_x509).
 *
 * @param [out] signed_x509 Signed X.509 certificate data structure to be filled
 * @param [in] signer_key_data Buffer that holds the loaded key data
 *				where the buffer must have the same
 *				lifetime as \p signer_x509
 * @param [in] signer_x509 Signer X.509 certificate data that shall sign the
 *			   \p signed_x509
 *
 * @return 0 on success, < 0 on error
 */
int lc_x509_cert_set_signer(struct lc_x509_certificate *signed_x509,
			    const struct lc_x509_key_data *signer_key_data,
			    const struct lc_x509_certificate *signer_x509);

/**
 * @ingroup X509Gen
 * @brief Set the extended key usage from human readable form
 *
 * The service function can be called repeadetly to set all intended EKU
 * flags.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] name Human readable string (any wrong string will create the
 *		    list of allowed strings on stdout)
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_eku(struct lc_x509_certificate *cert, const char *name);

/**
 * @ingroup X509Gen
 * @brief Set the extended key usage in integer form
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] val EKU value holding the LC_KEY_EKU_* flags
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_eku_val(struct lc_x509_certificate *cert, uint16_t val);

/**
 * @ingroup X509Gen
 * @brief Set the key usage from human readable form
 *
 * The service function can be called repeadetly to set all intended key usage
 * flags.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] name Human readable string (any wrong string will craete the
 *		    list of allowed strings on stdout)
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_keyusage(struct lc_x509_certificate *cert,
			      const char *name);

/**
 * @ingroup X509Gen
 * @brief Set the key usage in integer form
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [out] val key usage value holding the LC_KEY_USAGE_* flags
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_keyusage_val(struct lc_x509_certificate *cert,
				  uint16_t val);

/**
 * @ingroup X509Gen
 * @brief Mark the certificate to bear the basicConstraint CA
 *
 * \note This call also sets the issuer name components in the \p cert based
 * on the subject data. Thus, when invoking this call, ensure that
 * all name components in \p cert are properly set. If this cannot be
 * guaranteed, the issuer information needs to be set with a sequence of
 * \p lc_x509_cert_set_issuer_*(cert).
 *
 * @param [in] cert Certificate data structure to be filled with the data
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_ca(struct lc_x509_certificate *cert);

/**
 * @ingroup X509Gen
 * @brief Get the SAN DNS name
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] san_dns_name SAN DNS name to add to the certificate
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_san_dns(struct lc_x509_certificate *cert,
			     const char *san_dns_name);

/**
 * @ingroup X509Gen
 * @brief Get the SAN IP value
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] san_ip Binary representation of IP address
 * @param [in] san_ip_len Length of the IP address buffer
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_san_ip(struct lc_x509_certificate *cert,
			    const uint8_t *san_ip, size_t san_ip_len);

/**
 * @ingroup X509Gen
 * @brief Helper to convert the human IP address value into binary form
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] ip_name Caller-provided buffer to fill with human-readable form
 * @param [out] ip Caller-provided buffer of binary representation of IP address
 * @param [in] ip_len Length of the IP address buffer
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_enc_san_ip(struct lc_x509_certificate *cert, char *ip_name,
		       uint8_t *ip, size_t *ip_len);

/**
 * @ingroup X509Gen
 * @brief Set the SKID value
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note If no SKID is set by the caller, leancrypto generates the SHA3-256
 * hash of the public key as an SKID.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] skid Binary representation of SKID
 * @param [in] skidlen length of the SKID buffer
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_skid(struct lc_x509_certificate *cert, const uint8_t *skid,
			  size_t skidlen);

/**
 * @ingroup X509Gen
 * @brief Set the AKID value
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note If the certificate to be generated is marked as a CA certificate and
 * no AKID is set, the AKID is set to be identical to the SKID.
 *
 * \note If a signer of a certificate is set, its SKID is used as AKID.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] akid Binary representation of AKID
 * @param [in] akidlen length of the AKID buffer
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_akid(struct lc_x509_certificate *cert, const uint8_t *akid,
			  size_t akidlen);

/**
 * @ingroup X509Gen
 * @brief Set the valid-from data to the certificate
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] time_since_epoch Time in seconds since EPOCH to set
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_valid_from(struct lc_x509_certificate *cert,
				time64_t time_since_epoch);

/**
 * @ingroup X509Gen
 * @brief Set the valid-to data to the certificate
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] time_since_epoch Time in seconds since EPOCH to set
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_valid_to(struct lc_x509_certificate *cert,
			      time64_t time_since_epoch);

/**
 * @ingroup X509Gen
 * @brief Set the subject CN field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_subject_cn(struct lc_x509_certificate *cert,
				const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the subject email field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_subject_email(struct lc_x509_certificate *cert,
				   const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the subject OU field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_subject_ou(struct lc_x509_certificate *cert,
				const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the subject O field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_subject_o(struct lc_x509_certificate *cert,
			       const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the subject ST field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_subject_st(struct lc_x509_certificate *cert,
				const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the subject C field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_subject_c(struct lc_x509_certificate *cert,
			       const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the issuer CN field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_issuer_cn(struct lc_x509_certificate *cert,
			       const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the issuer email field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_issuer_email(struct lc_x509_certificate *cert,
				  const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the issuer OU field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_issuer_ou(struct lc_x509_certificate *cert,
			       const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the issuer O field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_issuer_o(struct lc_x509_certificate *cert,
			      const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the issuer ST field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_issuer_st(struct lc_x509_certificate *cert,
			       const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the issuer C field tp the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * \note The returned pointer may *not* be NULL-terminated which implies that
 * this function returns also the size of the string. Yet, it is a human
 * readable string.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] string Data field to set
 * @param [in] len Length of the data field
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_issuer_c(struct lc_x509_certificate *cert,
			      const char *string, size_t len);

/**
 * @ingroup X509Gen
 * @brief Set the serial number of the certificate
 *
 * \note The caller must keep the input data available for the lifetime of
 * \p cert.
 *
 * @param [in] cert Certificate data structure to be filled with the data
 * @param [in] serial Binary representation of serial number
 * @param [in] serial_len Length of the serial number
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_cert_set_serial(struct lc_x509_certificate *cert,
			    const uint8_t *serial, size_t serial_len);

/**
 * @ingroup X509Gen
 * @brief Helper to convert the human readable name of a public key algorithm to
 *	  its internal representation
 *
 * If there is no match, the function prints out the allowed strings.
 *
 * @param [in] name public key algorithm in human readable form
 * @param [out] pkey_algo leancrypto algorithm reference
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_pkey_name_to_algorithm(const char *name,
				   enum lc_sig_types *pkey_algo);

/**
 * @ingroup X509Gen
 * @brief Helper to convert the human readable name of a hash algorithm to
 *	  its internal representation
 *
 * If there is no match, the function prints out the allowed strings.
 *
 * @param [in] hash_name hash algorithm in human readable form
 * @param [out] hash_algo leancrypto algorithm reference
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_name_to_hash(const char *hash_name,
			 const struct lc_hash **hash_algo);

/**
 * @ingroup X509Gen
 * @brief Helper to convert the internal representation of a hash algorithm to
 *	  its human readable form
 *
 * @param [in] hash_algo leancrypto algorithm reference
 * @param [out] hash_name hash algorithm in human readable form
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_hash_to_name(const struct lc_hash *hash_algo,
			 const char **hash_name);
/**
 * @ingroup X509Gen
 * @brief Helper to convert the human readable name of a keyusage to
 *	  its internal representation
 *
 * If there is no match, the function prints out the allowed strings.
 *
 * @param [in] name hash algorithm in human readable form
 * @param [out] keyusage leancrypto keyusage (note, the function ORs the value
 *			 into \p keyusage)
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_name_to_keyusage(const char *name, uint16_t *keyusage);

/**
 * @ingroup X509Gen
 * @brief Helper to convert the human readable name of a EKU to
 *	  its internal representation
 *
 * If there is no match, the function prints out the allowed strings.
 *
 * @param [in] name hash algorithm in human readable form
 * @param [out] eku leancrypto eku (note, the function ORs the value
 *			 into \p eku)
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_name_to_eku(const char *name, uint16_t *eku);

#ifdef __cplusplus
}
#endif

#endif /* LC_X509_GENERATOR_H */
