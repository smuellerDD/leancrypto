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

#ifndef _CRYPTO_PKCS7_H
#define _CRYPTO_PKCS7_H

#include "ext_headers.h"
#include "lc_hash.h"
#include "lc_pkcs7_common.h"
#include "lc_x509_parser.h"

/** @defgroup PKCS7 PKCS#7 Message Parsing
 *
 * Concept of PKCS#7 parsing in leancrypto
 *
 * The leancrypto library provides a PKCS#7 parser which can read and understand
 * PKCS#7 messages. To appropriately use the PKCS#7 parser, please consider
 * the following rules:
 *
 * 1. The parser interprets the provided PKCS#7 data blob and fills a data
 *    structure which allows immediate access to the certificate properties
 *    by the leancrypto code. The data structure \p pkcs7_message is provided
 *    as part of the official header file. But it is NOT considered to be an
 *    API. I.e. member variables or the structure format may change between
 *    versions of leancrypto without announcement. The reason for providing the
 *    data structure in the official header file is to support stack-only
 *    clients. Aas a PKCS#7 message may contain an arbitrary amount of X.509
 *    certificates and signer information sections, the macro
 *    \p LC_PKCS7_MSG_ON_STACK is provided to allocate stack memory for a given
 *    number of signers and X.509 certificates. If more certificates or signers
 *    are found, heap is transparently allocated.
 *
 * 2. The parser fills the data structure with pointers into the original PKCS#7
 *    data blob. The caller MUST keep the original PKCS#7 data blob at the same
 *    location for the life time of the associated instance of the
 *    \p pkcs7_message data structure.
 *
 * 3. The PKCS#7 parser API call only interprets and parses the PKCS#7 data
 *    blob. It does NOT enforce any kind of restrictions or policies. The caller
 *    MUST use the provided verification API to enforce policies on the given
 *    certificate.
 *
 * The PKCS#7 message parser currently only covers signature verification to
 * support use cases of secure boot.
 *
 * For performing a proper PKCS#7 validation, execute the following steps:
 *
 * 1. Initialize and load the certificate trust store by executing the following
 *    sub tasks. This assumes that each trusted public key is represented as an
 *    X.509 certificate which implies the set of sub steps must be executed for
 *    each certificate that shall be part of the trust store.
 *
 *    a. Load the X.509 data blob with \p lc_x509_certificate_parse
 *
 *    b. Register the certificate in the PKCS#7 trust store with
 *       \p lc_pkcs7_trust_anchor_add
 *
 * 2. Load the PKCS#7 data blob using \p lc_pkcs7_message_parse.
 *
 * 3. Validate the PKCS#7 message which verifies the encapsulated data and the
 *    certificate chain using \p lc_pkcs7_verify.
 */

/**
 * @ingroup PKCS7
 * @brief Decode a PKCS#7 message
 *
 * The function parses a PKCS#7 data buffer into a data structure that allows
 * accessing the various data points of the PKCS#7 message.
 *
 * \note The \p pkcs7 data structure will contain pointers to the \p data
 * buffer. I.e. the message parsing analyzes \p data and finds all relevant
 * data in the raw X.509 data blob. The caller MUST therefore keep the
 * \p data pointer constant as long as the \p pkcs7 pointer is valid.
 *
 * \note This function only loads and parses the PKCS#7 message into the data
 * structure to allow leancrypto to immediately access the information. This
 * function call does not validate the PKCS#7 message (except for a self-signed
 * signature). Thus, the caller MUST apply the PKCS#7 verification API to
 * validate the PKCS#7 message considering that the loading of the PKCS#7
 * message has no information about the use case.
 *
 * @param [in,out] pkcs7 The data structure that is filled with all parameters
 *			from the PKCS#7 message data buffer. The buffer must
 *			have been allocated by the caller. It is permissible
 *			to keep it on the stack.
 * @param [in] data Raw PKCS#7 data blob following RFC5652
 * @param [in] datalen Length of the raw PKCS#7 message buffer
 *
 * @return 0 on success or < 0 on error
 */
int lc_pkcs7_decode(struct lc_pkcs7_message *pkcs7, const uint8_t *data,
		    size_t datalen);

/**
 * @ingroup PKCS7
 * @brief Clear the resources used by the PKCS#7 message parsing state
 *
 * @param [in] pkcs7 Certificate structure to be cleared
 */
void lc_pkcs7_message_clear(struct lc_pkcs7_message *pkcs7);

/**
 * @ingroup PKCS7
 * @brief Get access to the PKCS#7 encapsulated content
 *
 * Get access to the data content of the PKCS#7 message.  The size of the
 * header of the ASN.1 object that contains it is also provided and can be used
 * to adjust *data and *data_len to get the entire object.
 *
 * @param [in] pkcs7 The preparsed PKCS#7 message to access
 * @param [out] data Place to return a pointer to the data
 * @param [out] datalen Place to return the data length
 *
 * @return 0 on success or < 0 on error (returns -ENODATA if the data object was
 * missing from the message)
 */
int lc_pkcs7_get_content_data(const struct lc_pkcs7_message *pkcs7,
			      const uint8_t **data, size_t *datalen);

struct lc_verify_rules {
	/**
	 * Specify the key usage flags a signer certificate must possess.
	 *
	 * The allowed flags are documented as part of struct lc_public_key.
	 * If any key usage flag should match (e.g. the key usage field is
	 * irrelevant, use 0).
	 */
	uint16_t required_keyusage;

	/**
	 * Specify the extended key usage flags a signer certificate must
	 * possess.
	 *
	 * The allowed flags are documented as part of struct lc_public_key.
	 * If any key usage flag should match (e.g. the key usage field is
	 * irrelevant, use 0).
	 */
	uint16_t required_eku;
};

/**
 * @ingroup PKCS7
 * @brief Verify a PKCS#7 message
 *
 * Verify a PKCS#7 message is internally consistent - that is, the data digest
 * matches the digest in the AuthAttrs and any signature in the message or one
 * of the X.509 certificates it carries that matches another X.509 cert in the
 * message can be verified.
 *
 * If a \p trust_store is provided, perform the certificate validation also
 * against this trust store to find intermediate or root CA certificates. The
 * final certificate of a certificate chain must end in a root CA certificate
 * which must also be present in the \p trust_store.
 *
 * The validation against the \p trust_store checks that the certificate chains
 * inside the PKCS#7 message intersects keys we already know and trust. I.e. at
 * least one certificate chain must lead to the \p trust_store.
 *
 * \note The PKCS7 message block MAY be a detached signature, i.e. the data to
 * be integrity-protected and authentiated is not embedded into the PKCS7 block.
 * In this case, the caller MUST use \p lc_pkcs7_supply_detached_data to refer
 * to this detached data before the \p lc_pkcs7_verify can be executed.
 *
 * @param [in] pkcs7 The PKCS#7 message to be verified
 * @param [in] trust_store Trust store with trust anchor certificates - it MAY
 * 			   be NULL which implies that no check against the
 *			   a trust anchor store is performed. In this case,
 * 			   the presence of a root certificate is considered
 * 			   sufficient.
 * @param [in] verify_rules If non-NULL, the given rules are applied during
 *			    certificate verification.
 *
 * @return 0 on success or < 0 on error (-ENODATA refers to the case when no
 * the detached data was not provided)
 *
 * Returns, in order of descending priority:
 *
 *  (*) -EKEYREJECTED if a key was selected that had a usage restriction at
 *      odds with the specified usage, or:
 *
 *  (*) -EKEYREJECTED if a signature failed to match for which we found an
 *	appropriate X.509 certificate, or:
 *
 *  (*) -EBADMSG if some part of the message was invalid, or:
 *
 *  (*) 0 if a signature chain passed verification, or:
 *
 *  (*) -EKEYREJECTED if a blacklisted key was encountered, or:
 *
 *  (*) -ENOPKG if none of the signature chains are verifiable because suitable
 *	crypto modules couldn't be found.
 *
 */
int lc_pkcs7_verify(struct lc_pkcs7_message *pkcs7,
		    const struct lc_pkcs7_trust_store *trust_store,
		    const struct lc_verify_rules *verify_rules);

/**
 * @ingroup PKCS7
 * @brief Supply the data needed to verify a PKCS#7 message
 *
 * Supply the detached data needed to verify a PKCS#7 message.  Note that no
 * attempt to retain/pin the data is made.  That is left to the caller.  The
 * data will not be modified by pkcs7_verify() and will not be freed when the
 * PKCS#7 message is freed.
 *
 * @param [in] pkcs7 The PKCS#7 message
 * @param [in] data The data to be verified
 * @param [in] datalen The amount of data
 *
 *
 * @return 0 on success or < 0 on error (-EEXIST refers to the case if data is
 * already supplied in the message)
 */
int lc_pkcs7_supply_detached_data(struct lc_pkcs7_message *pkcs7,
				  const uint8_t *data, size_t datalen);

/**
 * @ingroup PKCS7
 * @brief Calculate and return the message digest of the data
 *
 * Using the PKCS#7 message, calculate the message digest of the data
 * encapsulated by the PKCS#7 structure and return the message digest. It uses
 * the message digest algorithm defined by the PKCS#7 structure. Optionally
 * the function returns the used hash algorithm.
 *
 * \note The returned buffer pointer points to an entry in the \p pkcs7 data
 * structure. It has the same life time as this structure and thus should
 * not be freed or modified.
 *
 * @param [in] pkcs7 The PKCS#7 message with the encapsulated data
 * @param [out] message_digest Pointer to the message digest returned to the
 *			       caller
 * @param [out] message_digest_len Length of the message digest returned to the
 *				   caller
 * @param [out] hash_algo Reference to used hash algorithm (if the caller
 *			  supplies NULL, no data is returned)
 *
 * @return 0 on success or < 0 on error
 */
int lc_pkcs7_get_digest(struct lc_pkcs7_message *pkcs7,
			const uint8_t **message_digest,
			size_t *message_digest_len,
			const struct lc_hash **hash_algo);

/**
 * @ingroup PKCS7
 * @brief Add a certificate to a certificate trust store
 *
 * The caller provides the \p trust_store which may be empty at the beginning.
 * The function initializes the trust store and registers the certificate as
 * a trusted certificate.
 *
 * This function can be called repeatedly with the same trust store to add
 * an arbitrary number of X.509 certificates.
 *
 * Only certificates marked as CAs are allowed to be registered in the trust
 * store.
 *
 * It is permissible to load intermediate certificates. But the loading of such
 * intermediate certificate requires the presence of the certificate chain
 * leading to the associated root CA.
 *
 * @param [in] trust_store Trust store to add the certificate to
 * @param [in] x509 Certificate to be added to trust store
 *
 * @return 0 on success or < 0 on error (-EKEYREJECTED implies that the
 * provided certificate does not have a chain to a root CA in the trust store)
 */
int lc_pkcs7_trust_store_add(struct lc_pkcs7_trust_store *trust_store,
			     struct lc_x509_certificate *x509);

/**
 * @ingroup PKCS7
 * @brief Release and clear the trust store
 *
 * @param [in] trust_store Trust store be released
 */
void lc_pkcs7_trust_store_clear(struct lc_pkcs7_trust_store *trust_store);

#endif /* _CRYPTO_PKCS7_H */
