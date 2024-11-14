/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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
#include "lc_x509_parser.h"

/// \cond DO_NOT_DOCUMENT
struct pkcs7_trust_store {
	struct lc_x509_certificate *anchor_cert;
};

struct pkcs7_signed_info {
	struct pkcs7_signed_info *next;

	/* Message signature.
	 *
	 * This contains the generated digest of _either_ the Content Data or
	 * the Authenticated Attributes [RFC2315 9.3].  If the latter, one of
	 * the attributes contains the digest of the Content Data within it.
	 *
	 * This also contains the issuing cert serial number and issuer's name
	 * [PKCS#7 or CMS ver 1] or issuing cert's SKID [CMS ver 3].
	 */
	struct lc_public_key_signature sig;
	struct lc_x509_certificate
		*signer; /* Signing certificate (in msg->certs) */
	time64_t signing_time;

	unsigned int index;
	unsigned int
		unsupported_crypto : 1; /* T if not usable due to missing crypto */
	unsigned int blacklisted : 1;

	/* Message digest - the digest of the Content Data (or NULL) */
	const uint8_t *msgdigest;
	size_t msgdigest_len;

	/* Authenticated Attribute data (or NULL) */
	const uint8_t *authattrs;
	size_t authattrs_len;

	unsigned long aa_set;
#define sinfo_has_content_type (1 << 0)
#define sinfo_has_signing_time (1 << 1)
#define sinfo_has_message_digest (1 << 2)
#define sinfo_has_smime_caps (1 << 3)
#define sinfo_has_ms_opus_info (1 << 4)
#define sinfo_has_ms_statement_type (1 << 5)
};

struct pkcs7_message {
	struct lc_x509_certificate *certs; /* Certificate list */
	struct lc_x509_certificate *crl; /* Revocation list */
	struct pkcs7_signed_info *signed_infos;
	uint8_t version; /* Version of cert (1 -> PKCS#7 or CMS; 3 -> CMS) */
	unsigned int have_authattrs : 1; /* T if have authattrs */

	/* Content Data (or NULL) */
	enum OID data_type; /* Type of Data */
	size_t data_len; /* Length of Data */
	size_t data_hdrlen; /* Length of Data ASN.1 header */
	const uint8_t *data; /* Content Data (or 0) */
};
/// \endcond

/** @defgroup PKCS7 PKCS#7 Message Handling
 *
 * Concept of PKCS#7 certificate handling in leancrypto
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
 *    clients. As of now, this is not fully achieved as a PKCS#7 message may
 *    contain an arbitrary amount of X.509 certificates and signer information
 *    sections. Each is covered with a separate instance of the associated
 *    data structures allocated on the heap.
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
 *
 * 4. Validate the PKCS#7 certificate and/or its certificate chain traces back
 *    to the trust anchor using \p lc_pkcs7_trust_validate.
 */

/**
 * @ingroup PKCS7
 * @brief Parse a PKCS#7 message
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
int lc_pkcs7_message_parse(struct pkcs7_message *pkcs7, const uint8_t *data,
			   size_t datalen);

/**
 * @ingroup PKCS7
 * @brief Clear the resources used by the PKCS#7 message parsing state
 *
 * @param [in] pkcs7 Certificate structure to be cleared
 */
void lc_pkcs7_message_clear(struct pkcs7_message *pkcs7);

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
 * @param [out] headerlen Size of ASN.1 header not included in \p data
 *
 * @return 0 on success or < 0 on error (returns -ENODATA if the data object was
 * missing from the message)
 */
int lc_pkcs7_get_content_data(const struct pkcs7_message *pkcs7,
			      const uint8_t **data, size_t *datalen,
			      size_t *headerlen);

/**
 * @ingroup PKCS7
 * @brief Verify a PKCS#7 message
 *
 * Verify a PKCS#7 message is internally consistent - that is, the data digest
 * matches the digest in the AuthAttrs and any signature in the message or one
 * of the X.509 certificates it carries that matches another X.509 cert in the
 * message can be verified.
 *
 * This does not look to match the contents of the PKCS#7 message against any
 * external public keys.
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
 * \note The PKCS7 message block MAY be a detached signature, i.e. the data to
 * be integrity-protected and authentiated is not embedded into the PKCS7 block.
 * In this case, the caller MUST use \p lc_pkcs7_supply_detached_data to refer
 * to this detached data before the \p lc_pkcs7_verify can be executed.
 *
 * @param [in] pkcs7 The PKCS#7 message to be verified
 *
 * @return 0 on success or < 0 on error (-ENODATA refers to the case when no
 * the detached data was not provided)
 */
int lc_pkcs7_verify(struct pkcs7_message *pkcs7);

/**
 * @ingroup PKCS7
 * @brief Supply the data needed to verify a PKCS#7 message
 *
 * @param [in] pkcs7 The PKCS#7 message
 * @param [in] data The data to be verified
 * @param [in] datalen The amount of data
 *
 * Supply the detached data needed to verify a PKCS#7 message.  Note that no
 * attempt to retain/pin the data is made.  That is left to the caller.  The
 * data will not be modified by pkcs7_verify() and will not be freed when the
 * PKCS#7 message is freed.
 *
 * @return 0 on success or < 0 on error (-EEXIST refers to the case if data is
 * already supplied in the message)
 */
int lc_pkcs7_supply_detached_data(struct pkcs7_message *pkcs7,
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
int lc_pkcs7_get_digest(struct pkcs7_message *pkcs7,
			const uint8_t **message_digest,
			size_t *message_digest_len,
			const struct lc_hash **hash_algo);

/**
 * @ingroup PKCS7
 * @brief Validate PKCS#7 trust chain
 *
 * Validate that the certificate chain inside the PKCS#7 message intersects
 * keys we already know and trust.
 *
 * @param [in] pkcs7 The PKCS#7 certificate to validate
 * @param [in] trust_store Signing certificates to use as starting points
 *
 * @return 0 on success or < 0 on error
 *
 * Returns, in order of descending priority:
 *
 *  (*) -EKEYREJECTED if a signature failed to match for which we have a valid
 *	key, or
 *
 *  (*) 0 if at least one signature chain intersects with the keys in the trust
 *	\p trust_store, or
 *
 *  (*) -ENOPKG if a suitable crypto module couldn't be found for a check on a
 *	chain.
 *
 *  (*) -ENOKEY if we couldn't find a match for any of the signature chains in
 *	the message.
 */
int lc_pkcs7_trust_validate(struct pkcs7_message *pkcs7,
			    struct pkcs7_trust_store *trust_store);

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
 * @return 0 on success or < 0 on error (-EKEYREJECTED implies that the
 * provided certificate does not have a chain to a root CA in the trust store)
 */
int lc_pkcs7_trust_store_add(struct pkcs7_trust_store *trust_store,
			     struct lc_x509_certificate *x509);

/**
 * @ingroup PKCS7
 * @brief Release and clear the trust store
 */
void lc_pkcs7_trust_store_clear(struct pkcs7_trust_store *trust_store);

#endif /* _CRYPTO_PKCS7_H */