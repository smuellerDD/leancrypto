/*
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef _CRYPTO_PKCS8_PARSER_H
#define _CRYPTO_PKCS8_PARSER_H

#include "ext_headers.h"
#include "lc_hash.h"
#include "lc_pkcs8_common.h"
#include "lc_x509_parser.h"

/** @defgroup PKCS8 PKCS#8 Message Parsing
 *
 * Concept of PKCS#8 parsing in leancrypto
 *
 * The leancrypto library provides a PKCS#8 parser which can read and understand
 * PKCS#8 messages. To appropriately use the PKCS#8 parser, please consider
 * the following rules:
 *
 * 1. The parser interprets the provided PKCS#8 data blob and fills a data
 *    structure which allows immediate access to the certificate properties
 *    by the leancrypto code. The data structure \p pkcs8_message is provided
 *    as part of the official header file. But it is NOT considered to be an
 *    API. I.e. member variables or the structure format may change between
 *    versions of leancrypto without announcement. The reason for providing the
 *    data structure in the official header file is to support stack-only
 *    clients. Aas a PKCS#8 message may contain an arbitrary amount of X.509
 *    certificates and signer information sections, the macro
 *    \p LC_PKCS8_MSG_ON_STACK is provided to allocate stack memory for a given
 *    number of signers and X.509 certificates. If more certificates or signers
 *    are found, heap is transparently allocated.
 *
 * 2. The parser fills the data structure with pointers into the original PKCS#8
 *    data blob. The caller MUST keep the original PKCS#8 data blob at the same
 *    location for the life time of the associated instance of the
 *    \p pkcs8_message data structure.
 *
 * 3. The PKCS#8 parser API call only interprets and parses the PKCS#8 data
 *    blob. It does NOT enforce any kind of restrictions or policies. The caller
 *    MUST use the provided verification API to enforce policies on the given
 *    certificate.
 *
 * The PKCS#8 message parser currently only covers signature verification to
 * support use cases of secure boot.
 *
 * For performing a proper PKCS#8 validation, execute the following steps:
 *
 * 1. Initialize and load the certificate trust store by executing the following
 *    sub tasks. This assumes that each trusted public key is represented as an
 *    X.509 certificate which implies the set of sub steps must be executed for
 *    each certificate that shall be part of the trust store.
 *
 *    a. Load the X.509 data blob with \p lc_x509_certificate_parse
 *
 *    b. Register the certificate in the PKCS#8 trust store with
 *       \p lc_pkcs8_trust_anchor_add
 *
 * 2. Load the PKCS#8 data blob using \p lc_pkcs8_message_parse.
 *
 * 3. Validate the PKCS#8 message which verifies the encapsulated data and the
 *    certificate chain using \p lc_pkcs8_verify.
 */

/**
 * @ingroup PKCS8
 * @brief Decode a PKCS#8 message
 *
 * The function parses a PKCS#8 data buffer into a data structure that allows
 * accessing the various data points of the PKCS#8 message.
 *
 * \note The \p pkcs8 data structure will contain pointers to the \p data
 * buffer. I.e. the message parsing analyzes \p data and finds all relevant
 * data in the raw X.509 data blob. The caller MUST therefore keep the
 * \p data pointer constant as long as the \p pkcs8 pointer is valid.
 *
 * \note This function only loads and parses the PKCS#8 message into the data
 * structure to allow leancrypto to immediately access the information. This
 * function call does not validate the PKCS#8 message (except for a self-signed
 * signature). Thus, the caller MUST apply the PKCS#8 verification API to
 * validate the PKCS#8 message considering that the loading of the PKCS#8
 * message has no information about the use case.
 *
 * @param [in,out] pkcs8 The data structure that is filled with all parameters
 *			from the PKCS#8 message data buffer. The buffer must
 *			have been allocated by the caller. It is permissible
 *			to keep it on the stack.
 * @param [in] data Raw PKCS#8 data blob following RFC5652
 * @param [in] datalen Length of the raw PKCS#8 message buffer
 *
 * @return 0 on success or < 0 on error
 */
int lc_pkcs8_decode(struct lc_pkcs8_message *pkcs8, const uint8_t *data,
		    size_t datalen);

/**
 * @ingroup PKCS8
 * @brief Set the private key for the PKCS8 message
 *
 * The function sets the pointers to the private key in the PKCS#8 message
 * correctly. For encoding, the private key is read, for decoding, the
 * private key buffer is filled by the parser.
 *
 * @param [in,out] pkcs8 The PKCS#8 data structure that shall receive the
 *			 private key.
 * @param [in] privkey Raw private key data
 *
 * @return 0 on success or < 0 on error
 */
int lc_pkcs8_set_privkey(struct lc_pkcs8_message *pkcs8,
			 struct lc_x509_key_data *privkey);

/**
 * @ingroup PKCS8
 * @brief Clear the resources used by the PKCS#8 message parsing state
 *
 * @param [in] pkcs8 Certificate structure to be cleared
 */
void lc_pkcs8_message_clear(struct lc_pkcs8_message *pkcs8);

/**
 * @ingroup PKCS8
 * @brief Generate signature over user-supplied data
 *
 * This is the PKCS#8 equivalent to lc_x509_signature_gen.
 *
 * @param [out] sig_data Caller-supplied buffer with signature (it needs to be
 * 			 at least as large as reported by
 * 			 \p lc_x509_get_signature_size_from_sk or
 *			 \p lc_x509_get_signature_size_from_cert)
 * @param [in,out] siglen Length of the \p sig_data buffer, the value will be
 *			  updated such that it reflects the length of the
 *			  signature.
 * @param [in] pkcs8 The PKCS#8 message holding the private key
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
int lc_pkcs8_signature_gen(uint8_t *sig_data, size_t *siglen,
			   const struct lc_pkcs8_message *pkcs8,
			   const uint8_t *m, size_t mlen,
			   const struct lc_hash *prehash_algo);

#endif /* _CRYPTO_PKCS8_PARSER_H */
