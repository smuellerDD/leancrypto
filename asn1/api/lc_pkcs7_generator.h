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

#ifndef LC_PKCS7_GENERATOR_H
#define LC_PKCS7_GENERATOR_H

#include "lc_pkcs7_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup PKCS7Gen PKCS#7 Message Generate Handling
 *
 * Concept of PKCS#7 message generation handling in leancrypto
 *
 * The leancrypto library provides an PKCS#7 generator which can create
 * PKCS#7 messages. The generator does not enforce any PKCS#7 limitations and
 * thus allows the caller to generate any combination of field offered by the
 * PKCS#7 specification. To appropriately use the PKCS#7 parser, please consider
 * the following rules:
 *
 * 1. The generated PKCS#7 data blob is independent of the original PKCS#7
 *    certificate data structure.
 *
 * 2. The generator does not allocate any memory. All memory MUST be provided
 *    by the caller. Thus, if the caller provides insufficient memory, the
 *    generator will return -EOVERFLOW.
 *
 * 3. Before invoking the PKCS#7 generator, the caller must allocate an
 *    \p pkcs7_message data structure (e.g. on stack) and fill it with the
 *    numerous setter functions to add data.
 *
 * 4. The \p pkcs7_message data structure should be released at the end of the
 *    operation with \p lc_pkcs7_message_clear.
 */

/**
 * @ingroup PKCS7Gen
 * @brief Encode a PKCS#7 message
 *
 * The function generates a PKCS#7 data blob from the filled PKCS#7 data
 * structure.
 *
 * The signature of the data using the signer is created within this call.
 *
 * @param [in] pkcs7 The data structure that is filled by the caller before this
 *		     invocation using the various setter functions.
 * @param [in,out] data Raw PKCS#7 data blob in DER / BER format - the caller
 *			must provide the memory
 * @param [in,out] avail_datalen Length of the raw PKCS#7 certificate buffer that
 *				 is free (the input value must be equal to the
 * 				 \p data buffer size, the output refers to how
 *				 many bytes are unused)
 *
 * @return 0 on success or < 0 on error
 */
int lc_pkcs7_encode(const struct lc_pkcs7_message *pkcs7, uint8_t *data,
		    size_t *avail_datalen);

/**
 * @ingroup PKCS7Gen
 * @brief Set an PKCS#7 certificate to be added to a PKCS#7 message
 *
 * With this call, additional certificates can be supplied that shall be added
 * to the PKCS#7 message.
 *
 * The X.509 certificate associated with the signer is automatically be added as
 * it is registered with \p lc_pkcs7_set_signer. Therefore, it SHALL NOT be
 * added with this call.
 *
 * \note The caller must retain the \p x509 structure for the lifetime of the
 * \p pkcs7 structure.
 *
 * @param [out] pkcs7 PKCS#7 structure that shall receive the signer
 * @param [in] x509 PKCS#7 certificate
 *
 * @return 0 on success, < 0 on error
 */
int lc_pkcs7_set_certificate(struct lc_pkcs7_message *pkcs7,
			     struct lc_x509_certificate *x509);

/**
 * @ingroup PKCS7Gen
 * @brief Set an PKCS#7 certificate as signer for a PKCS#7 message
 *
 * The certificate MUST have a public and secret key set to be added. This
 * function implies that the data to be protected is signed with the private
 * key supplied by this call. Furthermore, the associated X.509 certificate is
 * added to the PKCS#7 message.
 *
 * \note The caller must retain the \p x509_with_sk structure for the lifetime
 * of the \p pkcs7 structure.
 *
 * @param [out] pkcs7 PKCS#7 structure that shall receive the signer
 * @param [in] x509_with_sk PKCS#7 certificate with secret key to be used as
 *			    signer
 * @param [in] signing_hash With this parameter, the signing hash MAY be
 *			    specified by the caller. If this is NULL, the
 *			    default message digest is used. Note, the message
 *			    digest algorithm must be capable of delivering at
 *			    least twice the classic security strength of the
 *			    signature algorithm. This is checked with this
 *			    function and returns -ENOPKG if the requirement is
 *			    not met.
 * @param [in] auth_attribute Specify which authenticated attributes are to be
 *			      generated. When set to 0, no authenticated
 *			      attributes are generated.
 *			      \note When authenticated attributes are to be
 *			      generated, the caller MUST provide a
 *			      \p signing_hash as RFC5652 section 5.3 requres
 *			      the presence of the message digest attribute.
 *			      The following attributes are allowed:
 *			      \p sinfo_has_content_type - set content type
 *			      \p sinfo_has_signing_time - set signing time
 *			      \p sinfo_has_message_digest - set message digest
 *
 * @return 0 on success, < 0 on error
 */
int lc_pkcs7_set_signer(struct lc_pkcs7_message *pkcs7,
			struct lc_x509_certificate *x509_with_sk,
			const struct lc_hash *signing_hash,
			unsigned long auth_attribute);

enum lc_pkcs7_set_data_flags {
	/** Define no flags */
	lc_pkcs7_set_data_noflag,
	/** Embed data into PKCS#7 message */
	lc_pkcs7_set_data_embed,
};

/**
 * @ingroup PKCS7Gen
 * @brief Set the data to be signed with PKCS#7
 *
 * \note The caller must retain the \p data for the lifetime of the \p pkcs7
 * structure.
 *
 * @param [in] pkcs7 PKCS#7 data structure to be filled
 * @param [in] data Pointer to the data to be signed
 * @param [in] data_len Size of the data buffer
 * @param [in] flags Flags to be set
 *
 * @return 0 on success, < 0 on error
 */
int lc_pkcs7_set_data(struct lc_pkcs7_message *pkcs7, const uint8_t *data,
		      size_t data_len, enum lc_pkcs7_set_data_flags flags);

#ifdef __cplusplus
}
#endif

#endif /* LC_PKCS7_GENERATOR_H */
