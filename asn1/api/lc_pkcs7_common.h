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

#ifndef LC_PKCS7_COMMON_H
#define LC_PKCS7_COMMON_H

#include "lc_x509_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
struct lc_pkcs7_trust_store {
	struct lc_x509_certificate *anchor_cert;
};

struct lc_pkcs7_signed_info {
	struct lc_pkcs7_signed_info *next;

	/* Message signature.
	 *
	 * This contains the generated digest of _either_ the Content Data or
	 * the Authenticated Attributes [RFC2315 9.3]. If the latter, one of
	 * the attributes contains the digest of the Content Data within it.
	 *
	 * This also contains the issuing cert serial number and issuer's name
	 * [PKCS#7 or CMS ver 1] or issuing cert's SKID [CMS ver 3].
	 */
	struct lc_public_key_signature sig;

	/*
	 * Certificate / private key signing the message in pkcs7->data. The
	 * certificate is a pointer to one member of the pkcs7->certs list.
	 */
	struct lc_x509_certificate *signer;
	time64_t signing_time;

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

	unsigned int index;

	unsigned int
		unsupported_crypto : 1; /* T if not usable due to missing crypto */
	unsigned int blacklisted : 1;
};

struct lc_pkcs7_message {
	/*
	 * List of all certificates encapsulated by the PKCS#7 message. This
	 * includes both, the auxiliary certificates as well as the signer
	 * certificates for which also the private key is present.
	 */
	struct lc_x509_certificate *certs;
	struct lc_x509_certificate *crl; /* Revocation list */

	/*
	 * Signed information
	 */
	struct lc_pkcs7_signed_info *curr_signed_infos;
	struct lc_pkcs7_signed_info *list_head_signed_infos;
	struct lc_pkcs7_signed_info **list_tail_signed_infos;
	uint8_t version; /* Version of cert (1 -> PKCS#7 or CMS; 3 -> CMS) */

	/* Content Data (or NULL) */
	enum OID data_type; /* Type of Data */
	size_t data_len; /* Length of Data */
	const uint8_t *data; /* Content Data (or 0) */

	unsigned int have_authattrs : 1; /* T if have authattrs */
	unsigned int embed_data : 1; /* Embed data into message */
};
/// \endcond

#ifdef __cplusplus
}
#endif

#endif /* LC_PKCS7_COMMON_H */
