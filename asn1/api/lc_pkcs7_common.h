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
	struct lc_pkcs7_signed_info *curr_sinfo;
	struct lc_pkcs7_signed_info *list_head_sinfo;
	struct lc_pkcs7_signed_info **list_tail_sinfo;
	uint8_t avail_preallocated_sinfo;
	uint8_t consumed_preallocated_sinfo;
	struct lc_pkcs7_signed_info *preallocated_sinfo;

	uint8_t version; /* Version of cert (1 -> PKCS#7 or CMS; 3 -> CMS) */

	/* Content Data (or NULL) */
	enum OID data_type; /* Type of Data */
	size_t data_len; /* Length of Data */
	const uint8_t *data; /* Content Data (or 0) */

	uint8_t avail_preallocated_x509;
	uint8_t consumed_preallocated_x509;
	struct lc_x509_certificate *preallocated_x509;

	unsigned int have_authattrs : 1; /* T if have authattrs */
	unsigned int embed_data : 1; /* Embed data into message */
};

/// \endcond

/**
 * @ingroup PKCS7
 * @brief Size of pre-allocated PKCS7 message
 *
 * @param [in] num_sinfo Number of preallocated sinfo members (must be less than
 *			 256)
 * @param [in] num_x509 Number of preallocated X.509 certificate structures
 *			(must be less than 256)
 */
#define LC_PKCS7_MSG_SIZE(num_sinfo, num_x509)                                 \
	sizeof(struct lc_pkcs7_message) +                                      \
		num_sinfo * sizeof(struct lc_pkcs7_signed_info) +              \
		num_x509 * sizeof(struct lc_x509_certificate)

/**
 * @ingroup PKCS7
 * @brief Allocate memory for struct lc_pkcs7_message holding given number of
 *	  preallocated sinfo members
 *
 * This allocation allows the PKCS7 parsing to avoid allocate memory and keep
 * all operations on stack. In case more signers than \p num_sinfo or more
 * X.509 certificates than \p num_x509 are parsed from the PKCS7 message,
 * then first all pre-allocated structures are used and then new ones are
 * allocated.
 *
 * When not using this macro, which is perfectly legal, an simply allocating
 * \p struct lc_pkcs7_message on stack, then for all parsed signers and
 * X.509 certificates, a new memory entry is allocated.
 *
 * Zeroize the data structure with the size provided by \p LC_PKCS7_MSG_SIZE.
 *
 * @param [in] name Name of stack variable
 * @param [in] num_sinfo Number of preallocated sinfo members (must be less than
 *			 256)
 * @param [in] num_x509 Number of preallocated X.509 certificate structures
 *			(must be less than 256)
 */
#define LC_PKCS7_MSG_ON_STACK(name, num_sinfo, num_x509)                       \
	_Pragma("GCC diagnostic push") _Pragma(                                \
		"GCC diagnostic ignored \"-Wdeclaration-after-statement\"")    \
		_Pragma("GCC diagnostic ignored \"-Wcast-align\"")             \
			LC_ALIGNED_BUFFER(                                     \
				name##_ctx_buf,                                \
				LC_PKCS7_MSG_SIZE(num_sinfo, num_x509), 8);    \
	struct lc_pkcs7_message *name =                                        \
		(struct lc_pkcs7_message *)name##_ctx_buf;                     \
	(name)->avail_preallocated_sinfo = num_sinfo;                          \
	(name)->preallocated_sinfo =                                           \
		(struct lc_pkcs7_signed_info                                   \
			 *)((uint8_t *)(name) +                                \
			    sizeof(struct lc_pkcs7_message));                  \
	(name)->avail_preallocated_x509 = num_x509;                            \
	(name)->preallocated_x509 =                                            \
		(struct lc_x509_certificate                                    \
			 *)((uint8_t *)(name) +                                \
			    sizeof(struct lc_pkcs7_message) +                  \
			    num_sinfo * sizeof(struct lc_pkcs7_signed_info));  \
	_Pragma("GCC diagnostic pop")

#ifdef __cplusplus
}
#endif

#endif /* LC_PKCS7_COMMON_H */
