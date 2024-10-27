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

#ifndef LC_X509_H
#define LC_X509_H

#include "ext_headers.h"
#include "lc_asn1.h"
#include "lc_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT
typedef int64_t time64_t;

/*
 * Identifiers for an asymmetric key ID.  We have three ways of looking up a
 * key derived from an X.509 certificate:
 *
 * (1) Serial Number & Issuer.  Non-optional.  This is the only valid way to
 *     map a PKCS#7 signature to an X.509 certificate.
 *
 * (2) Issuer & Subject Unique IDs.  Optional.  These were the original way to
 *     match X.509 certificates, but have fallen into disuse in favour of (3).
 *
 * (3) Auth & Subject Key Identifiers.  Optional.  SKIDs are only provided on
 *     CA keys that are intended to sign other keys, so don't appear in end
 *     user certificates unless forced.
 *
 * We could also support an PGP key identifier, which is just a SHA1 sum of the
 * public key and certain parameters, but since we don't support PGP keys at
 * the moment, we shall ignore those.
 *
 * What we actually do is provide a place where binary identifiers can be
 * stashed and then compare against them when checking for an id match.
 *
 * The following size constraints are considered:
 *
 * * Serial number can be up to 20 octets (RFC 5280 section 4.1.2.2)
 *
 * * Subject Key Identifier can be SHA-1 or other sizes (RFC 5280 section
 *   4.2.1.2) - we allow up to 64 bytes
 *
 * * Issuer can be an arbitrary size of bytes but at least one (RFC 5280
 *   section 4.1.2.4) - we apply the upper limit of 128 bytes
 *
 * * Subject Key Identifier "MAY be based on either the key identifier (the
 *   subject key identifier in the issuer's certificate) or the issuer name
 *   and serial number." (RFC 5280 section 4.2.1.1)
 */
#define LC_ASN1_MAX_ISSUER_NAME 128
#define LC_ASN1_MAX_SKID 64
struct asymmetric_key_id {
	uint8_t len;
	uint8_t data[LC_ASN1_MAX_SKID + LC_ASN1_MAX_ISSUER_NAME];
};

enum lc_sig_types {
	/** Undefined signature */
	LC_SIG_UNKNOWN,
	/** ML-DSA / Dilithium 44 */
	LC_SIG_DILITHIUM_44,
	/** ML-DSA / Dilithium 65 */
	LC_SIG_DILITHIUM_65,
	/** ML-DSA / Dilithium 87 */
	LC_SIG_DILITHIUM_87,
	/** ML-DSA / Dilithium 44 hybrid with ED25519 */
	LC_SIG_DILITHIUM_44_ED25519,
	/** ML-DSA / Dilithium 65 hybrid with ED25519 */
	LC_SIG_DILITHIUM_65_ED25519,
	/** ML-DSA / Dilithium 87 hybrid with ED25519 */
	LC_SIG_DILITHIUM_87_ED25519,
	/** ML-DSA / Dilithium 87 hybrid with ED448 */
	LC_SIG_DILITHIUM_87_ED448,
	/** SLH-DSA / Sphincs Plus SHAKE 256s */
	LC_SIG_SPINCS_SHAKE_256S,
	/** SLH-DSA / Sphincs Plus SHAKE 256f */
	LC_SIG_SPINCS_SHAKE_256F,
	/** SLH-DSA / Sphincs Plus SHAKE 192s */
	LC_SIG_SPINCS_SHAKE_192S,
	/** SLH-DSA / Sphincs Plus SHAKE 192f */
	LC_SIG_SPINCS_SHAKE_192F,
	/** SLH-DSA / Sphincs Plus SHAKE 128s */
	LC_SIG_SPINCS_SHAKE_128S,
	/** SLH-DSA / Sphincs Plus SHAKE 128f */
	LC_SIG_SPINCS_SHAKE_128F,

	/** RSA with PKCS1 */
	LC_SIG_RSA_PKCS1,
	/** ECDSA following X9.63 */
	LC_SIG_ECDSA_X963,
	/** SM2 */
	LC_SIG_SM2,
	/** ECRDSA with PKCS1 */
	LC_SIG_ECRDSA_PKCS1,
};

/*
 * Cryptographic data for the public-key subtype of the asymmetric key type.
 *
 * Note that this may include private part of the key as well as the public
 * part.
 */
struct public_key {
	const uint8_t *key;
	size_t keylen;
	const uint8_t *params;
	size_t paramlen;
	const char *id_type;
	enum OID algo;
	enum lc_sig_types pkey_algo;

	uint16_t key_usage; /* key extension flags */
#define LC_KEY_USAGE_DIGITALSIG 0x0080 /* (0) */
#define LC_KEY_USAGE_CONTENT_COMMITMENT 0x0040 /* (1) */
#define LC_KEY_USAGE_KEY_ENCIPHERMENT 0x0020 /* (2) */
#define LC_KEY_USAGE_DATA_ENCIPHERMENT 0x0010 /* (3) */
#define LC_KEY_USAGE_KEY_AGREEMENT 0x0008 /* (4) */
#define LC_KEY_USAGE_KEYCERTSIGN 0x0004 /* (5) */
#define LC_KEY_USAGE_CRLSIGN 0x0002 /* (6) */
#define LC_KEY_USAGE_ENCIPHER_ONLY 0x0001 /* (7) */
#define LC_KEY_USAGE_DECIPHER_ONLY 0x8000 /* (8) */
#define LC_KEY_USAGE_CRITICAL 0x4000
#define LC_KEY_USAGE_EXTENSION_PRESENT 0x2000

	uint16_t key_eku;
#define LC_KEY_EKU_CRITICAL (1 << 1)
#define LC_KEY_EKU_EXTENSION_PRESENT (1 << 2)
#define LC_KEY_EKU_ANY (1 << 3)
#define LC_KEY_EKU_SERVER_AUTH (1 << 4)
#define LC_KEY_EKU_CLIENT_AUTH (1 << 5)
#define LC_KEY_EKU_CODE_SIGNING (1 << 6)
#define LC_KEY_EKU_EMAIL_PROTECTION (1 << 7)
#define LC_KEY_EKU_TIME_STAMPING (1 << 8)
#define LC_KEY_EKU_OCSP_SIGNING (1 << 9)

	uint8_t ca_pathlen;
#define LC_KEY_CA_CRITICAL 0x80
#define LC_KEY_CA_MAXLEN 16
#define LC_KEY_CA_MASK ((LC_KEY_CA_MAXLEN << 1) - 1)

	unsigned int key_is_private : 1;
};

/*
 * Public key cryptography signature data
 */
struct public_key_signature {
	const uint8_t *s; /* Signature */
	size_t s_size; /* Number of bytes in signature */
	size_t digest_size;
	const struct lc_hash *hash_algo;
	enum lc_sig_types pkey_algo;
	uint8_t digest[LC_SHA_MAX_SIZE_DIGEST];
	struct asymmetric_key_id auth_ids[3];
};

struct x509_certificate_name_component {
	const uint8_t *value;
	uint8_t size;
};

struct x509_certificate_name {
	struct x509_certificate_name_component email;
	struct x509_certificate_name_component cn;
	struct x509_certificate_name_component ou;
	struct x509_certificate_name_component o;
	struct x509_certificate_name_component st;
	struct x509_certificate_name_component c;
};

struct x509_certificate {
	struct x509_certificate *next;
	struct x509_certificate *signer; /* Certificate that signed this one */
	struct public_key pub; /* Public key details */
	struct public_key_signature sig; /* Signature parameters */
	struct asymmetric_key_id id; /* Issuer + Serial number */
	struct asymmetric_key_id skid; /* Subject + subjectKeyId (optional) */

	struct x509_certificate_name issuer_segments;
	struct x509_certificate_name subject_segments;
	const char *san_dns; /* Subject Alternative Name DNS */
	size_t san_dns_len;
	const uint8_t *san_ip; /* Subject Alternative Name IP */
	size_t san_ip_len;
	time64_t valid_from;
	time64_t valid_to;
	const uint8_t *tbs; /* Signed data */
	size_t tbs_size; /* Size of signed data */
	size_t raw_sig_size; /* Size of signature */
	const uint8_t *raw_sig; /* Signature data */
	const uint8_t *raw_serial; /* Raw serial number in ASN.1 */
	size_t raw_serial_size;
	size_t raw_issuer_size;
	const uint8_t *raw_issuer; /* Raw issuer name in ASN.1 */
	const uint8_t *raw_subject; /* Raw subject name in ASN.1 */
	size_t raw_subject_size;
	size_t raw_skid_size;
	const uint8_t *raw_skid; /* subjectKeyId in binary format */
	size_t raw_akid_size;
	const uint8_t *raw_akid; /* authority key Id binary format */
	unsigned int index;
	char issuer[LC_ASN1_MAX_ISSUER_NAME + 1]; /* Name of certificate issuer */
	char subject[LC_ASN1_MAX_ISSUER_NAME + 1]; /* Name of certificate subject */
	unsigned int seen : 1; /* Infinite recursion prevention */
	unsigned int verified : 1;
	unsigned int
		self_signed : 1; /* T if self-signed (check unsupported_sig too) */
	unsigned int
		unsupported_sig : 1; /* T if signature uses unsupported crypto */
	unsigned int blacklisted : 1;
};
/// \endcond

/** @defgroup X509 X.509 Certificate Handling
 *
 * Concept of X.509 certificate handling in leancrypto
 *
 * The leancrypto library provides an X.509 parser which can read and understand
 * X.509 certificates. To appropriately use the X.509 parser, please consider
 * the following rules:
 *
 * 1. The parser interprets the provided X.509 data blob and fills a data
 *    structure which allows immediate access to the certificate properties
 *    by the leancrypto code. The data structure \p x509_certificate is provided
 *    as part of the official header file. But it is NOT considered to be an
 *    API. I.e. member variables or the structure format may change between
 *    versions of leancrypto without announcement. The reason for providing the
 *    data structure in the official header file is to support stack-only
 *    clients.
 *
 * 2. The parser fills the data structure with pointers into the original X.509
 *    data blob. The caller MUST keep the original X.509 data blob at the same
 *    location for the life time of the associated instance of the
 *    \p x509_certificate data structure.
 *
 * 3. The X.509 parser API call only interprets and parses the X.509 data blob.
 *    It does NOT enforce any kind of restrictions or policies. The caller
 *    MUST use the provided X.509 policy API to enforce policies on the given
 *    certificate.
 */

/**
 * @ingroup X509
 * @brief Clear the resources used by the X.509 certificate parsing state
 *
 * @param [in] cert Certificate structure to be cleared
 */
void lc_x509_certificate_clear(struct x509_certificate *cert);

/**
 * @ingroup X509
 * @brief Parse an X.509 certificate
 *
 * The function parses an X.509 data buffer into a data structure that allows
 * accessing the various data points of the certificate.
 *
 * \note The \p cert data structure will contain pointers to the \p data
 * buffer. I.e. the certificate parsing analyzes \p data and finds all relevant
 * data in the raw X.509 data blob. The caller MUST therefore keep the
 * \p data pointer constant as long as the \p cert pointer is valid.
 *
 * \note This function only loads and parses the certificate into the data
 * structure to allow leancrypto to immediately access the information. This
 * function call does not validate the certificate (except for a self-signed
 * signature). Thus, the caller MUST apply the X.509 policy check functions
 * to validate the certificate considering that the loading of the certificate
 * has no information about the use case.
 *
 * @param [in,out] cert The data structure that is filled with all parameters
 *			from the X.509 certificate data buffer. The buffer must
 *			have been allocated by the caller. It is permissible
 *			to keep it on the stack.
 * @param [in] data Raw X.509 data blob in DER / BER format
 * @param [in] datalen Length of the raw X.509 certificate buffer
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_certificate_parse(struct x509_certificate *cert,
			      const uint8_t *data, size_t datalen);

/******************************************************************************
 * X.509 Certificate policy service functions
 ******************************************************************************/

/** X.509 Policy checks: returns True or False, or a POSIX error */
typedef int x509_pol_ret_t /* __attribute__((warn_unused_result)) */;

/** X.509 Policy checks: "True" result */
#define LC_X509_POL_TRUE 1

/** X.509 Policy checks: "False" result */
#define LC_X509_POL_FALSE 0

/**
 * @ingroup X509
 * @brief Is the given certificate a CA certificate (root or intermediate)?
 *
 * @param [in] cert Reference to the certificate
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */
x509_pol_ret_t lc_x509_policy_is_ca(const struct x509_certificate *cert);

/**
 * @ingroup X509
 * @brief Can the given certificate validate CRLs?
 *
 * @param [in] cert Reference to the certificate
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */
x509_pol_ret_t
lc_x509_policy_can_validate_crls(const struct x509_certificate *cert);

/**
 * @ingroup X509
 * @brief Is the given certificate a root CA certificate?
 *
 * @param [in] cert Reference to the certificate
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */
x509_pol_ret_t lc_x509_policy_is_root_ca(const struct x509_certificate *cert);

/**
 * @ingroup X509
 * @brief Does the given AKID match the certificate AKID?
 *
 * @param [in] cert Reference to the certificate
 * @param [in] reference_akid AKID in binary format to be matched
 * @param [in] reference_akid_len length of AKID binary buffer
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */
x509_pol_ret_t lc_x509_policy_match_akid(const struct x509_certificate *cert,
					 const uint8_t *reference_akid,
					 size_t reference_akid_len);

/**
 * @ingroup X509
 * @brief Does the given SKID match the certificate SKID?
 *
 * @param [in] cert Reference to the certificate
 * @param [in] reference_skid SKID in binary format to be matched
 * @param [in] reference_skid_len length of SKID binary buffer
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */
x509_pol_ret_t lc_x509_policy_match_skid(const struct x509_certificate *cert,
					 const uint8_t *reference_skid,
					 size_t reference_skid_len);

/**
 * @ingroup X509
 * @brief Check if set of required key usage flags are present
 *
 * @param [in] cert Reference to the certificate
 * @param [in] required_key_usage flags field with the bits set that the
 *				  certificate must contain
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */
x509_pol_ret_t
lc_x509_policy_match_key_usage(const struct x509_certificate *cert,
			       uint16_t required_key_usage);

/**
 * @ingroup X509
 * @brief Check if set of required extended key usage flags are present
 *
 * @param [in] cert Reference to the certificate
 * @param [in] required_eku flags field with the bits set that the certificate
 *			    must contain
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */
x509_pol_ret_t
lc_x509_policy_match_extended_key_usage(const struct x509_certificate *cert,
					uint16_t required_eku);

/**
 * @ingroup X509
 * @brief Check if the given time falls within the range of the certificate
 * validity time.
 *
 * @param [in] cert Reference to the certificate
 * @param [in] current_time Time value to verify - this time is given in seconds
 *			    since EPOCH, e.g. by the POSIX service function
 *			    `time`.
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */

x509_pol_ret_t lc_x509_policy_time_valid(const struct x509_certificate *cert,
					 time64_t current_time);

/**
 * @ingroup X509
 * @brief Check if certificate is valid
 *
 * This check validates all RFC5280 constraints for a conforming certificate.
 *
 * @param [in] cert Reference to the certificate
 *
 * @return < 0 on error, LC_X509_POL_TRUE or LC_X509_POL_FALSE
 */
x509_pol_ret_t lc_x509_policy_cert_valid(const struct x509_certificate *cert);

#ifdef __cplusplus
}
#endif

#endif /* LC_X509_H */
