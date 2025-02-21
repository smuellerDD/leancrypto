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

#ifndef LC_X509_COMMON_H
#define LC_X509_COMMON_H

#include "ext_headers.h"
#include "lc_asn1.h"
#include "lc_hash.h"

#if defined __has_include
#if __has_include("lc_dilithium.h")
#include "lc_dilithium.h"
#define LC_DILITHIUM_ENABLED
#endif
#if __has_include("lc_sphincs.h")
#include "lc_sphincs.h"
#define LC_SPHINCS_ENABLED
#endif
#else
#error "Compiler misses __has_include"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/// \cond DO_NOT_DOCUMENT

/*
 * Default hash type used to generate the SKID / AKID from the public key.
 * The algorithm is only used if the caller does not set an SKID/AKID.
 *
 * NOTE: X.509 support requires asymmetric algorithms. All asymmetric algorithms
 * require the presence of SHA-3 which means the use of SHA-3 is a safe choice.
 */
#define LC_X509_SKID_DEFAULT_HASH lc_sha3_256
#define LC_X509_SKID_DEFAULT_HASHSIZE LC_SHA3_256_SIZE_DIGEST

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
struct lc_asymmetric_key_id {
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
struct lc_public_key {
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
#define LC_KEY_USAGE_MASK                                                      \
	((uint16_t)~(LC_KEY_USAGE_CRITICAL | LC_KEY_USAGE_EXTENSION_PRESENT))

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
#define LC_KEY_EKU_MASK                                                        \
	((uint16_t)~LC_KEY_EKU_CRITICAL | LC_KEY_EKU_EXTENSION_PRESENT)

	uint8_t basic_constraint;
#define LC_KEY_CA (1 << 2)
#define LC_KEY_NOCA (1 << 1)
#define LC_KEY_BASIC_CONSTRAINT_CRITICAL (1 << 0)
#define LC_KEY_IS_CA (LC_KEY_CA | LC_KEY_BASIC_CONSTRAINT_CRITICAL)

	uint8_t ca_pathlen;
#define LC_KEY_CA_MAXLEN 16
#define LC_KEY_CA_MASK ((LC_KEY_CA_MAXLEN << 1) - 1)

	unsigned int key_is_private : 1;
};

/*
 * Public key cryptography signature data
 */
struct lc_public_key_signature {
	/*
	  * Signature
	  */
	const uint8_t *s;

	/*
	  * Number of bytes in signature
	  */
	size_t s_size;

	/*
	 * Digest size (0 if no digest was calculated and in this case the
	 * raw_data is used for signature). In case of having no digest, the
	 * signature algorithm must calculate the signature over the full
	 * ->raw_data.
	 */
	size_t digest_size;
	uint8_t digest[LC_SHA_MAX_SIZE_DIGEST];
	const struct lc_hash *hash_algo;
	unsigned int request_prehash : 1;

	enum lc_sig_types pkey_algo;

	/*
	 * Pointers to raw daa to be signed in case no message digest is
	 * calculated. This pointer is set if no message digest is calculated.
	 */
	const uint8_t *raw_data;
	size_t raw_data_len;

	/*
	 * Auth IDs of the signer
	 */
	struct lc_asymmetric_key_id auth_ids[3];
};

struct lc_x509_certificate_name_component {
	const char *value;
	uint8_t size;
};

struct lc_x509_certificate_name {
	struct lc_x509_certificate_name_component email;
	struct lc_x509_certificate_name_component cn;
	struct lc_x509_certificate_name_component ou;
	struct lc_x509_certificate_name_component o;
	struct lc_x509_certificate_name_component st;
	struct lc_x509_certificate_name_component c;
};

/*
 * The X.509 Generator also uses the parser for final operations. This
 * data structure encapsulates the information only required during generation.
 */
struct lc_x509_key_data {
	enum lc_sig_types sig_type;
	unsigned int data_struct_size;
	union {
		struct lc_dilithium_pk *dilithium_pk;
		struct lc_dilithium_ed25519_pk *dilithium_ed25519_pk;
		struct lc_sphincs_pk *sphincs_pk;
	} pk;
	union {
		struct lc_dilithium_sk *dilithium_sk;
		struct lc_dilithium_ed25519_sk *dilithium_ed25519_sk;
		struct lc_sphincs_sk *sphincs_sk;
	} sk;
	uint8_t pk_digest[LC_X509_SKID_DEFAULT_HASHSIZE];
};

struct lc_x509_certificate {
	struct lc_x509_certificate *next;
	struct lc_x509_certificate *signer; /* Certificate that signed this one */
	struct lc_x509_key_data sig_gen_data;
	struct lc_x509_key_data pub_gen_data;
	struct lc_public_key pub; /* Public key details */
	struct lc_public_key_signature sig; /* Signature parameters */
	struct lc_asymmetric_key_id id; /* Issuer + Serial number */
	struct lc_asymmetric_key_id skid; /* Subject + subjectKeyId (optional) */

	struct lc_x509_certificate_name issuer_segments;
	struct lc_x509_certificate_name subject_segments;
	struct lc_x509_certificate_name san_directory_name_segments;

	/*
	 * Pointer to encoded certificate data. This is used when parsing
	 * a certificate.
	 */
	const uint8_t *raw_cert;
	size_t raw_cert_size;

	const char *san_dns; /* Subject Alternative Name DNS */
	size_t san_dns_len;
	const uint8_t *san_ip; /* Subject Alternative Name IP */
	size_t san_ip_len;
	time64_t valid_from; /* Time since EPOCH in UTC */
	time64_t valid_to; /* Time since EPOCH in UTC */
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
	char subject[LC_ASN1_MAX_ISSUER_NAME +
		     1]; /* Name of certificate subject */

	uint8_t x509_version; /* X.509 Version of certificate */
	unsigned int seen : 1; /* Infinite recursion prevention */
	unsigned int verified : 1;
	unsigned int
		self_signed : 1; /* T if self-signed (check unsupported_sig too) */
	unsigned int
		unsupported_sig : 1; /* T if signature uses unsupported crypto */
	unsigned int blacklisted : 1;
	unsigned int allocated : 1;
};

/// \endcond

/**
 * @brief Convert a leancrypto public key algorithm reference into human
 *	  readable form
 *
 * @param [in] pkey_algo public key algorithm type
 *
 * @return character string with the name
 */
const char *lc_x509_sig_type_to_name(enum lc_sig_types pkey_algo);

/**
 * @brief Obtain the hash type to be used with a given public key algorithm
 *
 * @param [in] pkey_algo public key algorithm type
 * @param [out] hash_algo Hash reference (or NULL if none is to be used)
 *
 * @return 0 on success, < 0 on error
 */
int lc_x509_sig_type_to_hash(enum lc_sig_types pkey_algo,
			     const struct lc_hash **hash_algo);

#ifdef __cplusplus
}
#endif

#endif /* LC_X509_COMMON_H */
