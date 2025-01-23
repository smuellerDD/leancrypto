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

#ifndef X509_CERT_PARSER_H
#define X509_CERT_PARSER_H

#include "ext_headers.h"

#include "asym_key.h"
#include "asymmetric_type.h"
#include "lc_x509_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

struct x509_parse_context {
	struct lc_x509_certificate *cert; /* Certificate being constructed */
	const uint8_t *key; /* Public key data */
	size_t key_size; /* Size of public key data */
	const uint8_t *data; /* TODO remove Start of data */
	const uint8_t *params; /* Key parameters */
	size_t params_size; /* Size of key parameters */
	size_t raw_akid_size;
	const uint8_t *raw_akid; /* Raw authorityKeyId in ASN.1 */
	const uint8_t *akid_raw_issuer; /* Raw directoryName in authorityKeyId */
	size_t akid_raw_issuer_size;
	unsigned int extension_critical : 1;
	uint16_t o_offset; /* Offset of organizationName (O) */
	uint16_t cn_offset; /* Offset of commonName (CN) */
	uint16_t email_offset; /* Offset of emailAddress */
	enum OID key_algo; /* Algorithm used by the cert's key */
	enum OID last_oid; /* Last OID encountered */
	enum OID sig_algo; /* Algorithm used to sign the cert */
	uint8_t o_size; /* Size of organizationName (O) */
	uint8_t cn_size; /* Size of commonName (CN) */
	uint8_t email_size; /* Size of emailAddress */
};

struct x509_flag_name {
	uint16_t val;
	const char *name;
	size_t namelen;
	enum OID oid;
};

extern const struct x509_flag_name x509_eku_to_name[];
extern const unsigned int x509_eku_to_name_size;
extern const struct x509_flag_name x509_keyusage_to_name[];
extern const unsigned int x509_keyusage_to_name_size;

int lc_x509_cert_oid_to_eku(enum OID oid, uint16_t *eku);

/**
 * @brief Decode an X.509 time ASN.1 object
 * @param [out] _t The time to fill in
 * @param [in] hdrlen: The length of the object header
 * @param [in] tag The object tag
 * @param [in] value The object value
 * @param [in] vlen The size of the object value
 *
 * Decode an ASN.1 universal time or generalised time field into a struct the
 * kernel can handle and check it for validity.  The time is decoded thus:
 *
 *	[RFC5280 §4.1.2.5]
 *	CAs conforming to this profile MUST always encode certificate validity
 *	dates through the year 2049 as UTCTime; certificate validity dates in
 *	2050 or later MUST be encoded as GeneralizedTime.  Conforming
 *	applications MUST be able to process validity dates that are encoded in
 *	either UTCTime or GeneralizedTime.
 */
int x509_decode_time(time64_t *_t, size_t hdrlen, unsigned char tag,
		     const uint8_t *value, size_t vlen);
/*
 * x509_public_key.c
 */
/*
 * Set the proper digest size for the hashes used in X.509 / PKCS7
 */
int x509_set_digestsize(size_t *digestsize, struct lc_hash_ctx *hash_ctx);
int x509_get_sig_params(struct lc_x509_certificate *cert);
int x509_check_for_self_signed(struct lc_x509_certificate *cert);

#ifdef __cplusplus
}
#endif

#endif /* X509_CERT_PARSER_H */
