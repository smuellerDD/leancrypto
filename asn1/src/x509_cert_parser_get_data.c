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

#include "asn1_debug.h"
#include "asym_key_dilithium_ed25519.h"
#include "ext_headers.h"
#include "helper.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "lc_x509_parser.h"
#include "x509_cert_parser.h"

#ifdef LC_DILITHIUM_ED25519
LC_INTERFACE_FUNCTION(int, lc_x509_cert_load_pk_dilithium_ed25519,
		      struct lc_dilithium_ed25519_pk *dilithium_ed25519_pk,
		      const uint8_t *pk_ptr, size_t pk_len)
{
	int ret;

	CKINT(public_key_decode_dilithium_ed25519(dilithium_ed25519_pk,
						  pk_ptr, pk_len));

out:
	return ret;
}
#endif

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_pubkey,
		      const struct lc_x509_certificate *cert,
		      const uint8_t **pk, size_t *pk_size,
		      enum lc_sig_types *key_type)
{
	const struct lc_public_key *pub;
	int ret = 0;

	CKNULL(cert, -EINVAL);

	pub = &cert->pub;

	CKNULL(pub->key, -EOPNOTSUPP);

	if (pk)
		*pk = pub->key;
	if (pk_size)
		*pk_size = pub->keylen;
	if (key_type)
		*key_type = pub->pkey_algo;

out:
	return ret;
}

/******************************************************************************
 * EKU
 ******************************************************************************/

// clang-format off
const struct x509_flag_name x509_eku_to_name[] =
{
	{ .val = LC_KEY_EKU_CRITICAL, .name = "critical", .namelen = 8, .oid = 0 },
	{ .val = LC_KEY_EKU_ANY, .name = "any", .namelen = 3, .oid = OID_anyExtendedKeyUsage },
	{ .val = LC_KEY_EKU_SERVER_AUTH, .name = "serverAuth", .namelen = 10, .oid = OID_id_kp_serverAuth },
	{ .val = LC_KEY_EKU_CLIENT_AUTH, .name = "clientAuth", .namelen = 10, .oid = OID_id_kp_clientAuth },
	{ .val = LC_KEY_EKU_CODE_SIGNING, .name = "codeSigning", .namelen = 11, .oid = OID_id_kp_codeSigning },
	{ .val = LC_KEY_EKU_EMAIL_PROTECTION, .name = "emailProtection", .namelen = 15, .oid = OID_id_kp_emailProtection },
	{ .val = LC_KEY_EKU_TIME_STAMPING, .name = "timeStamping", .namelen = 12, .oid = OID_id_kp_timeStamping },
	{ .val = LC_KEY_EKU_OCSP_SIGNING, .name = "OCSPSigning", .namelen = 11, .oid = OID_id_kp_OCSPSigning },
};
// clang-format on

const unsigned int x509_eku_to_name_size = ARRAY_SIZE(x509_eku_to_name);

int lc_x509_cert_oid_to_eku(enum OID oid, uint16_t *eku)
{
	unsigned int i;

	for (i = 0; i < x509_eku_to_name_size; i++) {
		if (oid == x509_eku_to_name[i].oid) {
			*eku = x509_eku_to_name[i].val;
			return 0;
		}
	}

	return -ENOENT;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_eku,
		      const struct lc_x509_certificate *cert,
		      const char ***eku_names, unsigned int *num_eku)
{
	const struct lc_public_key *pub;
	unsigned int i, num = 0;
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(eku_names, -EINVAL);
	CKNULL(num_eku, -EINVAL);

	pub = &cert->pub;

	for (i = 0; i < x509_eku_to_name_size; i++) {
		if (pub->key_eku & x509_eku_to_name[i].val)
			*eku_names[num++] = x509_eku_to_name[i].name;
	}

	*num_eku = num;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_eku_val,
		      const struct lc_x509_certificate *cert, uint16_t *val)
{
	const struct lc_public_key *pub;
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(val, -EINVAL);

	pub = &cert->pub;
	*val = pub->key_eku;

out:
	return ret;
}

/******************************************************************************
 * Key Usage
 ******************************************************************************/

// clang-format off
const struct x509_flag_name x509_keyusage_to_name[] =
{
	{ .val = LC_KEY_USAGE_CRITICAL, .name = "critical", .namelen = 8 },
	{ .val = LC_KEY_USAGE_DIGITALSIG, .name = "digitalSignature", .namelen = 16 },
	{ .val = LC_KEY_USAGE_CONTENT_COMMITMENT, .name = "contentCommitment", .namelen = 17 },
	{ .val = LC_KEY_USAGE_KEY_ENCIPHERMENT, .name = "keyEncipherment", .namelen = 15 },
	{ .val = LC_KEY_USAGE_DATA_ENCIPHERMENT, .name = "dataEncipherment", .namelen = 16 },
	{ .val = LC_KEY_USAGE_KEY_AGREEMENT, .name = "keyAgreement", .namelen = 12 },
	{ .val = LC_KEY_USAGE_KEYCERTSIGN, .name = "keyCertSign", .namelen = 11 },
	{ .val = LC_KEY_USAGE_CRLSIGN, .name = "cRLSign", .namelen = 7 },
	{ .val = LC_KEY_USAGE_ENCIPHER_ONLY, .name = "encipherOnly", .namelen = 12 },
	{ .val = LC_KEY_USAGE_DECIPHER_ONLY, .name = "decipherOnly", .namelen = 12 },
};
// clang-format on

const unsigned int x509_keyusage_to_name_size =
	ARRAY_SIZE(x509_keyusage_to_name);

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_keyusage,
		      const struct lc_x509_certificate *cert,
		      const char ***keyusage_names, unsigned int *num_keyusage)
{
	const struct lc_public_key *pub;
	unsigned int i, num = 0;
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(keyusage_names, -EINVAL);
	CKNULL(num_keyusage, -EINVAL);

	pub = &cert->pub;

	for (i = 0; i < x509_keyusage_to_name_size; i++) {
		if (pub->key_usage & x509_keyusage_to_name[i].val)
			*keyusage_names[num++] = x509_keyusage_to_name[i].name;
	}

	*num_keyusage = num;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_keyusage_val,
		      const struct lc_x509_certificate *cert, uint16_t *val)
{
	const struct lc_public_key *pub;
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(val, -EINVAL);

	pub = &cert->pub;
	*val = pub->key_usage;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_san_dns,
		      const struct lc_x509_certificate *cert,
		      const char **san_dns_name, size_t *san_dns_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(san_dns_name, -EINVAL);
	CKNULL(san_dns_len, -EINVAL);

	*san_dns_name = cert->san_dns;
	*san_dns_len = cert->san_dns_len;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_dec_san_ip, const uint8_t *ip, size_t ip_len,
		      char *ip_name, size_t ip_name_len)
{
	int ret = 0;

	CKNULL(ip, -EINVAL);
	CKNULL(ip_name, -EINVAL);

	if (ip_len == 16) {
		snprintf(
			ip_name, ip_name_len,
			"%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x",
			ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
			ip[8], ip[8], ip[10], ip[11], ip[12], ip[13], ip[14],
			ip[15]);
	} else {
		snprintf(ip_name, ip_name_len, "%3u.%3u.%3u.%3u", ip[0], ip[1],
			 ip[2], ip[3]);
	}

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_san_ip,
		      const struct lc_x509_certificate *cert,
		      const uint8_t **san_ip, size_t *san_ip_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(san_ip, -EINVAL);
	CKNULL(san_ip_len, -EINVAL);

	*san_ip = cert->san_ip;
	*san_ip_len = cert->san_ip_len;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_skid,
		      const struct lc_x509_certificate *cert,
		      const uint8_t **skid, size_t *skidlen)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(skid, -EINVAL);
	CKNULL(skidlen, -EINVAL);

	*skid = cert->raw_skid;
	*skidlen = cert->raw_skid_size;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_akid,
		      const struct lc_x509_certificate *cert,
		      const uint8_t **akid, size_t *akidlen)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(akid, -EINVAL);
	CKNULL(akidlen, -EINVAL);

	*akid = cert->raw_akid;
	*akidlen = cert->raw_akid_size;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_valid_from,
		      const struct lc_x509_certificate *cert,
		      time64_t *time_since_epoch)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(time_since_epoch, -EINVAL);

	*time_since_epoch = cert->valid_from;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_valid_to,
		      const struct lc_x509_certificate *cert,
		      time64_t *time_since_epoch)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(time_since_epoch, -EINVAL);

	*time_since_epoch = cert->valid_to;

out:
	return ret;
}

static int
x509_cert_get_string(const struct lc_x509_certificate_name_component *component,
		     const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(string, -EINVAL);
	CKNULL(string_len, -EINVAL);

	*string = component->value;
	*string_len = component->size;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_subject_cn,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->subject_segments.cn, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_subject_email,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->subject_segments.email, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_subject_ou,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->subject_segments.ou, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_subject_o,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->subject_segments.o, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_subject_st,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->subject_segments.st, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_subject_c,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->subject_segments.c, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_issuer_cn,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->issuer_segments.cn, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_issuer_email,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->issuer_segments.email, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_issuer_ou,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->issuer_segments.ou, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_issuer_o,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->issuer_segments.o, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_issuer_st,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->issuer_segments.st, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_issuer_c,
		      const struct lc_x509_certificate *cert,
		      const char **string, size_t *string_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_get_string(&cert->issuer_segments.c, string,
				   string_len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_get_serial,
		      const struct lc_x509_certificate *cert,
		      const uint8_t **serial, size_t *serial_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(serial, -EINVAL);
	CKNULL(serial_len, -EINVAL);

	*serial = cert->raw_serial;
	*serial_len = cert->raw_serial_size;

out:
	return ret;
}
