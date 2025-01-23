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
#include "asym_key_dilithium.h"
#include "asym_key_dilithium_ed25519.h"
#include "asym_key_sphincs.h"
#include "ext_headers.h"
#include "helper.h"
#include "lc_memcmp_secure.h"
#include "lc_x509_generator.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "x509_cert_parser.h"

/******************************************************************************
 * EKU
 ******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_eku,
		      struct lc_x509_certificate *cert, const char *name)
{
	struct lc_public_key *pub;
	size_t namelen;
	unsigned int i;
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(name, -EINVAL);

	pub = &cert->pub;

	namelen = strlen(name);

	for (i = 0; i < x509_eku_to_name_size; i++) {
		if (!lc_memcmp_secure(name, namelen, x509_eku_to_name[i].name,
				      x509_eku_to_name[i].namelen)) {
			pub->key_eku |= x509_eku_to_name[i].val;
			goto out;
		}
	}

	printf("Allowed Extended Key Usage (EKU) flags:\n");
	for (i = 0; i < x509_eku_to_name_size; i++)
		printf(" %s\n", x509_eku_to_name[i].name);

	return -EINVAL;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_eku_val,
		      struct lc_x509_certificate *cert, uint16_t val)
{
	struct lc_public_key *pub;
	int ret = 0;

	CKNULL(cert, -EINVAL);

	pub = &cert->pub;
	pub->key_eku = val;

out:
	return ret;
}

/******************************************************************************
 * Key Usage
 ******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_keyusage,
		      struct lc_x509_certificate *cert, const char *name)
{
	struct lc_public_key *pub;
	size_t namelen;
	unsigned int i;
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(name, -EINVAL);

	pub = &cert->pub;

	namelen = strlen(name);

	for (i = 0; i < x509_keyusage_to_name_size; i++) {
		if (!lc_memcmp_secure(name, namelen,
				      x509_keyusage_to_name[i].name,
				      x509_keyusage_to_name[i].namelen)) {
			pub->key_usage |= x509_keyusage_to_name[i].val;
			goto out;
		}
	}

	printf("Allowed Key Usage flags:\n");
	for (i = 0; i < x509_keyusage_to_name_size; i++)
		printf(" %s\n", x509_keyusage_to_name[i].name);

	return -EINVAL;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_keyusage_val,
		      struct lc_x509_certificate *cert, uint16_t val)
{
	struct lc_public_key *pub;
	int ret = 0;

	CKNULL(cert, -EINVAL);

	pub = &cert->pub;
	pub->key_usage = val;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_ca,
		      struct lc_x509_certificate *cert)
{
	struct lc_public_key *pub;
	size_t paramlen = 0;
	const char *param;
	int ret = 0;

	CKNULL(cert, -EINVAL);

	pub = &cert->pub;
	pub->ca_pathlen = LC_KEY_CA_CRITICAL | LC_KEY_CA_MAXLEN;

	/* Set AKID by pointing to the SKID */
	if (!cert->raw_akid) {
		if (cert->raw_skid) {
			/* If SKID was already set, point to it */
			CKINT(lc_x509_cert_set_akid(cert, cert->raw_skid,
						    cert->raw_skid_size));
		} else {
			/* Otherwise point to the default SKID */
			const struct lc_x509_key_data *gendata =
				&cert->pub_gen_data;

			CKINT(lc_x509_cert_set_akid(cert, gendata->pk_digest,
						    sizeof(gendata->pk_digest)));
		}
	}

	/* Set issuer */
	CKINT(lc_x509_cert_get_subject_c(cert, &param, &paramlen));
	CKINT(lc_x509_cert_set_issuer_c(cert, param, paramlen));

	CKINT(lc_x509_cert_get_subject_st(cert, &param, &paramlen));
	CKINT(lc_x509_cert_set_issuer_st(cert, param, paramlen));

	CKINT(lc_x509_cert_get_subject_o(cert, &param, &paramlen));
	CKINT(lc_x509_cert_set_issuer_o(cert, param, paramlen));

	CKINT(lc_x509_cert_get_subject_ou(cert, &param, &paramlen));
	CKINT(lc_x509_cert_set_issuer_ou(cert, param, paramlen));

	CKINT(lc_x509_cert_get_subject_cn(cert, &param, &paramlen));
	CKINT(lc_x509_cert_set_issuer_cn(cert, param, paramlen));

	CKINT(lc_x509_cert_get_subject_email(cert, &param, &paramlen));
	CKINT(lc_x509_cert_set_issuer_email(cert, param, paramlen));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_san_dns,
		      struct lc_x509_certificate *cert,
		      const char *san_dns_name)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(san_dns_name, -EINVAL);

	cert->san_dns = san_dns_name;
	cert->san_dns_len = strlen(san_dns_name);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_enc_san_ip, struct lc_x509_certificate *cert,
		      char *ip_name, uint8_t *ip, size_t *ip_len)
{
	unsigned long val;
	char *saveptr = NULL;
	char *res = NULL;
	const char *tok = ".";
	unsigned int i, upper = 4;
	int ret = 0, base = 10;

	CKNULL(cert, -EINVAL);
	CKNULL(ip_name, -EINVAL);
	CKNULL(ip, -EINVAL);
	CKNULL(ip_len, -EINVAL);

	/* Check for IPv6 */
	if (strstr(ip_name, ":")) {
		tok = ":";
		upper = 16;
		base = 16;
	}

	if (*ip_len < upper)
		return -EOVERFLOW;

	res = strtok_r(ip_name, tok, &saveptr);
	for (i = 0; i < upper; i++) {
		CKNULL(res, -EINVAL);
		val = strtoul(res, NULL, base);
		if (val > 255)
			return -EINVAL;
		ip[i] = (uint8_t)val;
		res = strtok_r(NULL, tok, &saveptr);
	}

	*ip_len = i;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_san_ip,
		      struct lc_x509_certificate *cert, const uint8_t *san_ip,
		      size_t san_ip_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(san_ip, -EINVAL);

	cert->san_ip = san_ip;
	cert->san_ip_len = san_ip_len;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_skid,
		      struct lc_x509_certificate *cert, const uint8_t *skid,
		      size_t skidlen)
{
	const struct lc_x509_key_data *gendata = &cert->pub_gen_data;
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(skid, -EINVAL);

	cert->raw_skid = skid;
	cert->raw_skid_size = skidlen;

	/*
	 * In case AKID was set to the default SKID, then we implicitly have a
	 * CA certificate. Thus, if a separate SKID was set, change it to the
	 * newly set SKID.
	 */
	if (cert->raw_akid == gendata->pk_digest) {
		CKINT(lc_x509_cert_set_akid(cert, cert->raw_skid,
					    cert->raw_skid_size));
	}

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_akid,
		      struct lc_x509_certificate *cert, const uint8_t *akid,
		      size_t akidlen)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(akid, -EINVAL);

	cert->raw_akid = akid;
	cert->raw_akid_size = akidlen;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_valid_from,
		      struct lc_x509_certificate *cert,
		      time64_t time_since_epoch)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);

	cert->valid_from = time_since_epoch;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_valid_to,
		      struct lc_x509_certificate *cert,
		      time64_t time_since_epoch)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);

	cert->valid_to = time_since_epoch;

out:
	return ret;
}

static int
x509_cert_set_string(struct lc_x509_certificate_name_component *component,
		     const char *string, size_t len)
{
	/* Allow setting a NULL value */

	if (len > 0xff)
		return -EOVERFLOW;

	component->value = string;
	component->size = (uint8_t)len;

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_subject_cn,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->subject_segments.cn, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_subject_email,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->subject_segments.email, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_subject_ou,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->subject_segments.ou, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_subject_o,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->subject_segments.o, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_subject_st,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->subject_segments.st, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_subject_c,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->subject_segments.c, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_issuer_cn,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->issuer_segments.cn, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_issuer_email,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->issuer_segments.email, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_issuer_ou,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->issuer_segments.ou, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_issuer_o,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->issuer_segments.o, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_issuer_st,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->issuer_segments.st, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_issuer_c,
		      struct lc_x509_certificate *cert, const char *string,
		      size_t len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKINT(x509_cert_set_string(&cert->issuer_segments.c, string, len));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_serial,
		      struct lc_x509_certificate *cert, const uint8_t *serial,
		      size_t serial_len)
{
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(serial, -EINVAL);

	cert->raw_serial = serial;
	cert->raw_serial_size = serial_len;

out:
	return ret;
}
