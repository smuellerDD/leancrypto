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

#include "binhexbin.h"
#include "ext_headers.h"
#include "lc_asn1.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "lc_x509_common.h"
#include "math_helper.h"
#include "visibility.h"
#include "x509_print.h"

static void
print_x509_name_component(unsigned int *comma, const char *prefix,
			  const struct lc_x509_certificate_name_component *comp)
{
	char buf[LC_ASN1_MAX_ISSUER_NAME + 1] = { 0 };

	if (!comp->size)
		return;

	if (*comma)
		printf(", ");
	*comma = 1;
	memcpy(buf, comp->value, min_size(comp->size, LC_ASN1_MAX_ISSUER_NAME));
	printf("%s%s", prefix, buf);
}

static void print_x509_name(const char *prefix,
			    const struct lc_x509_certificate_name *name)
{
	unsigned int i;

	printf("%s: ", prefix);
	i = 0;
	print_x509_name_component(&i, "C = ", &name->c);
	print_x509_name_component(&i, "ST = ", &name->st);
	print_x509_name_component(&i, "O = ", &name->o);
	print_x509_name_component(&i, "OU = ", &name->ou);
	print_x509_name_component(&i, "CN = ", &name->cn);
	print_x509_name_component(&i, "Email = ", &name->email);
	printf("\n");
}

static void _print_x509_sinature_algo(const struct lc_public_key_signature *sig)
{
	const struct lc_hash *hash_algo;

	printf("Signature Algorithm: %s",
	       lc_x509_sig_type_to_name(sig->pkey_algo));

	if (lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo)) {
		printf(" (Cannot resolve signature algorithm)\n");
		return;
	}

	if (hash_algo == lc_sha256)
		printf(" SHA2-256");
	else if (hash_algo == lc_sha384)
		printf(" SHA2-384");
	else if (hash_algo == lc_sha512)
		printf(" SHA2-512");
	else if (hash_algo == lc_sha3_256)
		printf(" SHA3-256");
	else if (hash_algo == lc_sha3_384)
		printf(" SHA3-384");
	else if (hash_algo == lc_sha3_512)
		printf(" SHA3-512");
	else if (hash_algo == NULL)
		printf(" <builtin hash>");
	else
		printf(" <unknown hash>");
	printf("\n");
}

static void print_x509_sinature_algo(const struct lc_x509_certificate *x509)
{
	const struct lc_public_key_signature *sig = &x509->sig;

	_print_x509_sinature_algo(sig);
}

static void print_x509_pubkey_algo(const struct lc_x509_certificate *x509)
{
	const struct lc_public_key *pub = &x509->pub;

	printf("Public Key Algorithm: %s\n",
	       lc_x509_sig_type_to_name(pub->pkey_algo));
}

static void print_x509_bindata(const char *prefix, const uint8_t *data,
			       size_t datalen)
{
	size_t i;

	if (!data || !datalen)
		return;

	printf("%s: ", prefix);
	for (i = 0; i < datalen; i++) {
		if (i)
			printf(":");
		printf("%.02x", data[i]);
	}
	printf("\n");
}

static void print_x509_serial(const struct lc_x509_certificate *x509)
{
	print_x509_bindata("Serial Number", x509->raw_serial,
			   x509->raw_serial_size);
}

static void print_x509_extensions(const struct lc_x509_certificate *x509)
{
	const struct lc_public_key *pub = &x509->pub;

	print_x509_bindata("X509v3 Subject Key Identifier", x509->raw_skid,
			   x509->raw_skid_size);
	print_x509_bindata("X509v3 Authority Key Identifier", x509->raw_akid,
			   x509->raw_akid_size);

	if (pub->ca_pathlen) {
		printf("X509v3 Basic Constraints: CA");
		if (pub->ca_pathlen & LC_KEY_CA_CRITICAL)
			printf(" (critical)");
		if (pub->ca_pathlen < LC_KEY_CA_MAXLEN)
			printf(" (pathlen %u)", pub->ca_pathlen);

		printf("\n");
	}
	if (pub->key_usage) {
		printf("X509v3 Key Usage: ");
		if (pub->key_usage & (LC_KEY_USAGE_CRITICAL))
			printf("(critical) ");
		if (pub->key_usage & (LC_KEY_USAGE_DIGITALSIG))
			printf("digitalSignature ");
		if (pub->key_usage & (LC_KEY_USAGE_CONTENT_COMMITMENT))
			printf("contentCommitment ");
		if (pub->key_usage & (LC_KEY_USAGE_KEY_ENCIPHERMENT))
			printf("keyEncipherment ");
		if (pub->key_usage & (LC_KEY_USAGE_DATA_ENCIPHERMENT))
			printf("dataEncipherment ");
		if (pub->key_usage & (LC_KEY_USAGE_KEYCERTSIGN))
			printf("keyCertSign ");
		if (pub->key_usage & (LC_KEY_USAGE_CRLSIGN))
			printf("cRLSign ");
		if (pub->key_usage & (LC_KEY_USAGE_ENCIPHER_ONLY))
			printf("encipherOnly ");
		if (pub->key_usage & (LC_KEY_USAGE_DECIPHER_ONLY))
			printf("decipherOnly ");
		printf("\n");
	}

	if (pub->key_eku) {
		printf("X509v3 Extended Key Usage: ");
		if (pub->key_eku & (LC_KEY_EKU_CRITICAL))
			printf("(critical) ");

		if (pub->key_eku & (LC_KEY_EKU_ANY))
			printf("anyExtendedKeyUsage ");
		if (pub->key_eku & (LC_KEY_EKU_SERVER_AUTH))
			printf("ServerAuthentication ");
		if (pub->key_eku & (LC_KEY_EKU_CLIENT_AUTH))
			printf("ClientAuthentication ");
		if (pub->key_eku & (LC_KEY_EKU_CODE_SIGNING))
			printf("CodeSigning ");
		if (pub->key_eku & (LC_KEY_EKU_EMAIL_PROTECTION))
			printf("EmailProtection ");
		if (pub->key_eku & (LC_KEY_EKU_TIME_STAMPING))
			printf("TImeStamping ");
		if (pub->key_eku & (LC_KEY_EKU_OCSP_SIGNING))
			printf("OCSPSignign ");
		printf("\n");
	}

	if (x509->san_dns && x509->san_dns_len) {
		char buf[32];

		memcpy(buf, x509->san_dns,
		       min_size(sizeof(buf), x509->san_dns_len));
		printf("Subject Alternative Name (DNS): %s\n", buf);
	}
	if (x509->san_ip && x509->san_ip_len) {
		if (x509->san_ip_len == 4) {
			printf("Subject Alternative Name (IP): %u.%u.%u.%u\n",
			       x509->san_ip[0], x509->san_ip[1],
			       x509->san_ip[2], x509->san_ip[3]);
		} else if (x509->san_ip_len == 16) {
			unsigned int i;

			printf("Subject Alternative Name (IP): ");
			for (i = 0; i < x509->san_ip_len; i++) {
				if (i)
					printf(":");
				printf("%.02x", x509->san_ip[i]);
			}
			printf("\n");
		} else {
			bin2print(x509->san_ip, x509->san_ip_len, stdout,
				  "Unknown SAN IP");
		}
	}
}

static void print_x509_validity(const char *prefix, time64_t valid)
{
	struct tm *time_detail;

	//localtime_r(&valid, &time_detail);
	time_detail = localtime(&valid);
	printf("%s: %d-%.2d-%.2d %.2d:%.2d:%.2d\n", prefix,
	       time_detail->tm_year + 1900, time_detail->tm_mon + 1,
	       time_detail->tm_mday, time_detail->tm_hour, time_detail->tm_min,
	       time_detail->tm_sec);
}

static void _print_x509_authids(const struct lc_asymmetric_key_id auth_ids[3])
{
	bin2print(auth_ids[0].data, auth_ids[0].len, stdout, "AuthID[0]");
	bin2print(auth_ids[1].data, auth_ids[1].len, stdout, "AuthID[1]");
	bin2print(auth_ids[2].data, auth_ids[2].len, stdout, "AuthID[2]");
}

static void print_x509_authids(const struct lc_x509_certificate *x509)
{
	const struct lc_public_key_signature *sig = &x509->sig;

	_print_x509_authids(sig->auth_ids);
	bin2print(x509->id.data, x509->id.len, stdout, "X.509 ID");
}

static void print_x509_pkey_size(const struct lc_x509_certificate *x509)
{
	const struct lc_public_key *pkey = &x509->pub;

	printf("Public key size %zu\n", pkey->keylen);
}

int print_x509_cert(const struct lc_x509_certificate *x509)
{
	print_x509_serial(x509);
	print_x509_sinature_algo(x509);
	print_x509_name("Issuer", &x509->issuer_segments);
	print_x509_name("Subject", &x509->subject_segments);
	print_x509_validity("Valid From", x509->valid_from);
	print_x509_validity("Valid To", x509->valid_to);
	print_x509_pubkey_algo(x509);
	print_x509_extensions(x509);
	print_x509_authids(x509);
	print_x509_pkey_size(x509);

	printf("Self-signed: %s\n", x509->self_signed ? "yes" : "no");

	return 0;
}

void print_pkcs7_data(const struct pkcs7_message *pkcs7_msg)
{
	struct lc_x509_certificate *cert = pkcs7_msg->certs;
	struct pkcs7_signed_info *sinfos = pkcs7_msg->signed_infos;

	printf("======= X.509 certificate listing ==========\n");
	while (cert) {
		print_x509_cert(cert);
		printf("====== End one certificate ==========\n");
		cert = cert->next;
	}

	if (sinfos)
		printf("======= PKCS7 signed info listing ==========\n");
	while (sinfos) {
		struct lc_public_key_signature *sig = &sinfos->sig;

		/* Print signer */
		if (sinfos->signer)
			print_x509_cert(sinfos->signer);

		if (sinfos->authattrs_len) {
			bin2print(sinfos->authattrs, sinfos->authattrs_len,
				  stdout, "Signed Authinfo");
		}

		_print_x509_sinature_algo(&sinfos->sig);

		_print_x509_authids(sig->auth_ids);

		bin2print(sig->digest, sig->digest_size, stdout,
			  "signerInfos messageDigest");

		printf("====== End one PKCS7 signed info listing ==========\n");

		sinfos = sinfos->next;
	}
}
