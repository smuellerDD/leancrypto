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

#include "asn1_debug.h"
#include "ext_headers.h"
#include "helper.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "lc_x509_generator.h"
#include "x509_cert_parser.h"

static int lc_x509_cert_set_dilithium_keypair(struct lc_x509_key_data *gen_data,
					      struct lc_dilithium_pk *pk,
					      struct lc_dilithium_sk *sk)
{
	uint8_t *pk_ptr;
	size_t pk_len;
	enum lc_dilithium_type dilithium_type;

	int ret = 0;

	CKNULL(gen_data, -EINVAL);
	CKNULL(pk, -EINVAL);

	dilithium_type = lc_dilithium_pk_type(pk);
	switch (dilithium_type) {
	case LC_DILITHIUM_44:
		gen_data->sig_type = LC_SIG_DILITHIUM_44;
		break;
	case LC_DILITHIUM_65:
		gen_data->sig_type = LC_SIG_DILITHIUM_65;
		break;
	case LC_DILITHIUM_87:
		gen_data->sig_type = LC_SIG_DILITHIUM_87;
		break;
	case LC_DILITHIUM_UNKNOWN:
	default:
		printf_debug("Unknown Dilithium type\n");
		return -ENOPKG;
	}

	gen_data->pk.dilithium_pk = pk;
	gen_data->sk.dilithium_sk = sk;

	CKINT(lc_dilithium_pk_ptr(&pk_ptr, &pk_len, pk));
	lc_hash(LC_X509_SKID_DEFAULT_HASH, pk_ptr, pk_len, gen_data->pk_digest);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_signer_keypair_dilithium,
		      struct lc_x509_certificate *x509,
		      struct lc_dilithium_pk *pk, struct lc_dilithium_sk *sk)
{
	int ret;

	if (!x509)
		return -EINVAL;

	CKINT(lc_x509_cert_set_dilithium_keypair(&x509->sig_gen_data, pk, sk));
	x509->sig.pkey_algo = x509->sig_gen_data.sig_type;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_pubkey_dilithium,
		      struct lc_x509_certificate *x509,
		      struct lc_dilithium_pk *pk)
{
	int ret;

	if (!x509)
		return -EINVAL;

	CKINT(lc_x509_cert_set_dilithium_keypair(&x509->pub_gen_data, pk,
						 NULL));
	x509->pub.pkey_algo = x509->pub_gen_data.sig_type;

out:
	return ret;
}

static int lc_x509_cert_set_sphincs_keypair(struct lc_x509_key_data *gen_data,
					    struct lc_sphincs_pk *pk,
					    struct lc_sphincs_sk *sk)
{
	uint8_t *pk_ptr;
	size_t pk_len;
	enum lc_sphincs_type sphincs_type;

	int ret = 0;

	CKNULL(gen_data, -EINVAL);
	CKNULL(pk, -EINVAL);

	sphincs_type = lc_sphincs_pk_type(pk);
	switch (sphincs_type) {
	case LC_SPHINCS_SHAKE_128f:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_128F;
		break;
	case LC_SPHINCS_SHAKE_128s:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_128S;
		break;
	case LC_SPHINCS_SHAKE_192f:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_192F;
		break;
	case LC_SPHINCS_SHAKE_192s:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_192S;
		break;
	case LC_SPHINCS_SHAKE_256f:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_256F;
		break;
	case LC_SPHINCS_SHAKE_256s:
		gen_data->sig_type = LC_SIG_SPINCS_SHAKE_256S;
		break;
	case LC_SPHINCS_UNKNOWN:
	default:
		printf_debug("Unknown Dilithium type\n");
		return -ENOPKG;
	}

	gen_data->pk.sphincs_pk = pk;
	gen_data->sk.sphincs_sk = sk;

	CKINT(lc_sphincs_pk_ptr(&pk_ptr, &pk_len, pk));
	lc_hash(LC_X509_SKID_DEFAULT_HASH, pk_ptr, pk_len, gen_data->pk_digest);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_signer_keypair_sphincs,
		      struct lc_x509_certificate *x509,
		      struct lc_sphincs_pk *pk, struct lc_sphincs_sk *sk)
{
	int ret;

	if (!x509)
		return -EINVAL;

	CKINT(lc_x509_cert_set_sphincs_keypair(&x509->sig_gen_data, pk, sk));
	x509->sig.pkey_algo = x509->sig_gen_data.sig_type;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_pubkey_sphincs,
		      struct lc_x509_certificate *x509,
		      struct lc_sphincs_pk *pk)
{
	int ret;

	if (!x509)
		return -EINVAL;

	CKINT(lc_x509_cert_set_sphincs_keypair(&x509->pub_gen_data, pk, NULL));
	x509->pub.pkey_algo = x509->pub_gen_data.sig_type;

out:
	return ret;
}

static int
lc_x509_cert_set_dilithium_ed25519_keypair(struct lc_x509_key_data *gen_data,
					   struct lc_dilithium_ed25519_pk *pk,
					   struct lc_dilithium_ed25519_sk *sk)
{
	uint8_t *dilithium_pk_ptr, *ed25519_pk_ptr;
	size_t dilithium_pk_len, ed25519_pk_len;
	enum lc_dilithium_type dilithium_ed25519_type;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, LC_X509_SKID_DEFAULT_HASH);

	CKNULL(gen_data, -EINVAL);
	CKNULL(pk, -EINVAL);

	dilithium_ed25519_type = lc_dilithium_ed25519_pk_type(pk);
	switch (dilithium_ed25519_type) {
	case LC_DILITHIUM_44:
		gen_data->sig_type = LC_SIG_DILITHIUM_44_ED25519;
		break;
	case LC_DILITHIUM_65:
		gen_data->sig_type = LC_SIG_DILITHIUM_65_ED25519;
		break;
	case LC_DILITHIUM_87:
		gen_data->sig_type = LC_SIG_DILITHIUM_87_ED25519;
		break;
	case LC_DILITHIUM_UNKNOWN:
	default:
		printf_debug("Unknown Dilithium ED25519 type\n");
		return -ENOPKG;
	}

	gen_data->pk.dilithium_ed25519_pk = pk;
	gen_data->sk.dilithium_ed25519_sk = sk;

	CKINT(lc_dilithium_ed25519_pk_ptr(&dilithium_pk_ptr, &dilithium_pk_len,
					  &ed25519_pk_ptr, &ed25519_pk_len,
					  pk));

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, dilithium_pk_ptr, dilithium_pk_len);
	lc_hash_update(hash_ctx, ed25519_pk_ptr, ed25519_pk_len);
	lc_hash_final(hash_ctx, gen_data->pk_digest);
	lc_hash_zero(hash_ctx);

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_signer_keypair_dilithium_ed25519,
		      struct lc_x509_certificate *x509,
		      struct lc_dilithium_ed25519_pk *pk,
		      struct lc_dilithium_ed25519_sk *sk)
{
	int ret;

	if (!x509)
		return -EINVAL;

	CKINT(lc_x509_cert_set_dilithium_ed25519_keypair(&x509->sig_gen_data,
							 pk, sk));
	x509->sig.pkey_algo = x509->sig_gen_data.sig_type;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_pubkey_dilithium_ed25519,
		      struct lc_x509_certificate *x509,
		      struct lc_dilithium_ed25519_pk *pk)
{
	int ret;

	if (!x509)
		return -EINVAL;

	CKINT(lc_x509_cert_set_dilithium_ed25519_keypair(&x509->pub_gen_data,
							 pk, NULL));
	x509->pub.pkey_algo = x509->pub_gen_data.sig_type;

out:
	return ret;
}

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
		if (namelen == x509_eku_to_name[i].namelen &&
		    !strncmp(name, x509_eku_to_name[i].name, namelen)) {
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
		if (namelen == x509_keyusage_to_name[i].namelen &&
		    !strncmp(name, x509_keyusage_to_name[i].name, namelen)) {
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
