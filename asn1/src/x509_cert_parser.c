/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This code is derived in parts from the Linux kernel
 * License: SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
/*
 * Red Hat granted the following additional license to the leancrypto project:
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "lc_memcmp_secure.h"
#include "lc_memory_support.h"
#include "lc_memset_secure.h"
#include "ret_checkers.h"

#include "asn1_debug.h"
#include "asym_key_dilithium.h"
#include "asym_key_dilithium_ed25519.h"
#include "asym_key_dilithium_ed448.h"
#include "asym_key_sphincs.h"
#include "asymmetric_type.h"
#include "binhexbin_raw.h"
#include "conv_be_le.h"
#include "math_helper.h"
#include "oid_registry.h"
#include "visibility.h"
#include "x509_cert_parser.h"
#include "x509_algorithm_mapper.h"
#include "x509_asn1.h"
#include "x509_akid_asn1.h"
#include "x509_basic_constraints_asn1.h"
#include "x509_eku_asn1.h"
#include "x509_keyusage_asn1.h"
#include "x509_san_asn1.h"
#include "x509_skid_asn1.h"

/******************************************************************************
 * ASN.1 parser support functions
 ******************************************************************************/

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
static int x509_note_OID(void *context, size_t hdrlen, unsigned char tag,
			 const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	bin2print_debug(value, vlen, stdout, "OID");
	ctx->last_oid = lc_look_up_OID(value, vlen);
	if (ctx->last_oid == OID__NR) {
		char buffer[50];
		lc_sprint_oid(value, vlen, buffer, sizeof(buffer));
		printf_debug("Unknown OID: %s\n", buffer);
	}
	return 0;
}

/*
 * Save the position of the TBS data so that we can check the signature over it
 * later.
 */
int lc_x509_note_tbs_certificate(void *context, size_t hdrlen,
				 unsigned char tag, const uint8_t *value,
				 size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)tag;

	printf_debug("x509_note_tbs_certificate(%zu,%02x,%ld,%zu)!\n", hdrlen,
		     tag, value - ctx->data, vlen);

	cert->tbs = value - hdrlen;
	cert->tbs_size = vlen + hdrlen;
	return 0;
}

/*
 * Record the algorithm that was used to sign this certificate.
 */
int lc_x509_note_sig_algo(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key_signature *sig = &cert->sig;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	printf_debug("Signature algo: %s (OID: %u)\n",
		     lc_x509_oid_to_name(ctx->last_oid), ctx->last_oid);

	ctx->sig_algo = ctx->last_oid;

	return lc_x509_oid_to_sig_type(ctx->last_oid, &sig->pkey_algo);
}

int lc_x509_note_algorithm_OID(void *context, size_t hdrlen, unsigned char tag,
			       const uint8_t *value, size_t vlen)
{
	return x509_note_OID(context, hdrlen, tag, value, vlen);
}

/*
 * Note the whereabouts and type of the signature.
 */
int lc_x509_note_signature(void *context, size_t hdrlen, unsigned char tag,
			   const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	printf_debug("Signature: alg=%u, size=%zu\n", ctx->last_oid, vlen);

	/*
	 * In X.509 certificates, the signature's algorithm is stored in two
	 * places: inside the TBSCertificate (the data that is signed), and
	 * alongside the signature.  These *must* match.
	 */
	if (ctx->last_oid != ctx->sig_algo) {
		printf_debug(
			"signatureAlgorithm (%u) differs from tbsCertificate.signature (%u)\n",
			ctx->last_oid, ctx->sig_algo);
		return -EINVAL;
	}

	/* Discard the BIT STRING metadata */
	if (vlen < 1 || *(const uint8_t *)value != 0)
		return -EBADMSG;

	value++;
	vlen--;

	cert->raw_sig = value;
	cert->raw_sig_size = vlen;
	printf_debug("Found signature of size %zu\n", cert->raw_sig_size);

	return 0;
}

int lc_x509_signature_algorithm(void *context, size_t hdrlen, unsigned char tag,
				const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;
	return 0;
}

/*
 * Note the certificate serial number
 */
int lc_x509_note_serial(void *context, size_t hdrlen, unsigned char tag,
			const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	/* RFC5280 requires the serial to be not longer than 20 bytes. */
	if (vlen > LC_X509_SERIAL_MAX_SIZE)
		return -EINVAL;

	cert->raw_serial = value;
	cert->raw_serial_size = vlen;
	bin2print_debug(cert->raw_serial, cert->raw_serial_size, stdout,
			"Serial");

	return 0;
}

/*
 * Note some of the name segments from which we'll fabricate a name.
 */
int lc_x509_extract_name_segment(void *context, size_t hdrlen,
				 unsigned char tag, const uint8_t *value,
				 size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_x509_certificate_name *name = &cert->issuer_segments;

	(void)hdrlen;
	(void)tag;

	/*
	 * If cert->raw_issuer is filled, we received the full issuer,
	 * fill subject
	 */
	if (cert->raw_issuer)
		name = &cert->subject_segments;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
	switch (ctx->last_oid) {
	case OID_commonName:
		ctx->cn_size = (uint8_t)vlen;
		ctx->cn_offset = (uint16_t)(value - ctx->data);
		name->cn.value = (char *)value;
		name->cn.size = (uint8_t)vlen;
		break;
	case OID_organizationName:
		ctx->o_size = (uint8_t)vlen;
		ctx->o_offset = (uint16_t)(value - ctx->data);
		name->o.value = (char *)value;
		name->o.size = (uint8_t)vlen;
		break;
	case OID_email_address:
		ctx->email_size = (uint8_t)vlen;
		ctx->email_offset = (uint16_t)(value - ctx->data);
		name->email.value = (char *)value;
		name->email.size = (uint8_t)vlen;
		break;
	case OID_countryName:
		name->c.value = (char *)value;
		name->c.size = (uint8_t)vlen;
		break;
	case OID_stateOrProvinceName:
		name->st.value = (char *)value;
		name->st.size = (uint8_t)vlen;
		break;
	case OID_organizationUnitName:
		name->ou.value = (char *)value;
		name->ou.size = (uint8_t)vlen;
		break;
	default:
		break;
	}
#pragma GCC diagnostic pop

	return 0;
}

int lc_x509_extract_attribute_name_segment(void *context, size_t hdrlen,
					   unsigned char tag,
					   const uint8_t *value, size_t vlen)
{
	return lc_x509_extract_name_segment(context, hdrlen, tag, value, vlen);
}

int lc_x509_note_attribute_type_OID(void *context, size_t hdrlen,
				    unsigned char tag, const uint8_t *value,
				    size_t vlen)
{
	return x509_note_OID(context, hdrlen, tag, value, vlen);
}

int lc_x509_attribute_value_continue(void *context, size_t hdrlen,
				     unsigned char tag, const uint8_t *value,
				     size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;
	return 0;
}

/*
 * Fabricate and save the issuer and subject names
 */
static int x509_fabricate_name(struct x509_parse_context *ctx, size_t hdrlen,
			       unsigned char tag,
			       char _name[LC_ASN1_MAX_ISSUER_NAME], size_t vlen,
			       int subject)
{
	const uint8_t *name, *data = (const void *)ctx->data;
	struct lc_x509_certificate *cert = ctx->cert;
	size_t namesize;
	int ret = 0;

	(void)hdrlen;
	(void)tag;
	(void)vlen;

	/*
	 * A SAN takes precedence over the DN for identifying the certificate
	 * and marking its subject.
	 */
	if (subject && cert->san_dns_len) {
		namesize = min_size(cert->san_dns_len, LC_ASN1_MAX_ISSUER_NAME);
		memcpy(_name, cert->san_dns, namesize);
		_name[namesize] = '\0';

		return 0;
	}

	if (subject && cert->san_email_len) {
		namesize =
			min_size(cert->san_email_len, LC_ASN1_MAX_ISSUER_NAME);
		memcpy(_name, cert->san_email, namesize);
		_name[namesize] = '\0';

		return 0;
	}

	if (subject && cert->san_ip_len) {
		if (cert->san_ip_len == 4) {
			/* IPv4 Address */
			snprintf(_name, LC_ASN1_MAX_ISSUER_NAME, "%u.%u.%u.%u",
				 cert->san_ip[0], cert->san_ip[1],
				 cert->san_ip[2], cert->san_ip[3]);

		} else if (cert->san_ip_len == 16) {
			/* IPv6 Address */
			size_t i, offset;

			for (i = 0; i < cert->san_ip_len; i++) {
				offset = i * 3;
				snprintf(_name + offset,
					 LC_ASN1_MAX_ISSUER_NAME - offset,
					 "%.02x:", cert->san_ip[i]);
			}
			/* Eliminate the last ":" and place a NULL terminator */
			_name[(i * 3) - 1] = '\0';

		} else {
			/*
			 * Something else, do a best-effort by converting it
			 * into Hex.
			 */
			lc_bin2hex(cert->san_ip, cert->san_ip_len, _name,
				   LC_ASN1_MAX_ISSUER_NAME, 1);
			_name[min_size(cert->san_ip_len,
				       LC_ASN1_MAX_ISSUER_NAME)] = '\0';
		}

		return 0;
	}

	/* Empty name string if no material */
	if (!ctx->cn_size && !ctx->o_size && !ctx->email_size) {
		_name[0] = 0;
		goto out;
	}

	if (ctx->cn_size && ctx->o_size) {
		/* Consider combining O and CN, but use only the CN if it is
		 * prefixed by the O, or a significant portion thereof.
		 */
		namesize = ctx->cn_size;
		name = data + ctx->cn_offset;
		if (ctx->cn_size >= ctx->o_size &&
		    lc_memcmp_secure(data + ctx->cn_offset, ctx->cn_size,
				     data + ctx->o_offset, ctx->o_size) == 0)
			goto single_component;
		if (ctx->cn_size >= 7 && ctx->o_size >= 7 &&
		    lc_memcmp_secure(data + ctx->cn_offset, 7,
				     data + ctx->o_offset, 7) == 0)
			goto single_component;

		if (ctx->o_size + 2 + ctx->cn_size + 1 >=
		    LC_ASN1_MAX_ISSUER_NAME) {
			ret = -EOVERFLOW;
			goto out;
		}

		memcpy(_name, data + ctx->o_offset, ctx->o_size);
		_name[ctx->o_size + 0] = ':';
		_name[ctx->o_size + 1] = ' ';
		memcpy(_name + ctx->o_size + 2, data + ctx->cn_offset,
		       ctx->cn_size);
		_name[ctx->o_size + 2 + ctx->cn_size] = '\0';

		goto out;

	} else if (ctx->cn_size) {
		namesize = ctx->cn_size;
		name = data + ctx->cn_offset;
	} else if (ctx->o_size) {
		namesize = ctx->o_size;
		name = data + ctx->o_offset;
	} else {
		namesize = ctx->email_size;
		name = data + ctx->email_offset;
	}

single_component:
	if (namesize >= LC_ASN1_MAX_ISSUER_NAME) {
		ret = -EOVERFLOW;
		goto out;
	}
	memcpy(_name, name, namesize);
	_name[namesize] = '\0';

out:
	ctx->cn_size = 0;
	ctx->o_size = 0;
	ctx->email_size = 0;
	return ret;
}

int lc_x509_note_issuer(void *context, size_t hdrlen, unsigned char tag,
			const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key_signature *sig = &cert->sig;
	int ret = 0;

	cert->raw_issuer = value;
	cert->raw_issuer_size = vlen;

	if (!sig->auth_ids[2].len) {
		CKINT(lc_asymmetric_key_generate_id(&sig->auth_ids[2], value,
						    vlen, NULL, 0));
	}

	CKINT(x509_fabricate_name(ctx, hdrlen, tag, cert->issuer, vlen, 0));

out:
	return ret;
}

/*
 * Extract the parameters for the subject
 */
int lc_x509_note_subject(void *context, size_t hdrlen, unsigned char tag,
			 const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	cert->raw_subject = value;
	cert->raw_subject_size = vlen;
	return x509_fabricate_name(ctx, hdrlen, tag, cert->subject, vlen, 1);
}

/*
 * Extract the parameters for the public key
 */
int lc_x509_note_params(void *context, size_t hdrlen, unsigned char tag,
			const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)tag;

	/*
	 * AlgorithmIdentifier is used three times in the x509, we should skip
	 * first and ignore third, using second one which is after subject and
	 * before subjectPublicKey.
	 */
	if (!cert->raw_subject || ctx->key)
		return 0;
	ctx->params = value - hdrlen;
	ctx->params_size = vlen + hdrlen;
	return 0;
}

/*
 * Extract the data for the public key algorithm
 */
int lc_x509_extract_key_data(void *context, size_t hdrlen, unsigned char tag,
			     const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key *pub = &cert->pub;
	int ret;

	(void)hdrlen;
	(void)tag;

	ctx->key_algo = ctx->last_oid;

	printf_debug("Public key algo: %s (OID: %u)\n",
		     lc_x509_oid_to_name(ctx->last_oid), ctx->last_oid);

	CKINT(lc_x509_oid_to_sig_type(ctx->last_oid, &pub->pkey_algo));

#if 0
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"

	enum OID oid;
	switch (ctx->last_oid) {
	case OID_id_ecPublicKey:
		printf_debug("Found public key for ECDSA with ");
		if (parse_OID(ctx->params, ctx->params_size, &oid) != 0)
			return -EBADMSG;

		switch (oid) {
		case OID_sm2:
			pub->pkey_algo = LC_SIG_SM2;
			printf_debug("SM2\n");
			break;
		case OID_id_prime192v1:
			printf_debug("P-192\n");
			fallthrough;
		case OID_id_prime256v1:
			printf_debug("P-256\n");
			fallthrough;
		case OID_id_ansip384r1:
			printf_debug("P-384\n");
			fallthrough;
		case OID_id_ansip521r1:
			printf_debug("P-521\n");
			pub->pkey_algo = LC_SIG_ECDSA_X963;
			break;
		default:
			printf("Unknown parameter\n");
			return -ENOPKG;
		}
		break;
	default:
		return -ENOPKG;
	}
#pragma GCC diagnostic pop
#endif

	/* Discard the BIT STRING metadata */
	if (vlen > 0 && *(const uint8_t *)value == 0) {
		ctx->key = value + 1;
		ctx->key_size = vlen - 1;
	} else {
		/*
		 * We allow that no BIT STRING prefix is set as we may have
		 * a sequence.
		 */
		ctx->key = value;
		ctx->key_size = vlen;
	}

	printf_debug("Public Key size %zu\n", ctx->key_size);
	bin2print_debug(ctx->key, ctx->key_size, stdout, "Public Key");

out:
	return ret;
}
/*
 * Extract the criticality of an extension
 */
int lc_x509_extension_critical(void *context, size_t hdrlen, unsigned char tag,
			       const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	if (vlen != 1)
		return -EBADMSG;

	ctx->extension_critical = (value[0] == 0xff);

	return 0;
}

/*
 * Extract the extended key usage
 */
int lc_x509_eku(void *context, size_t hdrlen, unsigned char tag,
		const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key *pub = &cert->pub;
	uint16_t eku;
	int ret;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	bin2print_debug(value, vlen, stdout, "OID");
	ctx->last_oid = lc_look_up_OID(value, vlen);
	printf_debug("Extended Key Usage: %u\n", ctx->last_oid);

	CKINT(lc_x509_cert_oid_to_eku(ctx->last_oid, &eku));

	pub->key_eku |= eku;
	pub->key_eku |= ctx->extension_critical ? LC_KEY_EKU_CRITICAL : 0;
	pub->key_eku |= LC_KEY_EKU_EXTENSION_PRESENT;

out:
	return ret;
}

/*
 * Extract the subject alternative name - DNS parameter
 */
int lc_x509_san_email(void *context, size_t hdrlen, unsigned char tag,
		      const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	cert->san_email = (char *)value;
	cert->san_email_len = vlen;

	return x509_fabricate_name(ctx, hdrlen, tag, cert->subject, vlen, 1);
}

/*
 * Extract the subject alternative name - DNS parameter
 */
int lc_x509_san_dns(void *context, size_t hdrlen, unsigned char tag,
		    const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	cert->san_dns = (char *)value;
	cert->san_dns_len = vlen;

	return x509_fabricate_name(ctx, hdrlen, tag, cert->subject, vlen, 1);
}

/*
 * Extract the subject alternative name - IP parameter
 */
int lc_x509_san_ip(void *context, size_t hdrlen, unsigned char tag,
		   const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	cert->san_ip = value;
	cert->san_ip_len = vlen;

	return 0;
}

int lc_x509_san_OID(void *context, size_t hdrlen, unsigned char tag,
		    const uint8_t *value, size_t vlen)
{
	return x509_note_OID(context, hdrlen, tag, value, vlen);
}

/*
 * Extract the basic constraints CA field
 */
int lc_x509_basic_constraints_ca(void *context, size_t hdrlen,
				 unsigned char tag, const uint8_t *value,
				 size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key *pub = &cert->pub;

	(void)hdrlen;
	(void)tag;

	if (vlen != 1)
		return -EBADMSG;

	ctx->extension_critical = (value[0] == ASN1_TRUE);
	pub->basic_constraint =
		(value[0] == ASN1_TRUE) ? LC_KEY_CA : LC_KEY_NOCA;
	pub->basic_constraint |=
		ctx->extension_critical ? LC_KEY_BASIC_CONSTRAINT_CRITICAL : 0;

	return 0;
}

/*
 * Extract the basic constraints pathlen
 */
int lc_x509_basic_constraints_pathlen(void *context, size_t hdrlen,
				      unsigned char tag, const uint8_t *value,
				      size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key *pub = &cert->pub;
	uint8_t pathlen;

	(void)hdrlen;
	(void)tag;

	if (vlen != 1)
		return -EBADMSG;
	pathlen = *(const uint8_t *)value;

	/*
	 * If pathlen is zero, it is treated as an invalid parameter and we
	 * silently ignore it.
	 */
	if (!pathlen)
		return 0;

	pub->ca_pathlen = min_uint8(LC_KEY_CA_MAXLEN, pathlen);

	return 0;
}

/*
 * Extract the key usage
 */
int lc_x509_keyusage(void *context, size_t hdrlen, unsigned char tag,
		     const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key *pub = &cert->pub;

	(void)hdrlen;
	(void)tag;

	if (vlen > 2 || vlen == 0)
		return -EBADMSG;

	/*
	 * BIT STRING is handled as a big-endian value which implies that we
	 * need to convert it here.
	 */
	if (vlen == 2)
		pub->key_usage = (uint16_t)(value[0] << 8) | value[1];
	else
		pub->key_usage = value[0];

	pub->key_usage |= ctx->extension_critical ? LC_KEY_USAGE_CRITICAL : 0;
	pub->key_usage |= LC_KEY_USAGE_EXTENSION_PRESENT;

	return 0;
}

/*
 * Extract the subject key ID
 */
int lc_x509_skid(void *context, size_t hdrlen, unsigned char tag,
		 const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_asymmetric_key_id *skid = &cert->skid;
	int ret;

	(void)hdrlen;
	(void)tag;

	/* Get hold of the key fingerprint */
	if (skid->len || vlen == 0)
		return -EBADMSG;

	cert->raw_skid_size = vlen;
	cert->raw_skid = value;
	CKINT(lc_asymmetric_key_generate_id(skid, value, vlen, NULL, 0));
	bin2print_debug(skid->data, skid->len, stdout, "subjkeyid");

out:
	return ret;
}

int lc_x509_extension_OID(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	return x509_note_OID(context, hdrlen, tag, value, vlen);
}

/*
 * Process certificate extensions that are used to qualify the certificate.
 */
int lc_x509_process_extension(void *context, size_t hdrlen, unsigned char tag,
			      const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	int ret = 0;

	(void)hdrlen;
	(void)tag;
	(void)ctx;

	printf_debug("Extension: %u\n", ctx->last_oid);

	if (ctx->last_oid == OID_subjectKeyIdentifier) {
		CKINT(lc_asn1_ber_decoder(&lc_x509_skid_decoder, ctx, value,
					  vlen));
	}

	if (ctx->last_oid == OID_keyUsage) {
		CKINT(lc_asn1_ber_decoder(&lc_x509_keyusage_decoder, ctx, value,
					  vlen));
	}

	if (ctx->last_oid == OID_authorityKeyIdentifier) {
		/* Get hold of the CA key fingerprint */
		ctx->raw_akid = value;
		ctx->raw_akid_size = vlen;
		return 0;
	}

	if (ctx->last_oid == OID_basicConstraints) {
		CKINT(lc_asn1_ber_decoder(&lc_x509_basic_constraints_decoder,
					  ctx, value, vlen));
	}

	if (ctx->last_oid == OID_extKeyUsage) {
		CKINT(lc_asn1_ber_decoder(&lc_x509_eku_decoder, ctx, value,
					  vlen));
	}

	if (ctx->last_oid == OID_subjectAltName) {
		CKINT(lc_asn1_ber_decoder(&lc_x509_san_decoder, ctx, value,
					  vlen));
	}

out:
	return ret;
}

int lc_x509_extension_continue(void *context, size_t hdrlen, unsigned char tag,
			       const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;
	return 0;
}

static time64_t lc_mktime64(const unsigned int year0, const unsigned int mon0,
			    const unsigned int day, const unsigned int hour,
			    const unsigned int min, const unsigned int sec)
{
	unsigned int mon = mon0, year = year0;

	/* 1..12 -> 11,12,1..10 */
	if (0 >= (int)(mon -= 2)) {
		mon += 12; /* Puts Feb last since it has leap day */
		year -= 1;
	}

	return ((((time64_t)(year / 4 - year / 100 + year / 400 +
			     367 * mon / 12 + day) +
		  year * 365 - 719499) *
			 24 +
		 hour /* now have hours - midnight tomorrow handled here */
		 ) * 60 +
		min /* now have minutes */
		) * 60 +
	       sec; /* finally seconds */
}

int lc_x509_decode_time(time64_t *_t, size_t hdrlen, unsigned char tag,
			const uint8_t *value, size_t vlen)
{
//TODO replace the macros
#pragma GCC diagnostic push
#ifdef __clang__
#pragma GCC diagnostic ignored "-Wgnu-statement-expression-from-macro-expansion"
#else
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
	static const unsigned char month_lengths[] = { 31, 28, 31, 30, 31, 30,
						       31, 31, 30, 31, 30, 31 };
	unsigned int year, mon, day, hour, min, sec, mon_len;

	(void)hdrlen;

#define dec2bin(X)                                                             \
	({                                                                     \
		unsigned char xx = (X) - '0';                                  \
		if (xx > 9)                                                    \
			goto invalid_time;                                     \
		xx;                                                            \
	})
#define DD2bin(P)                                                              \
	({                                                                     \
		unsigned int x = (unsigned int)dec2bin(P[0]) * 10 +            \
				 (unsigned int)dec2bin(P[1]);                  \
		P += 2;                                                        \
		x;                                                             \
	})

	if (tag == ASN1_UNITIM) {
		/* UTCTime: YYMMDDHHMMSSZ */
		if (vlen != 13)
			goto unsupported_time;
		year = DD2bin(value);
		if (year >= 50)
			year += 1900;
		else
			year += 2000;
	} else if (tag == ASN1_GENTIM) {
		/* GenTime: YYYYMMDDHHMMSSZ */
		if (vlen != 15)
			goto unsupported_time;
		year = DD2bin(value) * 100 + DD2bin(value);
		if (year >= 1950 && year <= 2049)
			goto invalid_time;
	} else {
		goto unsupported_time;
	}

	mon = DD2bin(value);
	day = DD2bin(value);
	hour = DD2bin(value);
	min = DD2bin(value);
	sec = DD2bin(value);

	if (*value != 'Z')
		goto unsupported_time;

	if (year < 1970 || mon < 1 || mon > 12)
		goto invalid_time;

	mon_len = month_lengths[mon - 1];
	if (mon == 2) {
		if (year % 4 == 0) {
			mon_len = 29;
			if (year % 100 == 0) {
				mon_len = 28;
				if (year % 400 == 0)
					mon_len = 29;
			}
		}
	}

	if (day < 1 || day > mon_len ||
	    hour > 24 || /* ISO 8601 permits 24:00:00 as midnight tomorrow */
	    min > 59 ||
	    sec > 60) /* ISO 8601 permits leap seconds [X.680 46.3] */
		goto invalid_time;

	*_t = lc_mktime64(year, mon, day, hour, min, sec);
	printf_debug("Time stamp %llu\n", (unsigned long long)*_t);
	return 0;

unsupported_time:
	printf_debug("Got unsupported time [tag %02x]: '%*phN'\n", tag,
		     (int)vlen, value);
	return -EBADMSG;
invalid_time:
	printf_debug("Got invalid time [tag %02x]: '%*phN'\n", tag, (int)vlen,
		     value);
	return -EBADMSG;
#pragma GCC diagnostic pop
}

/*
 * Process the time the certificate becomes valid
 */
int lc_x509_note_not_before(void *context, size_t hdrlen, unsigned char tag,
			    const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	return lc_x509_decode_time(&cert->valid_from, hdrlen, tag, value, vlen);
}

/*
 * Process the time when the certificate becomes invalid
 */
int lc_x509_note_not_after(void *context, size_t hdrlen, unsigned char tag,
			   const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	return lc_x509_decode_time(&cert->valid_to, hdrlen, tag, value, vlen);
}

int lc_x509_set_uct_time(void *context, size_t hdrlen, unsigned char tag,
			 const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;
	return 0;
}

int lc_x509_set_gen_time(void *context, size_t hdrlen, unsigned char tag,
			 const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;
	return 0;
}

/*
 * Note a key identifier-based AuthorityKeyIdentifier
 */
int lc_x509_akid_note_kid(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key_signature *sig = &cert->sig;
	struct lc_asymmetric_key_id *auth_id = &sig->auth_ids[1];
	int ret;

	(void)hdrlen;
	(void)tag;

	bin2print_debug(value, vlen, stdout, "AKID: keyid");

	if (auth_id->len)
		return 0;

	cert->raw_akid_size = vlen;
	cert->raw_akid = value;

	CKINT(lc_asymmetric_key_generate_id(auth_id, value, vlen, NULL, 0));
	bin2print_debug(auth_id->data, auth_id->len, stdout, "authkeyid");

out:
	return ret;
}

/*
 * Note a directoryName in an AuthorityKeyIdentifier
 */
int lc_x509_akid_note_name(void *context, size_t hdrlen, unsigned char tag,
			   const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	bin2print_debug(value, vlen, stdout, "AKID: name");

	ctx->akid_raw_issuer = value;
	ctx->akid_raw_issuer_size = vlen;
	return 0;
}

/*
 * Note a serial number in an AuthorityKeyIdentifier
 */
int lc_x509_akid_note_serial(void *context, size_t hdrlen, unsigned char tag,
			     const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;
	struct lc_public_key_signature *sig = &cert->sig;
	struct lc_asymmetric_key_id *auth_id = &sig->auth_ids[0];
	int ret;

	(void)hdrlen;
	(void)tag;

	bin2print_debug(value, vlen, stdout, "AKID: serial");

	if (auth_id->len)
		return 0;

	/*
	 * If we have a serial number, set it by itself.
	 */
	if (value) {
		CKINT(lc_asymmetric_key_generate_id(auth_id, value, vlen, NULL,
						    0));
	} else {
		if (!ctx->akid_raw_issuer)
			return 0;
		CKINT(lc_asymmetric_key_generate_id(
			auth_id, ctx->akid_raw_issuer,
			ctx->akid_raw_issuer_size, NULL, 0));
	}

	bin2print_debug(auth_id->data, auth_id->len, stdout, "authkeyid");

out:
	return ret;
}

int lc_x509_akid_note_OID(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	return x509_note_OID(context, hdrlen, tag, value, vlen);
}

int lc_x509_version(void *context, size_t hdrlen, unsigned char tag,
		    const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	if (vlen != 1)
		return -EBADMSG;

	cert->x509_version = value[0];

	/* Certificate versions start with zero as version 1 */
	cert->x509_version++;

	return 0;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(void, lc_x509_cert_clear,
		      struct lc_x509_certificate *cert)
{
	unsigned char alloc;

	if (!cert)
		return;

	alloc = cert->allocated;
	lc_public_key_clear(&cert->pub);
	lc_public_key_signature_clear(&cert->sig);
	lc_memset_secure(cert, 0, sizeof(struct lc_x509_certificate));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
	cert->allocated = alloc;
#pragma GCC diagnostic pop
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_decode,
		      struct lc_x509_certificate *x509, const uint8_t *data,
		      size_t datalen)
{
	struct x509_parse_context ctx = { 0 };
	int ret;

	CKNULL(x509, -EINVAL);
	CKNULL(data, -EINVAL);

	ctx.cert = x509;
	ctx.data = data;

	x509->raw_cert = data;
	x509->raw_cert_size = datalen;

	/* Attempt to decode the certificate */
	CKINT(lc_asn1_ber_decoder(&lc_x509_decoder, &ctx, data, datalen));

	/* Decode the AuthorityKeyIdentifier */
	if (ctx.raw_akid) {
		bin2print_debug(ctx.raw_akid, ctx.raw_akid_size, stdout,
				"AKID");
		CKINT(lc_asn1_ber_decoder(&lc_x509_akid_decoder, &ctx,
					  ctx.raw_akid, ctx.raw_akid_size));
	}

	x509->pub.key = ctx.key;
	x509->pub.keylen = ctx.key_size;

	x509->pub.params = ctx.params;
	x509->pub.paramlen = ctx.params_size;

	x509->pub.algo = ctx.key_algo;

	/* Grab the signature bits */
	CKINT(lc_x509_get_sig_params(x509));

	/* Generate cert issuer + serial number key ID */
	CKINT(lc_asymmetric_key_generate_id(
		&x509->id, x509->raw_serial, x509->raw_serial_size,
		x509->raw_issuer, x509->raw_issuer_size));

	/* Detect self-signed certificates */
	CKINT(lc_x509_check_for_self_signed(x509));

out:
	if (ret)
		lc_x509_cert_clear(x509);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_sk_decode, struct lc_x509_key_data *key,
		      enum lc_sig_types key_type, const uint8_t *data,
		      size_t datalen)
{
	int ret = 0;

	CKNULL(key, -EINVAL);
	CKNULL(data, -EINVAL);

	key->sig_type = key_type;

	CKINT(lc_privkey_key_decode(key, data, datalen));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_pk_decode, struct lc_x509_key_data *key,
		      enum lc_sig_types key_type, const uint8_t *data,
		      size_t datalen)
{
	int ret = 0;

	CKNULL(key, -EINVAL);
	CKNULL(data, -EINVAL);

	key->sig_type = key_type;

	CKINT(lc_pubkey_key_decode(key, data, datalen));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_signature_verify, const uint8_t *sig_data,
		      size_t siglen, const struct lc_x509_certificate *cert,
		      const uint8_t *m, size_t mlen,
		      const struct lc_hash *prehash_algo)
{
	const struct lc_public_key *pub;
	struct lc_public_key_signature sig = { 0 };
	int ret = 0;

	CKNULL(cert, -EINVAL);
	CKNULL(sig_data, -EINVAL);
	CKNULL(m, -EINVAL);

	pub = &cert->pub;

	sig.s = sig_data;
	sig.s_size = siglen;

	if (prehash_algo) {
		if (mlen > LC_SHA_MAX_SIZE_DIGEST)
			return -EOVERFLOW;

		memcpy(sig.digest, m, mlen);
		sig.digest_size = mlen;
		sig.hash_algo = prehash_algo;
	} else {
		sig.raw_data = m;
		sig.raw_data_len = mlen;
	}

	sig.pkey_algo = cert->pub.pkey_algo;

	CKINT(lc_public_key_verify_signature(pub, &sig));

out:
	lc_memset_secure(&sig, 0, sizeof(sig));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_keys_dilithium_ed25519_alloc,
		      struct lc_x509_key_data **keys)
{
#ifdef LC_DILITHIUM_ED25519
	struct lc_x509_key_data *out_keys;
	int ret;

	CKINT(lc_alloc_aligned((void **)&out_keys, LC_HASH_COMMON_ALIGNMENT,
			       LC_X509_KEYS_DILITHIUM_ED25519_SIZE));

	LC_X509_KEYS_DILITHIUM_ED25519_SET(out_keys);

	*keys = out_keys;

out:
	return ret;
#else
	(void)keys;
	return -ENOPKG;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_x509_keys_dilithium_ed448_alloc,
		      struct lc_x509_key_data **keys)
{
#ifdef LC_DILITHIUM_ED448
	struct lc_x509_key_data *out_keys;
	int ret;

	CKINT(lc_alloc_aligned((void **)&out_keys, LC_HASH_COMMON_ALIGNMENT,
			       LC_X509_KEYS_DILITHIUM_ED448_SIZE));

	LC_X509_KEYS_DILITHIUM_ED448_SET(out_keys);

	*keys = out_keys;

out:
	return ret;
#else
	(void)keys;
	return -ENOPKG;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_x509_keys_dilithium_alloc,
		      struct lc_x509_key_data **keys)
{
#ifdef LC_DILITHIUM
	struct lc_x509_key_data *out_keys;
	int ret;

	CKINT(lc_alloc_aligned((void **)&out_keys, LC_HASH_COMMON_ALIGNMENT,
			       LC_X509_KEYS_DILITHIUM_SIZE));

	LC_X509_KEYS_DILITHIUM_SET(out_keys);

	*keys = out_keys;

out:
	return ret;
#else
	(void)keys;
	return -ENOPKG;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_x509_keys_sphincs_alloc,
		      struct lc_x509_key_data **keys)
{
#ifdef LC_SPHINCS
	struct lc_x509_key_data *out_keys;
	int ret;

	CKINT(lc_alloc_aligned((void **)&out_keys, LC_HASH_COMMON_ALIGNMENT,
			       LC_X509_KEYS_SPHINCS_SIZE));

	LC_X509_KEYS_SPHINCS_SET(out_keys);

	*keys = out_keys;

out:
	return ret;
#else
	(void)keys;
	return -ENOPKG;
#endif
}

LC_INTERFACE_FUNCTION(int, lc_x509_keys_alloc, struct lc_x509_key_data **keys)
{
#ifdef LC_DILITHIUM_ED448
	return lc_x509_keys_dilithium_ed448_alloc(keys);
#elif defined(LC_DILITHIUM_ED25519)
	return lc_x509_keys_dilithium_ed25519_alloc(keys);
#else
	return lc_x509_keys_dilithium_alloc(keys);
#endif
}

LC_INTERFACE_FUNCTION(void, lc_x509_keys_zero_free,
		      struct lc_x509_key_data *keys)
{
	lc_x509_keys_zero(keys);
	lc_free(keys);
}

LC_INTERFACE_FUNCTION(int, lc_x509_enc_san_ip, const char *ip_name, uint8_t *ip,
		      size_t *ip_len)
{
	/*
	 * EFI does not have support for strstr, strtok_r and strtoul, so
	 * we simply do not compile this function. As this is a rarely used
	 * helper, we simply do not provide this function.
	 */
#if defined(LC_EFI) || defined(LINUX_KERNEL)
	int ret;

	(void)ip_name;
	(void)ip;
	(void)ip_len;

	CKRET(1, -EOPNOTSUPP);

out:
	return ret;
#else
	unsigned long val;
	char *saveptr = NULL;
	char *res = NULL;
	const char *tok = ".";
	unsigned int i, upper = 4;
	int ret = 0, base = 10;

	CKNULL(ip_name, -EINVAL);
	CKNULL(ip, -EINVAL);
	CKNULL(ip_len, -EINVAL);

	/* Check for IPv6 */
	if (strstr(ip_name, ":")) {
		tok = ":";
		upper = 16;
		base = 16;
	}

	CKRET(*ip_len < upper, -EOVERFLOW);

	/* Unconstify is acceptable, as we only read the value with strtoul */
	res = strtok_r((char *)ip_name, tok, &saveptr);
	for (i = 0; i < upper; i++) {
		CKNULL(res, -EINVAL);
		val = strtoul(res, NULL, base);
		CKRET(val > 255, -EINVAL);
		ip[i] = (uint8_t)val;
		res = strtok_r(NULL, tok, &saveptr);
	}

	*ip_len = i;

out:
	return ret;
#endif
}
