/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "lc_memcmp_secure.h"
#include "lc_memory_support.h"
#include "lc_memset_secure.h"
#include "ret_checkers.h"

#include "asn1_debug.h"
#include "asymmetric_type.h"
#include "binhexbin.h"
#include "conv_be_le.h"
#include "math_helper.h"
#include "oid_registry.h"
#include "visibility.h"
#include "x509_parser.h"
#include "x509.asn1.h"
#include "x509_akid.asn1.h"
#include "x509_basic_constraints.asn1.h"
#include "x509_eku.asn1.h"
#include "x509_keyusage.asn1.h"
#include "x509_san.asn1.h"
#include "x509_skid.asn1.h"

struct x509_parse_context {
	struct x509_certificate *cert; /* Certificate being constructed */
	const uint8_t *data; /* Start of data */
	const uint8_t *key; /* Key data */
	size_t key_size; /* Size of key data */
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

/******************************************************************************
 * ASN.1 parser support functions
 ******************************************************************************/

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int x509_note_OID(void *context, size_t hdrlen, unsigned char tag,
		  const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	bin2print_debug(value, vlen, stdout, "OID");
	ctx->last_oid = look_up_OID(value, vlen);
	if (ctx->last_oid == OID__NR) {
		char buffer[50];
		sprint_oid(value, vlen, buffer, sizeof(buffer));
		printf_debug("Unknown OID: [%lu] %s\n", value - ctx->data,
			     buffer);
	}
	return 0;
}

/*
 * Save the position of the TBS data so that we can check the signature over it
 * later.
 */
int x509_note_tbs_certificate(void *context, size_t hdrlen, unsigned char tag,
			      const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;

	(void)tag;

	printf_debug("x509_note_tbs_certificate(,%zu,%02x,%ld,%zu)!\n", hdrlen,
		     tag, value - ctx->data, vlen);

	cert->tbs = value - hdrlen;
	cert->tbs_size = vlen + hdrlen;
	return 0;
}

/*
 * Record the algorithm that was used to sign this certificate.
 */
int x509_note_sig_algo(void *context, size_t hdrlen, unsigned char tag,
		       const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key_signature *sig = &cert->sig;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	printf_debug("PubKey Algo: %u\n", ctx->last_oid);

	ctx->sig_algo = ctx->last_oid;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
	switch (ctx->last_oid) {
#ifdef LC_SHA3
	case OID_id_MLDSA44:
		sig->pkey_algo = LC_SIG_DILITHIUM_44;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_MLDSA65:
		sig->pkey_algo = LC_SIG_DILITHIUM_65;
		sig->hash_algo = lc_sha3_384;
		return 0;

	case OID_id_MLDSA87:
		sig->pkey_algo = LC_SIG_DILITHIUM_87;
		sig->hash_algo = lc_sha3_512;
		return 0;

	case OID_id_SLHDSA_SHAKE_128F:
		sig->pkey_algo = LC_SIG_SPINCS_SHAKE_128F;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_SLHDSA_SHAKE_128S:
		sig->pkey_algo = LC_SIG_SPINCS_SHAKE_128S;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_SLHDSA_SHAKE_192F:
		sig->pkey_algo = LC_SIG_SPINCS_SHAKE_192F;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_SLHDSA_SHAKE_192S:
		sig->pkey_algo = LC_SIG_SPINCS_SHAKE_192S;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_SLHDSA_SHAKE_256F:
		sig->pkey_algo = LC_SIG_SPINCS_SHAKE_256F;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_SLHDSA_SHAKE_256S:
		sig->pkey_algo = LC_SIG_SPINCS_SHAKE_256S;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_rsassa_pkcs1_v1_5_with_sha3_256:
		sig->pkey_algo = LC_SIG_RSA_PKCS1;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_rsassa_pkcs1_v1_5_with_sha3_384:
		sig->pkey_algo = LC_SIG_RSA_PKCS1;
		sig->hash_algo = lc_sha3_384;
		return 0;

	case OID_id_rsassa_pkcs1_v1_5_with_sha3_512:
		sig->pkey_algo = LC_SIG_RSA_PKCS1;
		sig->hash_algo = lc_sha3_512;
		return 0;

	case OID_id_ecdsa_with_sha3_256:
		sig->pkey_algo = LC_SIG_ECDSA_X963;
		sig->hash_algo = lc_sha3_256;
		return 0;

	case OID_id_ecdsa_with_sha3_384:
		sig->pkey_algo = LC_SIG_ECDSA_X963;
		sig->hash_algo = lc_sha3_384;
		return 0;

	case OID_id_ecdsa_with_sha3_512:
		sig->pkey_algo = LC_SIG_ECDSA_X963;
		sig->hash_algo = lc_sha3_512;
		return 0;
#endif
#ifdef LC_SHA2_256
	case OID_sha256WithRSAEncryption:
		sig->pkey_algo = LC_SIG_RSA_PKCS1;
		sig->hash_algo = lc_sha256;
		return 0;
	case OID_id_ecdsa_with_sha256:
		sig->pkey_algo = LC_SIG_ECDSA_X963;
		sig->hash_algo = lc_sha256;
		return 0;
#endif
#ifdef LC_SHA2_512
	/*
	 * See https://www.ietf.org/archive/id/draft-ietf-lamps-pq-composite-sigs-02.html
	 * section 7 (table, column pre-hash).
	 */
	case OID_id_MLDSA44_Ed25519_SHA512:
		sig->pkey_algo = LC_SIG_DILITHIUM_44;
		sig->hash_algo = lc_sha512;
		return 0;
	case OID_id_MLDSA65_Ed25519_SHA512:
		sig->pkey_algo = LC_SIG_DILITHIUM_65;
		sig->hash_algo = lc_sha512;
		return 0;
	case OID_id_MLDSA87_Ed448_SHA512:
		sig->pkey_algo = LC_SIG_DILITHIUM_87;
		sig->hash_algo = lc_sha512;
		return 0;

	case OID_sha384WithRSAEncryption:
		sig->pkey_algo = LC_SIG_RSA_PKCS1;
		sig->hash_algo = lc_sha384;
		return 0;

	case OID_sha512WithRSAEncryption:
		sig->pkey_algo = LC_SIG_RSA_PKCS1;
		sig->hash_algo = lc_sha512;
		return 0;

	case OID_id_ecdsa_with_sha384:
		sig->pkey_algo = LC_SIG_ECDSA_X963;
		sig->hash_algo = lc_sha384;
		return 0;

	case OID_id_ecdsa_with_sha512:
		sig->pkey_algo = LC_SIG_ECDSA_X963;
		sig->hash_algo = lc_sha512;
		return 0;
#endif

#if 0
	case OID_gost2012Signature256:
		sig->pkey_algo = LC_SIG_ECRDSA_PKCS1;
		sig->hash_algo = lc_streebog256;
		return 0;

	case OID_gost2012Signature512:
		sig->pkey_algo = LC_SIG_ECRDSA_PKCS1;
		sig->hash_algo = lc_streebog512;
		return 0;

	case OID_SM2_with_SM3:
		sig->pkey_algo = LC_SIG_SM2;
		sig->hash_algo = lc_sm3;
		return 0;
#endif

	default:
		ctx->sig_algo = OID__NR;
		return -ENOPKG; /* Unsupported combination */
	}
#pragma GCC diagnostic pop

	/* We should never reach this */
	return -EFAULT;
}

/*
 * Note the whereabouts and type of the signature.
 */
int x509_note_signature(void *context, size_t hdrlen, unsigned char tag,
			const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key_signature *sig = &cert->sig;

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

	switch (sig->pkey_algo) {
	case LC_SIG_RSA_PKCS1:
	case LC_SIG_ECDSA_X963:
	case LC_SIG_ECRDSA_PKCS1:
	case LC_SIG_SM2:
		/* Discard the BIT STRING metadata */
		if (vlen < 1 || *(const uint8_t *)value != 0)
			return -EBADMSG;

		value++;
		vlen--;
		break;

	case LC_SIG_DILITHIUM_44:
	case LC_SIG_DILITHIUM_44_ED25519:
	case LC_SIG_DILITHIUM_65:
	case LC_SIG_DILITHIUM_65_ED25519:
	case LC_SIG_DILITHIUM_87:
	case LC_SIG_DILITHIUM_87_ED25519:
	case LC_SIG_DILITHIUM_87_ED448:
	case LC_SIG_SPINCS_SHAKE_128F:
	case LC_SIG_SPINCS_SHAKE_128S:
	case LC_SIG_SPINCS_SHAKE_192F:
	case LC_SIG_SPINCS_SHAKE_192S:
	case LC_SIG_SPINCS_SHAKE_256F:
	case LC_SIG_SPINCS_SHAKE_256S:
	case LC_SIG_UNKNOWN:
	default:
		/* Do nothing */
		break;
	}

	ctx->cert->raw_sig = value;
	ctx->cert->raw_sig_size = vlen;
	return 0;
}

/*
 * Note the certificate serial number
 */
int x509_note_serial(void *context, size_t hdrlen, unsigned char tag,
		     const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	cert->raw_serial = value;
	cert->raw_serial_size = vlen;
	return 0;
}

/*
 * Note some of the name segments from which we'll fabricate a name.
 */
int x509_extract_name_segment(void *context, size_t hdrlen, unsigned char tag,
			      const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct x509_certificate_name *name = &cert->issuer_segments;

	(void)hdrlen;
	(void)tag;

	/* If cn.size is already filled, we received the issuer, fill subject */
	if (name->cn.size)
		name = &cert->subject_segments;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
	switch (ctx->last_oid) {
	case OID_commonName:
		ctx->cn_size = (uint8_t)vlen;
		ctx->cn_offset = (uint16_t)(value - ctx->data);
		name->cn.value = value;
		name->cn.size = (uint8_t)vlen;
		break;
	case OID_organizationName:
		ctx->o_size = (uint8_t)vlen;
		ctx->o_offset = (uint16_t)(value - ctx->data);
		name->o.value = value;
		name->o.size = (uint8_t)vlen;
		break;
	case OID_email_address:
		ctx->email_size = (uint8_t)vlen;
		ctx->email_offset = (uint16_t)(value - ctx->data);
		name->email.value = value;
		name->email.size = (uint8_t)vlen;
		break;
	case OID_countryName:
		name->c.value = value;
		name->c.size = (uint8_t)vlen;
		break;
	case OID_stateOrProvinceName:
		name->st.value = value;
		name->st.size = (uint8_t)vlen;
		break;
	case OID_organizationUnitName:
		name->ou.value = value;
		name->ou.size = (uint8_t)vlen;
		break;
	default:
		break;
	}
#pragma GCC diagnostic pop

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
	struct x509_certificate *cert = ctx->cert;
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
			bin2hex(cert->san_ip, cert->san_ip_len, _name,
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
		    memcmp(data + ctx->cn_offset, data + ctx->o_offset, 7) == 0)
			goto single_component;

		if (ctx->o_size + 2 + ctx->cn_size + 1 >
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
	if (namesize > LC_ASN1_MAX_ISSUER_NAME) {
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

int x509_note_issuer(void *context, size_t hdrlen, unsigned char tag,
		     const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key_signature *sig = &cert->sig;
	int ret = 0;

	cert->raw_issuer = value;
	cert->raw_issuer_size = vlen;

	if (!sig->auth_ids[2].len) {
		CKINT(asymmetric_key_generate_id(&sig->auth_ids[2], value, vlen,
						 NULL, 0));
	}

	CKINT(x509_fabricate_name(ctx, hdrlen, tag, cert->issuer, vlen, 0));

out:
	return ret;
}

/*
 * Extract the parameters for the subject
 */
int x509_note_subject(void *context, size_t hdrlen, unsigned char tag,
		      const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;

	cert->raw_subject = value;
	cert->raw_subject_size = vlen;
	return x509_fabricate_name(ctx, hdrlen, tag, cert->subject, vlen, 1);
}

/*
 * Extract the parameters for the public key
 */
int x509_note_params(void *context, size_t hdrlen, unsigned char tag,
		     const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;

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
int x509_extract_key_data(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key *pub = &cert->pub;
	enum OID oid;

	(void)hdrlen;
	(void)tag;

	ctx->key_algo = ctx->last_oid;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
	switch (ctx->last_oid) {
	case OID_id_MLDSA44:
	case OID_id_MLDSA44_Ed25519_SHA512:
		pub->pkey_algo = LC_SIG_DILITHIUM_44;
		break;

	case OID_id_MLDSA65:
	case OID_id_MLDSA65_Ed25519_SHA512:
		pub->pkey_algo = LC_SIG_DILITHIUM_65;
		break;

	case OID_id_MLDSA87:
	case OID_id_MLDSA87_Ed448_SHA512:
		pub->pkey_algo = LC_SIG_DILITHIUM_87;
		break;

	case OID_id_SLHDSA_SHAKE_128F:
		pub->pkey_algo = LC_SIG_SPINCS_SHAKE_128F;
		break;

	case OID_id_SLHDSA_SHAKE_128S:
		pub->pkey_algo = LC_SIG_SPINCS_SHAKE_128S;
		break;

	case OID_id_SLHDSA_SHAKE_192F:
		pub->pkey_algo = LC_SIG_SPINCS_SHAKE_192F;
		break;

	case OID_id_SLHDSA_SHAKE_192S:
		pub->pkey_algo = LC_SIG_SPINCS_SHAKE_192S;
		break;

	case OID_id_SLHDSA_SHAKE_256F:
		pub->pkey_algo = LC_SIG_SPINCS_SHAKE_256F;
		break;

	case OID_id_SLHDSA_SHAKE_256S:
		pub->pkey_algo = LC_SIG_SPINCS_SHAKE_256S;
		break;

	case OID_rsaEncryption:
		pub->pkey_algo = LC_SIG_RSA_PKCS1;
		break;
	case OID_gost2012PKey256:
	case OID_gost2012PKey512:
		pub->pkey_algo = LC_SIG_ECRDSA_PKCS1;
		break;
	case OID_sm2:
		pub->pkey_algo = LC_SIG_SM2;
		break;
	case OID_id_ecPublicKey:
		if (parse_OID(ctx->params, ctx->params_size, &oid) != 0)
			return -EBADMSG;

		switch (oid) {
		case OID_sm2:
			pub->pkey_algo = LC_SIG_SM2;
			break;
		case OID_id_prime192v1:
		case OID_id_prime256v1:
		case OID_id_ansip384r1:
		case OID_id_ansip521r1:
			pub->pkey_algo = LC_SIG_ECDSA_X963;
			break;
		default:
			return -ENOPKG;
		}
		break;
	default:
		return -ENOPKG;
	}
#pragma GCC diagnostic pop

	/* Discard the BIT STRING metadata */
	if (vlen < 1 || *(const uint8_t *)value != 0)
		return -EBADMSG;
	ctx->key = value + 1;
	ctx->key_size = vlen - 1;
	return 0;
}
/*
 * Extract the criticality of an extension
 */
int x509_extension_critical(void *context, size_t hdrlen, unsigned char tag,
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
int x509_eku(void *context, size_t hdrlen, unsigned char tag,
	     const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key *pub = &cert->pub;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	bin2print_debug(value, vlen, stdout, "OID");
	ctx->last_oid = look_up_OID(value, vlen);

	printf_debug("Extended Key Usage: %u\n", ctx->last_oid);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
	switch (ctx->last_oid) {
	case OID_anyExtendedKeyUsage:
		pub->key_eku |= LC_KEY_EKU_ANY;
		break;
	case OID_id_kp_serverAuth:
		pub->key_eku |= LC_KEY_EKU_SERVER_AUTH;
		break;
	case OID_id_kp_clientAuth:
		pub->key_eku |= LC_KEY_EKU_CLIENT_AUTH;
		break;
	case OID_id_kp_codeSigning:
		pub->key_eku |= LC_KEY_EKU_CODE_SIGNING;
		break;
	case OID_id_kp_emailProtection:
		pub->key_eku |= LC_KEY_EKU_EMAIL_PROTECTION;
		break;
	case OID_id_kp_timeStamping:
		pub->key_eku |= LC_KEY_EKU_TIME_STAMPING;
		break;
	case OID_id_kp_OCSPSigning:
		pub->key_eku |= LC_KEY_EKU_OCSP_SIGNING;
		break;
	default:
		break;
	}
#pragma GCC diagnostic pop

	pub->key_eku |= ctx->extension_critical ? LC_KEY_EKU_CRITICAL : 0;
	pub->key_eku |= LC_KEY_EKU_EXTENSION_PRESENT;

	return 0;
}

/*
 * Extract the subject alternative name - DNS parameter
 */
int x509_san_dns(void *context, size_t hdrlen, unsigned char tag,
		 const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	cert->san_dns = (char *)value;
	cert->san_dns_len = vlen;

	return x509_fabricate_name(ctx, hdrlen, tag, cert->subject, vlen, 1);
}

/*
 * Extract the subject alternative name - IP parameter
 */
int x509_san_ip(void *context, size_t hdrlen, unsigned char tag,
		const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	cert->san_ip = value;
	cert->san_ip_len = vlen;

	return 0;
}

/*
 * Extract the basic constraints CA field
 */
int x509_basic_constraints_ca(void *context, size_t hdrlen, unsigned char tag,
			      const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key *pub = &cert->pub;

	(void)hdrlen;
	(void)tag;

	if (vlen != 1)
		return -EBADMSG;

	ctx->extension_critical = (value[0] == ASN1_TRUE);
	pub->ca_pathlen = (value[0] == ASN1_TRUE) ? LC_KEY_CA_MAXLEN : 0;
	pub->ca_pathlen |= ctx->extension_critical ? LC_KEY_CA_CRITICAL : 0;

	return 0;
}

/*
 * Extract the basic constraints pathlen
 */
int x509_basic_constraints_pathlen(void *context, size_t hdrlen,
				   unsigned char tag, const uint8_t *value,
				   size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key *pub = &cert->pub;
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

	/* Undo the CA flag maxlen setting */
	pub->ca_pathlen &= (uint8_t)~LC_KEY_CA_MAXLEN;
	pub->ca_pathlen |= min_uint8(LC_KEY_CA_MAXLEN, pathlen);

	return 0;
}

/*
 * Extract the key usage
 */
int x509_key_usage(void *context, size_t hdrlen, unsigned char tag,
		   const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key *pub = &cert->pub;

	(void)hdrlen;
	(void)tag;

	if (vlen > 2 || vlen == 0)
		return -EBADMSG;

	pub->key_usage = value[0];

	if (vlen == 2)
		pub->key_usage |= (uint16_t)(value[1] << 8);

	pub->key_usage |= ctx->extension_critical ? LC_KEY_USAGE_CRITICAL : 0;
	pub->key_usage |= LC_KEY_USAGE_EXTENSION_PRESENT;

	/*
	 * BIT STRING is handled as a big-endian value which implies that we
	 * need to convert it here.
	 */
	pub->key_usage = be_bswap16(pub->key_usage);

	return 0;
}

/*
 * Extract the subject key ID
 */
int x509_skid(void *context, size_t hdrlen, unsigned char tag,
	      const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct asymmetric_key_id *skid = &cert->skid;
	int ret;

	(void)hdrlen;
	(void)tag;

	/* Get hold of the key fingerprint */
	if (skid->len || vlen == 0)
		return -EBADMSG;

	cert->raw_skid_size = vlen;
	cert->raw_skid = value;
	CKINT(asymmetric_key_generate_id(skid, value, vlen, NULL, 0));
	bin2print_debug(skid->data, skid->len, stdout, "subjkeyid");

out:
	return ret;
}

/*
 * Process certificate extensions that are used to qualify the certificate.
 */
int x509_process_extension(void *context, size_t hdrlen, unsigned char tag,
			   const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	int ret = 0;

	(void)hdrlen;
	(void)tag;
	(void)ctx;

	printf_debug("Extension: %u\n", ctx->last_oid);

	if (ctx->last_oid == OID_subjectKeyIdentifier) {
		CKINT(asn1_ber_decoder(&x509_skid_decoder, ctx, value, vlen));
	}

	if (ctx->last_oid == OID_keyUsage) {
		CKINT(asn1_ber_decoder(&x509_keyusage_decoder, ctx, value,
				       vlen));
	}

	if (ctx->last_oid == OID_authorityKeyIdentifier) {
		/* Get hold of the CA key fingerprint */
		ctx->raw_akid = value;
		ctx->raw_akid_size = vlen;
		return 0;
	}

	if (ctx->last_oid == OID_basicConstraints) {
		CKINT(asn1_ber_decoder(&x509_basic_constraints_decoder, ctx,
				       value, vlen));
	}

	if (ctx->last_oid == OID_extKeyUsage) {
		CKINT(asn1_ber_decoder(&x509_eku_decoder, ctx, value, vlen));
	}

	if (ctx->last_oid == OID_subjectAltName) {
		CKINT(asn1_ber_decoder(&x509_san_decoder, ctx, value, vlen));
	}

out:
	return ret;
}

static time64_t mktime64(const unsigned int year0, const unsigned int mon0,
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

int x509_decode_time(time64_t *_t, size_t hdrlen, unsigned char tag,
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

	*_t = mktime64(year, mon, day, hour, min, sec);
	printf_debug("Time stamp %" PRIu64 "\n", *_t);
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
int x509_note_not_before(void *context, size_t hdrlen, unsigned char tag,
			 const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;

	return x509_decode_time(&cert->valid_from, hdrlen, tag, value, vlen);
}

/*
 * Process the time when the certificate becomes invalid
 */
int x509_note_not_after(void *context, size_t hdrlen, unsigned char tag,
			const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;

	return x509_decode_time(&cert->valid_to, hdrlen, tag, value, vlen);
}

/*
 * Note a key identifier-based AuthorityKeyIdentifier
 */
int x509_akid_note_kid(void *context, size_t hdrlen, unsigned char tag,
		       const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key_signature *sig = &cert->sig;
	struct asymmetric_key_id *auth_id = &sig->auth_ids[1];
	int ret;

	(void)hdrlen;
	(void)tag;

	bin2print_debug(value, vlen, stdout, "AKID: keyid");

	if (auth_id->len)
		return 0;

	cert->raw_akid_size = vlen;
	cert->raw_akid = value;

	CKINT(asymmetric_key_generate_id(auth_id, value, vlen, NULL, 0));
	bin2print_debug(auth_id->data, auth_id->len, stdout, "authkeyid");

out:
	return ret;
}

/*
 * Note a directoryName in an AuthorityKeyIdentifier
 */
int x509_akid_note_name(void *context, size_t hdrlen, unsigned char tag,
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
int x509_akid_note_serial(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct x509_certificate *cert = ctx->cert;
	struct public_key_signature *sig = &cert->sig;
	struct asymmetric_key_id *auth_id = &sig->auth_ids[0];
	int ret;

	(void)hdrlen;
	(void)tag;

	bin2print_debug(value, vlen, stdout, "AKID: serial");

	if (!ctx->akid_raw_issuer || auth_id->len)
		return 0;

	CKINT(asymmetric_key_generate_id(auth_id, value, vlen,
					 ctx->akid_raw_issuer,
					 ctx->akid_raw_issuer_size));

	bin2print_debug(auth_id->data, auth_id->len, stdout, "authkeyid");

out:
	return ret;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(void, lc_x509_certificate_clear,
		      struct x509_certificate *cert)
{
	if (!cert)
		return;

	public_key_clear(&cert->pub);
	public_key_signature_clear(&cert->sig);
}

LC_INTERFACE_FUNCTION(int, lc_x509_certificate_parse,
		      struct x509_certificate *x509, const uint8_t *data,
		      size_t datalen)
{
	struct x509_parse_context ctx = { 0 };
	int ret;

	CKNULL(x509, -EINVAL);
	CKNULL(data, -EINVAL);

	lc_memset_secure(x509, 0, sizeof(struct x509_certificate));
	ctx.cert = x509;
	ctx.data = data;

	/* Attempt to decode the certificate */
	CKINT(asn1_ber_decoder(&x509_decoder, &ctx, data, datalen));

	/* Decode the AuthorityKeyIdentifier */
	if (ctx.raw_akid) {
		bin2print_debug(ctx.raw_akid, ctx.raw_akid_size, stdout,
				"AKID");
		CKINT(asn1_ber_decoder(&x509_akid_decoder, &ctx, ctx.raw_akid,
				       ctx.raw_akid_size));
	}

	x509->pub.key = ctx.key;
	x509->pub.keylen = ctx.key_size;

	x509->pub.params = ctx.params;
	x509->pub.paramlen = ctx.params_size;

	x509->pub.algo = ctx.key_algo;

	/* Grab the signature bits */
	CKINT(x509_get_sig_params(x509));

	/* Generate cert issuer + serial number key ID */
	CKINT(asymmetric_key_generate_id(
		&x509->id, x509->raw_serial, x509->raw_serial_size,
		x509->raw_issuer, x509->raw_issuer_size));

	/* Detect self-signed certificates */
	CKINT(x509_check_for_self_signed(x509));

out:
	if (ret)
		lc_x509_certificate_clear(x509);
	return ret;
}
