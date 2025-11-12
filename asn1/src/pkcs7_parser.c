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

#include "asn1_debug.h"
#include "ext_headers_internal.h"
#include "helper.h"
#include "lc_memory_support.h"
#include "lc_pkcs7_parser.h"
#include "oid_registry.h"
#include "pkcs7_internal.h"
#include "pkcs7_asn1.h"
#include "pkcs7_aa_asn1.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "x509_algorithm_mapper.h"
#include "x509_cert_parser.h"

/******************************************************************************
 * ASN.1 parser support functions
 ******************************************************************************/

static __always_inline int lc_test_and_set_bit(unsigned long nr,
					       volatile unsigned long *addr)
{
	unsigned long *p = ((unsigned long *)addr);
	unsigned long old = *p;

	*p = old | nr;
	return (old & nr) != 0;
}

int pkcs7_external_aa(void *context, size_t hdrlen, unsigned char tag,
		      const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;
	return 0;
}

int pkcs7_external_aa_OID(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;
	return 0;
}

int pkcs7_external_aa_continue(void *context, size_t hdrlen, unsigned char tag,
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
 * Check authenticatedAttributes are provided or not provided consistently.
 */
static int pkcs7_check_authattrs(struct lc_pkcs7_message *msg)
{
	struct lc_pkcs7_signed_info *sinfo;
	unsigned int want = 0;

	sinfo = msg->list_head_sinfo;
	if (!sinfo)
		goto inconsistent;

	if (sinfo->authattrs) {
		want = 1;
		msg->have_authattrs = 1;
	}

	for (sinfo = sinfo->next; sinfo; sinfo = sinfo->next)
		if (!!sinfo->authattrs != want)
			goto inconsistent;
	return 0;

inconsistent:
	printf_debug("Inconsistently supplied authAttrs\n");
	return -EINVAL;
}

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
static int pkcs7_note_OID(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	ctx->last_oid = look_up_OID(value, vlen);

	if (ctx->last_oid == OID__NR) {
		char buffer[50];

		sprint_oid(value, vlen, buffer, sizeof(buffer));
		printf_debug("PKCS7: Unknown OID: [%lu] %s\n",
			     value - ctx->data, buffer);
	}
	return 0;
}

int pkcs7_sig_note_pkey_algo_OID(void *context, size_t hdrlen,
				 unsigned char tag, const uint8_t *value,
				 size_t vlen)
{
	return pkcs7_note_OID(context, hdrlen, tag, value, vlen);
}

int pkcs7_digest_algorithm_OID(void *context, size_t hdrlen, unsigned char tag,
			       const uint8_t *value, size_t vlen)
{
	return pkcs7_note_OID(context, hdrlen, tag, value, vlen);
}

int pkcs7_authenticated_attr_OID(void *context, size_t hdrlen,
				 unsigned char tag, const uint8_t *value,
				 size_t vlen)
{
	return pkcs7_note_OID(context, hdrlen, tag, value, vlen);
}

int pkcs7_data_OID(void *context, size_t hdrlen, unsigned char tag,
		   const uint8_t *value, size_t vlen)
{
	return pkcs7_note_OID(context, hdrlen, tag, value, vlen);
}

int pkcs7_check_content_type_OID(void *context, size_t hdrlen,
				 unsigned char tag, const uint8_t *value,
				 size_t vlen)
{
	return pkcs7_note_OID(context, hdrlen, tag, value, vlen);
}

int pkcs7_note_attribute_type_OID(void *context, size_t hdrlen,
				  unsigned char tag, const uint8_t *value,
				  size_t vlen)
{
	return pkcs7_note_OID(context, hdrlen, tag, value, vlen);
}

int pkcs7_extract_attribute_name_segment(void *context, size_t hdrlen,
					 unsigned char tag,
					 const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;
	return 0;
}

int pkcs7_attribute_value_continue(void *context, size_t hdrlen,
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
 * Note the digest algorithm for the signature.
 */
int pkcs7_sig_note_digest_algo(void *context, size_t hdrlen, unsigned char tag,
			       const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct lc_pkcs7_message *pkcs7 = ctx->msg;
	struct lc_pkcs7_signed_info *sinfo;
	struct lc_public_key_signature *sig;
	int ret;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	CKINT(pkcs7_sinfo_get(&sinfo, pkcs7));

	sig = &sinfo->sig;
	CKINT(lc_x509_oid_to_hash(ctx->last_oid, &sig->hash_algo));

out:
	return ret;
}

/*
 * Note the public key algorithm for the signature.
 */
int pkcs7_sig_note_pkey_algo(void *context, size_t hdrlen, unsigned char tag,
			     const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct lc_pkcs7_message *pkcs7 = ctx->msg;
	struct lc_pkcs7_signed_info *sinfo;
	struct lc_public_key_signature *sig;
	int ret;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	CKINT(pkcs7_sinfo_get(&sinfo, pkcs7));

	sig = &sinfo->sig;
	CKINT(lc_x509_oid_to_sig_type(ctx->last_oid, &sig->pkey_algo));

out:
	return ret;
}

/*
 * We only support signed data [RFC5652 chapter 5].
 */
int pkcs7_check_content_type(void *context, size_t hdrlen, unsigned char tag,
			     const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	if (ctx->last_oid != OID_signed_data) {
		printf_debug("Only support pkcs7_signedData type\n");
		return -EINVAL;
	}

	return 0;
}

/*
 * Note the SignedData version
 */
int pkcs7_note_signeddata_version(void *context, size_t hdrlen,
				  unsigned char tag, const uint8_t *value,
				  size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	unsigned int version;

	(void)hdrlen;
	(void)tag;

	if (vlen != 1)
		goto unsupported;

	ctx->msg->version = *(const uint8_t *)value;
	version = ctx->msg->version;
	switch (version) {
	case 1:
		/* PKCS#7 SignedData [RFC2315 sec 9.1]
		 * CMS ver 1 SignedData [RFC5652 sec 5.1]
		 */
		break;
	case 3:
		/* CMS ver 3 SignedData [RFC2315 sec 5.1] */
		break;
	default:
		goto unsupported;
	}

	return 0;

unsupported:
	printf_debug("Unsupported SignedData version\n");
	return -EINVAL;
}

/*
 * Note the SignerInfo version
 */
int pkcs7_note_signerinfo_version(void *context, size_t hdrlen,
				  unsigned char tag, const uint8_t *value,
				  size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	unsigned version;

	(void)hdrlen;
	(void)tag;

	if (vlen != 1)
		goto unsupported;

	version = *(const uint8_t *)value;
	switch (version) {
	case 1:
		/* PKCS#7 SignerInfo [RFC2315 sec 9.2]
		 * CMS ver 1 SignerInfo [RFC5652 sec 5.3]
		 */
		if (ctx->msg->version != 1)
			goto version_mismatch;
		ctx->expect_skid = 0;
		break;
	case 3:
		/* CMS ver 3 SignerInfo [RFC2315 sec 5.3] */
		if (ctx->msg->version == 1)
			goto version_mismatch;
		ctx->expect_skid = 1;
		break;
	default:
		goto unsupported;
	}

	return 0;

unsupported:
	printf_debug("Unsupported SignerInfo version\n");
	return -EINVAL;
version_mismatch:
	printf_debug("SignedData-SignerInfo version mismatch\n");
	return -EBADMSG;
}

int pkcs7_extract_cert_continue(void *context, size_t hdrlen, unsigned char tag,
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
 * Extract a certificate and store it in the context.
 */
int pkcs7_extract_cert(void *context, size_t hdrlen, unsigned char tag,
		       const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct lc_pkcs7_message *pkcs7 = ctx->msg;
	struct lc_x509_certificate *x509;
	struct lc_asymmetric_key_id *id;
	int ret;

	if (tag != ((ASN1_UNIV << 6) | ASN1_CONS_BIT | ASN1_SEQ)) {
		printf_debug("Cert began with tag %02x at %lu\n", tag,
			     (uint8_t *)ctx - ctx->data);
		return -EBADMSG;
	}

	/* We have to correct for the header so that the X.509 parser can start
	 * from the beginning.  Note that since X.509 stipulates DER, there
	 * probably shouldn't be an EOC trailer - but it is in PKCS#7 (which
	 * stipulates BER).
	 */
	value -= hdrlen;
	vlen += hdrlen;

	if (((uint8_t *)value)[1] == 0x80)
		vlen += 2; /* Indefinite length - there should be an EOC */

	CKINT(pkcs7_x509_get(&x509, pkcs7));

	CKINT(lc_x509_cert_decode(x509, value, vlen));

	x509->index = ++ctx->x509_index;
	printf_debug("Got cert %u for %s\n", x509->index, x509->subject);

	id = &x509->id;
	(void)id; /* Unused in non-debug compilation */
	bin2print_debug(id->data, id->len, stdout, "- fingerprint");

	*ctx->ppcerts = x509;
	ctx->ppcerts = &x509->next;

out:
	return ret;
}

int pkcs7_extract_crl_cert(void *context, size_t hdrlen, unsigned char tag,
			   const uint8_t *value, size_t vlen)
{
	return pkcs7_extract_cert(context, hdrlen, tag, value, vlen);
}

int pkcs7_extract_extended_cert(void *context, size_t hdrlen, unsigned char tag,
				const uint8_t *value, size_t vlen)
{
	return pkcs7_extract_cert(context, hdrlen, tag, value, vlen);
}

/*
 * Save the certificate list
 */
int pkcs7_note_certificate_list(void *context, size_t hdrlen, unsigned char tag,
				const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	printf_debug("Got cert list (%02x)\n", tag);

	*ctx->ppcerts = ctx->msg->certs;
	ctx->msg->certs = ctx->certs;
	ctx->certs = NULL;
	ctx->ppcerts = &ctx->certs;
	return 0;
}

/*
 * Note the content type.
 */
int pkcs7_note_content(void *context, size_t hdrlen, unsigned char tag,
		       const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	if (ctx->last_oid != OID_data && ctx->last_oid != OID_msIndirectData) {
		printf_debug("Unsupported data type %d\n", ctx->last_oid);
		return -EINVAL;
	}

	ctx->msg->data_type = ctx->last_oid;
	return 0;
}

/*
 * Extract the data from the message and store that and its content type OID in
 * the context.
 */
int pkcs7_note_data(void *context, size_t hdrlen, unsigned char tag,
		    const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	printf_debug("Got data\n");

	ctx->msg->data = value;
	ctx->msg->data_len = vlen;
	return 0;
}

/*
 * Parse authenticated attributes.
 */
int pkcs7_sig_note_authenticated_attr(void *context, size_t hdrlen,
				      unsigned char tag, const uint8_t *value,
				      size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct lc_pkcs7_message *pkcs7 = ctx->msg;
	struct lc_pkcs7_signed_info *sinfo;
	enum OID content_type;
	int ret;

	printf_debug("AuthAttr: %02x %zu", tag, vlen);
	bin2print_debug(value, vlen, stdout, "");

	CKINT(pkcs7_sinfo_get(&sinfo, pkcs7));

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch-enum"
	switch (ctx->last_oid) {
	case OID_contentType:
		if (lc_test_and_set_bit(sinfo_has_content_type, &sinfo->aa_set))
			goto repeated;
		content_type = look_up_OID(value, vlen);
		if (content_type != ctx->msg->data_type) {
			printf_debug(
				"Mismatch between global data type (%d) and sinfo %u (%d)\n",
				ctx->msg->data_type, content_type,
				sinfo->index);
			return -EBADMSG;
		}
		return 0;

	case OID_signingTime:
		if (lc_test_and_set_bit(sinfo_has_signing_time, &sinfo->aa_set))
			goto repeated;
		/* Should we check that the signing time is consistent
		 * with the signer's X.509 cert?
		 */
		return x509_decode_time(&sinfo->signing_time, hdrlen, tag,
					value, vlen);

	case OID_messageDigest:
		if (lc_test_and_set_bit(sinfo_has_message_digest,
					&sinfo->aa_set))
			goto repeated;
		if (tag != ASN1_OTS)
			return -EBADMSG;
		sinfo->msgdigest = value;
		sinfo->msgdigest_len = vlen;
		return 0;

	case OID_smimeCapabilites:
		if (lc_test_and_set_bit(sinfo_has_smime_caps, &sinfo->aa_set))
			goto repeated;
		if (ctx->msg->data_type != OID_msIndirectData) {
			printf_debug(
				"S/MIME Caps only allowed with Authenticode\n");
			//TODO - Why is this in the Linux code?
			//			return -EKEYREJECTED;
		}
		return 0;

		/* Microsoft SpOpusInfo seems to be contain cont[0] 16-bit BE
		 * char URLs and cont[1] 8-bit char URLs.
		 *
		 * Microsoft StatementType seems to contain a list of OIDs that
		 * are also used as extendedKeyUsage types in X.509 certs.
		 */
	case OID_msSpOpusInfo:
		if (lc_test_and_set_bit(sinfo_has_ms_opus_info, &sinfo->aa_set))
			goto repeated;
		goto authenticode_check;
	case OID_msStatementType:
		if (lc_test_and_set_bit(sinfo_has_ms_statement_type,
					&sinfo->aa_set))
			goto repeated;
	authenticode_check:
		if (ctx->msg->data_type != OID_msIndirectData) {
			printf_debug(
				"Authenticode AuthAttrs only allowed with Authenticode\n");
			return -EKEYREJECTED;
		}
		/* I'm not sure how to validate these */
		return 0;
	default:
		return 0;
	}
#pragma GCC diagnostic pop

repeated:
	/* We permit max one item per AuthenticatedAttribute and no repeats */
	printf_debug("Repeated/multivalue AuthAttrs not permitted\n");
	return -EKEYREJECTED;

out:
	return ret;
}

/*
 * Note the set of auth attributes for digestion purposes [RFC2315 sec 9.3]
 */
int pkcs7_sig_note_set_of_authattrs(void *context, size_t hdrlen,
				    unsigned char tag, const uint8_t *value,
				    size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct lc_pkcs7_message *pkcs7 = ctx->msg;
	struct lc_pkcs7_signed_info *sinfo;
	int ret;

	(void)tag;

	CKINT(pkcs7_sinfo_get(&sinfo, pkcs7));

	if (!(sinfo->aa_set & sinfo_has_content_type) ||
	    !(sinfo->aa_set & sinfo_has_message_digest)) {
		printf_debug("Missing required AuthAttr\n");
		return -EBADMSG;
	}

	if (ctx->msg->data_type != OID_msIndirectData &&
	    (sinfo->aa_set & sinfo_has_ms_opus_info)) {
		printf_debug("Unexpected Authenticode AuthAttr\n");
		return -EBADMSG;
	}

	/* We need to switch the 'CONT 0' to a 'SET OF' when we digest */
	sinfo->authattrs = value - (hdrlen - 1);
	sinfo->authattrs_len = vlen + (hdrlen - 1);

out:
	return ret;
}

/*
 * This is the tag to be used as the leading tag for authenticated attributes.
 */
const uint8_t lc_pkcs7_authattr_tag = ASN1_CONS_BIT | ASN1_SET;

/*
 * Note the issuing certificate serial number
 */
int pkcs7_sig_note_serial(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	ctx->raw_serial = value;
	ctx->raw_serial_size = vlen;
	return 0;
}

/*
 * Note the issuer's name
 */
int pkcs7_sig_note_issuer(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	ctx->raw_issuer = value;
	ctx->raw_issuer_size = vlen;
	return 0;
}

/*
 * Note the issuing cert's subjectKeyIdentifier
 */
int pkcs7_sig_note_skid(void *context, size_t hdrlen, unsigned char tag,
			const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	bin2print_debug(value, vlen, stdout, "subjkeyid");

	ctx->raw_skid = value;
	ctx->raw_skid_size = vlen;
	return 0;
}

/*
 * Note the signature data
 */
int pkcs7_sig_note_signature(void *context, size_t hdrlen, unsigned char tag,
			     const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct lc_pkcs7_message *pkcs7 = ctx->msg;
	struct lc_pkcs7_signed_info *sinfo;
	int ret;

	(void)hdrlen;
	(void)tag;

	CKINT(pkcs7_sinfo_get(&sinfo, pkcs7));

	/* Do not allocate twice */
	if (sinfo->sig.s)
		return -EOVERFLOW;

	sinfo->sig.s = value;
	sinfo->sig.s_size = vlen;

out:
	return ret;
}

/*
 * Note a signature information block
 */
int pkcs7_note_signed_info(void *context, size_t hdrlen, unsigned char tag,
			   const uint8_t *value, size_t vlen)
{
	struct pkcs7_parse_context *ctx = context;
	struct lc_pkcs7_message *pkcs7 = ctx->msg;
	struct lc_pkcs7_signed_info *sinfo;
	int ret;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	CKINT(pkcs7_sinfo_get(&sinfo, pkcs7));

	if (ctx->msg->data_type == OID_msIndirectData && !sinfo->authattrs) {
		printf_debug("Authenticode requires AuthAttrs\n");
		return -EBADMSG;
	}

	CKINT(pkcs7_sinfo_get(&sinfo, pkcs7));

	/* Generate cert issuer + serial number key ID */
	if (!ctx->expect_skid) {
		CKINT(asymmetric_key_generate_id(
			&sinfo->sig.auth_ids[0], ctx->raw_serial,
			ctx->raw_serial_size, ctx->raw_issuer,
			ctx->raw_issuer_size));
	} else {
		CKINT(asymmetric_key_generate_id(&sinfo->sig.auth_ids[0],
						 ctx->raw_skid,
						 ctx->raw_skid_size, NULL, 0));
	}

	bin2print_debug(sinfo->sig.auth_ids[0].data, sinfo->sig.auth_ids[0].len,
			stdout, "SINFO KID");

	sinfo->index = ++ctx->sinfo_index;

	/* Now add the filled signed info to the PKCS7 */
	CKINT(pkcs7_sinfo_add(pkcs7));

out:
	return ret;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_pkcs7_get_content_data,
		      const struct lc_pkcs7_message *pkcs7,
		      const uint8_t **data, size_t *data_len)
{
	if (!pkcs7 || !data || !data_len)
		return -EINVAL;

	if (!pkcs7->data)
		return -ENODATA;

	*data = pkcs7->data;
	*data_len = pkcs7->data_len;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_pkcs7_message_clear,
		      struct lc_pkcs7_message *pkcs7)
{
	struct lc_x509_certificate *cert;

	if (pkcs7) {
		while (pkcs7->certs) {
			cert = pkcs7->certs;
			pkcs7->certs = cert->next;
			pkcs7_x509_free(cert);
		}
		while (pkcs7->crl) {
			cert = pkcs7->crl;
			pkcs7->crl = cert->next;
			lc_x509_cert_clear(cert);
		}
		pkcs7_sinfo_free(pkcs7);

		lc_memset_secure(pkcs7, 0, sizeof(struct lc_pkcs7_message));
	}
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_decode, struct lc_pkcs7_message *pkcs7,
		      const uint8_t *data, size_t datalen)
{
	struct pkcs7_parse_context ctx = { 0 };
	int ret;

	CKNULL(pkcs7, -EINVAL);
	CKNULL(data, -EINVAL);

	ctx.msg = pkcs7;
	ctx.data = data;
	ctx.ppcerts = &ctx.certs;

	/* Attempt to decode the signature */
	CKINT(asn1_ber_decoder(&pkcs7_decoder, &ctx, data, datalen));

	CKINT(pkcs7_check_authattrs(ctx.msg));

out:
	return ret;
}
