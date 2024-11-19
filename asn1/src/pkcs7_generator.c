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

#include "asn1_encoder.h"
#include "ext_headers.h"
#include "lc_pkcs7_generator.h"
#include "lc_x509_generator.h"
#include "pkcs7.asn1.h"
#include "pkcs7_aa.asn1.h"
#include "oid_registry.h"
#include "public_key.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "x509_algorithm_mapper.h"
#include "x509_cert_generator.h"

struct pkcs7_generate_context {
	/*
	  * Message being converted into PKCS#7 blob
	  */
	const struct lc_pkcs7_message *pkcs7;

	/*
	 * Iterator over the additional certificates to place their public key
	 * information into the PKCS#7 message.
	 */
	const struct lc_x509_certificate *current_x509;

	/*
	 * Iterator over the signer certificates to perform the actual signature
	 * operation.
	 */
	const struct lc_pkcs7_signed_info *current_sinfo;

	unsigned long aa_set_applied;
	uint8_t subject_attrib_processed;

	/* Authenticated Attribute data (or NULL) */
	const struct lc_hash *authattr_hash;
	size_t authattrs_digest_size;
	uint8_t authattrs_digest[LC_SHA_MAX_SIZE_DIGEST];
};

/******************************************************************************
 * ASN.1 parser support functions
 ******************************************************************************/

int pkcs7_sig_note_pkey_algo_OID_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_x509_certificate *current_x509 = ctx->current_x509;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	enum lc_sig_types pkey_algo;
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	enum OID oid;
	int ret;

	(void)tag;

	if (current_x509)
		pkey_algo = current_x509->pub.pkey_algo;
	else if (sinfo)
		pkey_algo = sinfo->signer->pub.pkey_algo;
	else
		return -EINVAL;

	CKINT(lc_x509_sig_type_to_oid(pkey_algo, &oid));

	CKINT(OID_to_data(oid, &oid_data, &oid_datalen));
	bin2print_debug(oid_data, oid_datalen, stdout,
			"OID signed pkey algorithm");

	if (oid_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

static int pkcs7_get_digest(const struct lc_hash **hash_algo,
			    const struct lc_pkcs7_signed_info *sinfo)
{
	const struct lc_public_key_signature *sig = &sinfo->sig;
	const struct lc_hash *tmp_algo = sig->hash_algo;
	int ret = 0;

	/*
	 * If we have no hash algorithm set externally, try the pubkey algo.
	 */
	if (!tmp_algo)
		CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &tmp_algo));
	*hash_algo = tmp_algo;

out:
	return ret;
}

int pkcs7_digest_algorithm_OID_enc(void *context, uint8_t *data,
				   size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const struct lc_hash *hash_algo;
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	enum OID oid;
	int ret;

	(void)tag;

	CKNULL(sinfo, -EINVAL);
	CKINT(pkcs7_get_digest(&hash_algo, sinfo));

	/*
	 * RFC5652 section 5.1 explicitly allows setting no entries here.
	 * This is applied with the return code of 2.
	 */
	if (!hash_algo)
		return LC_ASN1_RET_SET_ZERO_CONTENT;

	CKINT(lc_x509_hash_to_oid(hash_algo, &oid));
	CKINT(OID_to_data(oid, &oid_data, &oid_datalen));
	bin2print_debug(oid_data, oid_datalen, stdout,
			"OID signed hash algorithm");

	if (oid_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

/*
 * Note the digest algorithm for the signature.
 */
int pkcs7_sig_note_digest_algo_enc(void *context, uint8_t *data,
				   size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/*
 * Note the public key algorithm for the signature.
 */
int pkcs7_sig_note_pkey_algo_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/*
 * We only support signed data [RFC5652 chapter 5].
 */
int pkcs7_check_content_type_OID_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	int ret;

	(void)context;
	(void)tag;

	CKINT(OID_to_data(OID_signed_data, &oid_data, &oid_datalen));
	bin2print_debug(oid_data, oid_datalen, stdout, "OID pkcs7_signedData");

	if (oid_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

int pkcs7_check_content_type_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/*
 * Note the SignedData version
 */
int pkcs7_note_signeddata_version_enc(void *context, uint8_t *data,
				      size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_message *pkcs7 = ctx->pkcs7;
	const struct lc_x509_certificate *x509;
	unsigned int skid_present = 0;
	int ret;
	uint8_t cms_version;

	(void)tag;

	for (x509 = pkcs7->certs; x509; x509 = x509->next) {
		if (x509->raw_skid_size) {
			skid_present = 1;
			break;
		}
	}

	CKINT(x509_sufficient_size(avail_datalen, 1));

	if (skid_present)
		cms_version = 3;
	else
		cms_version = 1;

	data[0] = cms_version;
	*avail_datalen -= 1;
	printf_debug("Set CMS version %u\n", cms_version);

out:
	return ret;
}

/*
 * Note the SignerInfo version
 */
int pkcs7_note_signerinfo_version_enc(void *context, uint8_t *data,
				      size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const struct lc_x509_certificate *x509;
	int ret;
	uint8_t cms_version;

	(void)tag;

	CKNULL(sinfo, -EFAULT);
	x509 = sinfo->signer;

	CKINT(x509_sufficient_size(avail_datalen, 1));

	if (x509->raw_skid_size)
		cms_version = 3;
	else
		cms_version = 1;

	data[0] = cms_version;
	*avail_datalen -= 1;
	printf_debug("Set CMS version %u\n", cms_version);

out:
	return ret;
}

int pkcs7_extract_cert_continue_enc(void *context, uint8_t *data,
				    size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_x509_certificate *current_x509 = ctx->current_x509;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	if (!current_x509)
		return 0;

	/* Iterate to the next certificate */
	ctx->current_x509 = current_x509->next;

	current_x509 = ctx->current_x509;
	if (!current_x509)
		return 0;

	return LC_ASN1_RET_CONTINUE;
}

/*
 * Write a certificate and store it in the buffer.
 */
int pkcs7_extract_cert_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/*
 * Write a CRL certificate and store it in the buffer.
 */
int pkcs7_extract_crl_cert_enc(void *context, uint8_t *data,
			       size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/*
 * Write an Extended certificate and store it in the buffer.
 */
int pkcs7_extract_extended_cert_enc(void *context, uint8_t *data,
				    size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_x509_certificate *current_x509 = ctx->current_x509;
	size_t offset, len;
	int ret;

	CKNULL(current_x509->raw_cert, -EINVAL);

	if (current_x509->raw_cert_size < 4)
		return -EINVAL;

	/*
	 * Strip the tag and the length
	 *
	 * TODO recheck
	 */

	/* Set the tag */
	*tag = current_x509->raw_cert[0];

	/* Consume the just set tag value */
	offset = 1;

	len = *(current_x509->raw_cert + offset);
	/* Consume the just parsed length field */
	offset++;

	/* Check if we have an extended length field */
	if (len > 0x7f) {
		if (len == ASN1_INDEFINITE_LENGTH)
			return -EINVAL;

		len -= 0x80;
		if (len > 2)
			return -EINVAL;
		offset += len;
	}

	CKINT(x509_sufficient_size(avail_datalen,
				   current_x509->raw_cert_size - offset));
	memcpy(data, current_x509->raw_cert + offset,
	       current_x509->raw_cert_size - offset);
	*avail_datalen -= current_x509->raw_cert_size - offset;

out:
	return ret;
}

/*
 * Save the certificate list
 */
int pkcs7_note_certificate_list_enc(void *context, uint8_t *data,
				    size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

int pkcs7_note_content_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/*
 * Set the content type.
 */
int pkcs7_data_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
		       uint8_t *tag)
{
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	int ret;

	(void)context;
	(void)tag;

	CKINT(OID_to_data(OID_data, &oid_data, &oid_datalen));
	bin2print_debug(oid_data, oid_datalen, stdout, "OID pkcs7 Data");

	if (oid_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

/*
 * Extract the data from the message and store that and its content type OID in
 * the context.
 */
int pkcs7_note_data_enc(void *context, uint8_t *data, size_t *avail_datalen,
			uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_message *pkcs7 = ctx->pkcs7;
	int ret;

	(void)tag;

	/*
	 * When having no data, then the caller requested detached signatures
	 * and the PKCS7 bundle will not have any protected data at all.
	 */
	if (!pkcs7->data)
		return 0;

	CKINT(x509_sufficient_size(avail_datalen, pkcs7->data_len));

	memcpy(data, pkcs7->data, pkcs7->data_len);
	*avail_datalen -= pkcs7->data_len;
	bin2print_debug(pkcs7->data, pkcs7->data_len, stdout, "Set data");

out:
	return ret;
}

static inline int
pkcs7_authenticated_attr_unprocessed(const struct pkcs7_generate_context *ctx,
				     unsigned long check_aa)
{
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	unsigned long aa = sinfo->aa_set & ~ctx->aa_set_applied;

	if (aa & check_aa)
		return 1;
	return 0;
}

int pkcs7_external_aa_continue_enc(void *context, uint8_t *data,
				   size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	if (ctx->aa_set_applied != sinfo->aa_set)
		return LC_ASN1_RET_CONTINUE;

	return 0;
}

int pkcs7_external_aa_OID_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	int ret = 0;

	(void)tag;

	if (sinfo->aa_set &&
	    !(ctx->aa_set_applied & sinfo_has_message_digest)) {
		CKINT(OID_to_data(OID_messageDigest, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout,
				"OID message digest");
	} else if (pkcs7_authenticated_attr_unprocessed(
			   ctx, sinfo_has_content_type)) {
		CKINT(OID_to_data(OID_contentType, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID data type");
	} else if (pkcs7_authenticated_attr_unprocessed(
			   ctx, sinfo_has_signing_time)) {
		CKINT(OID_to_data(OID_signingTime, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout,
				"OID signing time");
	} else if (pkcs7_authenticated_attr_unprocessed(ctx,
							sinfo_has_smime_caps)) {
		CKINT(OID_to_data(OID_smimeCapabilites, &oid_data,
				  &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout,
				"OID smime capabilities");
	} else if (pkcs7_authenticated_attr_unprocessed(
			   ctx, sinfo_has_ms_opus_info)) {
		CKINT(OID_to_data(OID_msSpOpusInfo, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID ms opus");
	} else if (pkcs7_authenticated_attr_unprocessed(
			   ctx, sinfo_has_ms_statement_type)) {
		CKINT(OID_to_data(OID_msStatementType, &oid_data,
				  &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout,
				"OID ms statement type");
	}

	if (oid_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

static int pkcs7_set_time(uint8_t *data, size_t *avail_datalen, uint8_t *tag)
{
	/* UCTTime: YYMMDDHHMMSSZ */
#define X509_UCTTIM_SIZE 13
	/* GenTime: YYYYMMDDHHMMSSZ */
#define X509_GENTIM_SIZE 15
	/*
	 * Add 2 trailing bytes to shut up the stupid compiler check that cannot
	 * detect the modulo operation.
	 */
	char datestr[X509_GENTIM_SIZE + 2];
	struct tm *time_detail;
	time_t timeval = time(NULL);
	int ret;

	if (timeval == (time_t)-1)
		return -EFAULT;

	/* UTC time */
	time_detail = gmtime(&timeval);

	/*
	 * The value is the time since EPOCH for 2050-01-01
	 *
	 * Use `date -d "2050-01-01" -u "+%s"` to verify
	 *
	 * UCTTIM is only applicable for times before 2050
	 */
	if (timeval >= 2524608000) {
		CKINT(x509_sufficient_size(avail_datalen, X509_GENTIM_SIZE));
		snprintf(datestr, sizeof(datestr), "%.4d%.2d%.2d%.2d%.2d%.2dZ",
			 time_detail->tm_year + 1900, time_detail->tm_mon + 1,
			 time_detail->tm_mday, time_detail->tm_hour,
			 time_detail->tm_min, time_detail->tm_sec);

		memcpy(data, datestr, X509_GENTIM_SIZE);
		*avail_datalen -= X509_GENTIM_SIZE;
		*tag = ASN1_GENTIM;
	} else {
		CKINT(x509_sufficient_size(avail_datalen, X509_UCTTIM_SIZE));
		snprintf(datestr, sizeof(datestr), "%02d%02d%02d%02d%02d%02dZ",
			 time_detail->tm_year % 100, time_detail->tm_mon + 1,
			 time_detail->tm_mday, time_detail->tm_hour,
			 time_detail->tm_min, time_detail->tm_sec);

		memcpy(data, datestr, X509_UCTTIM_SIZE);
		*avail_datalen -= X509_UCTTIM_SIZE;
		*tag = ASN1_UNITIM;
	}

	printf_debug("Set certificate time %s\n", datestr);

out:
	return ret;
}

static int pkcs7_hash_data(uint8_t *digest, size_t *digest_size,
			   const struct lc_hash *hash_algo,
			   const struct lc_pkcs7_message *pkcs7)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, hash_algo);

	/* Digest the message [RFC5652 5.4] */
	lc_hash_init(hash_ctx);
	*digest_size = lc_hash_digestsize(hash_ctx);

	lc_hash_update(hash_ctx, pkcs7->data, pkcs7->data_len);
	lc_hash_final(hash_ctx, digest);
	lc_hash_zero(hash_ctx);

	return 0;
}

/*
 * Parse authenticated attributes.
 */
int pkcs7_external_aa_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_message *pkcs7 = ctx->pkcs7;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	uint8_t digest[LC_SHA_MAX_SIZE_DIGEST];
	size_t digest_size = 0;
	int ret = 0;

	(void)tag;

	/*
	 * If an AA set is present, we must force the message digest attribute.
	 * See RFC5652 section 5.3.
	 */
	if (sinfo->aa_set &&
	    !(ctx->aa_set_applied & sinfo_has_message_digest)) {
		const struct lc_hash *hash_algo;

		ctx->aa_set_applied |= sinfo_has_message_digest;

		*tag = ASN1_OTS;

		CKINT(pkcs7_get_digest(&hash_algo, sinfo));
		CKINT(pkcs7_hash_data(digest, &digest_size, hash_algo, pkcs7));
		bin2print_debug(digest, digest_size, stdout,
				"Generated messageDigest");

		CKINT(x509_sufficient_size(avail_datalen, digest_size));
		memcpy(data, digest, digest_size);
		*avail_datalen -= digest_size;
	} else if (pkcs7_authenticated_attr_unprocessed(
			   ctx, sinfo_has_content_type)) {
		const uint8_t *oid_data = NULL;
		size_t oid_datalen = 0;

		ctx->aa_set_applied |= sinfo_has_content_type;

		CKINT(OID_to_data(pkcs7->data_type, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID data type");

		if (oid_datalen) {
			CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

			memcpy(data, oid_data, oid_datalen);
			*avail_datalen -= oid_datalen;
		}
	} else if (pkcs7_authenticated_attr_unprocessed(
			   ctx, sinfo_has_signing_time)) {
		ctx->aa_set_applied |= sinfo_has_signing_time;
		CKINT(pkcs7_set_time(data, avail_datalen, tag));
	} else if (pkcs7_authenticated_attr_unprocessed(ctx,
							sinfo_has_smime_caps)) {
		ctx->aa_set_applied |= sinfo_has_smime_caps;
		return -EOPNOTSUPP;
	} else if (pkcs7_authenticated_attr_unprocessed(
			   ctx, sinfo_has_ms_opus_info)) {
		ctx->aa_set_applied |= sinfo_has_ms_opus_info;
		return -EOPNOTSUPP;
	} else if (pkcs7_authenticated_attr_unprocessed(
			   ctx, sinfo_has_ms_statement_type)) {
		ctx->aa_set_applied |= sinfo_has_ms_statement_type;
		return -EOPNOTSUPP;
	}

out:
	lc_memset_secure(digest, 0, digest_size);
	return ret;
}

int pkcs7_note_attribute_type_OID_enc(void *context, uint8_t *data,
				      size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const struct lc_x509_certificate *x509 = sinfo->signer;
	const struct lc_x509_certificate_name *name = &x509->subject_segments;
	uint8_t processed = ctx->subject_attrib_processed;

	(void)tag;

	if (x509->raw_skid)
		return 0;

	return x509_name_OID_enc(name, processed, data, avail_datalen);
}

int pkcs7_extract_attribute_name_segment_enc(void *context, uint8_t *data,
					     size_t *avail_datalen,
					     uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const struct lc_x509_certificate *x509 = sinfo->signer;
	const struct lc_x509_certificate_name *name = &x509->subject_segments;
	uint8_t *processed = &ctx->subject_attrib_processed;

	(void)tag;

	if (x509->raw_skid)
		return 0;

	return x509_name_segment_enc(name, processed, data, avail_datalen);
}

int pkcs7_attribute_value_continue_enc(void *context, uint8_t *data,
				       size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const struct lc_x509_certificate *x509 = sinfo->signer;
	const struct lc_x509_certificate_name *name = &x509->subject_segments;
	uint8_t processed = ctx->subject_attrib_processed;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	if (x509->raw_skid)
		return 0;

	return x509_name_unprocessed(name, processed);
}

/*
 * Spawn a separate parser to generate the authenticated attribute entry.
 * As this entire buffer must be hashed, this is the only way to get to the
 * buffer short of re-parsing the entire message again.
 */
int pkcs7_sig_note_set_of_authattrs_enc(void *context, uint8_t *data,
					size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	uint8_t aa[500], *aap = aa, len;
	size_t aalen = sizeof(aa);
	int ret;
	LC_HASH_CTX_ON_STACK(hash_ctx, ctx->authattr_hash);

	(void)tag;

	/* No authenticated attributes are requested to be generated */
	if (!sinfo->aa_set)
		return 0;

	/* Encode the authenticated attributes */
	CKINT(asn1_ber_encoder(&pkcs7_aa_encoder, ctx, aa, &aalen));
	aalen = sizeof(aa) - aalen;

	if (!(sinfo->aa_set & sinfo_has_content_type) ||
	    !(sinfo->aa_set & sinfo_has_message_digest)) {
		printf_debug("Missing required AuthAttr\n");
		return -EBADMSG;
	}

	if (ctx->pkcs7->data_type != OID_msIndirectData &&
	    (sinfo->aa_set & sinfo_has_ms_opus_info)) {
		printf_debug("Unexpected Authenticode AuthAttr\n");
		return -EBADMSG;
	}

	lc_hash_init(hash_ctx);
	ctx->authattrs_digest_size = lc_hash_digestsize(hash_ctx);

	aa[0] = ASN1_CONS_BIT | ASN1_SET;
	lc_hash_update(hash_ctx, aap, aalen);
	lc_hash_final(hash_ctx, ctx->authattrs_digest);
	lc_hash_zero(hash_ctx);
	bin2print_debug(ctx->authattrs_digest, ctx->authattrs_digest_size,
			stdout, "Generated signerInfos AADigest");

	/*
	 * The following code throws away the outer tag and message size which
	 * is added by this specific parser.
	 */
	/* Consume the tag */
	aap++;
	aalen--;

	/* Consume the length field */
	len = *aap;
	aap++;
	aalen--;

	/* Check if we have an extended length field and consume it */
	if (len > 0x7f) {
		if (len == ASN1_INDEFINITE_LENGTH)
			return -EINVAL;

		len -= 0x80;
		if (len > 2)
			return -EINVAL;
		aap += len;
		aalen -= len;
	}

	/* Copy the final message into the buffer */
	CKINT(x509_sufficient_size(avail_datalen, aalen));
	memcpy(data, aap, aalen);
	*avail_datalen -= aalen;

out:
	return ret;
}

/*
 * Note the issuing certificate serial number
 */
int pkcs7_sig_note_serial_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const struct lc_x509_certificate *x509 = sinfo->signer;
	int ret = 0;

	(void)tag;

	if (x509->raw_skid)
		return 0;

	CKINT(x509_sufficient_size(avail_datalen, x509->raw_serial_size));

	memcpy(data, x509->raw_serial, x509->raw_serial_size);
	*avail_datalen -= x509->raw_serial_size;
	bin2print_debug(x509->raw_serial, x509->raw_serial_size, stdout,
			"Serial");

out:
	return ret;
}

int pkcs7_sig_note_issuer_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

int pkcs7_sig_note_authenticated_attr_enc(void *context, uint8_t *data,
					  size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/*
 * Note the issuer's name
 */
int pkcs7_authenticated_attr_OID_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/*
 * Note the issuing cert's subjectKeyIdentifier
 */
int pkcs7_sig_note_skid_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const struct lc_x509_certificate *x509 = sinfo->signer;
	int ret;

	(void)tag;

	if (!x509->raw_skid)
		return 0;

	CKINT(x509_sufficient_size(avail_datalen, x509->raw_skid_size));

	memcpy(data, x509->raw_skid, x509->raw_skid_size);
	*avail_datalen -= x509->raw_skid_size;
	bin2print_debug(x509->raw_skid, x509->raw_skid_size, stdout, "SKID");

out:
	return ret;
}

/*
 * Note the signature data
 */
int pkcs7_sig_note_signature_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	struct lc_public_key_signature sig = { 0 };
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_message *pkcs7 = ctx->pkcs7;
	const struct lc_pkcs7_signed_info *sinfo = ctx->current_sinfo;
	const struct lc_x509_certificate *x509 = sinfo->signer;
	const struct lc_x509_generate_data *sig_gen_data = &x509->sig_gen_data;
	int ret;

	(void)tag;

	/* Require that a signer is set */
	if (!sig_gen_data->sig_type)
		return -EINVAL;

	CKINT(pkcs7_get_digest(&sig.hash_algo, sinfo));

	/*
	 * If a hash algorithm is present, apply it by generating the digest
	 * over the message. This implies we have a pre-hashed signature.
	 *
	 * If no digest algorithm is present, we have a regular signature.
	 * However, this can only work if there is no authenticated attribute
	 * present, because if it is present, it must bear the OID_messageDigest
	 * of the actual data and then only the authenticated attributes is
	 * signed. Therefore, with the authenticated attributes present we must
	 * have a digest algorithm.
	 */
	if (sig.hash_algo) {
		if (!ctx->authattrs_digest_size)
			return -EINVAL;
		memcpy(sig.digest, ctx->authattrs_digest,
		       ctx->authattrs_digest_size);
		sig.digest_size = ctx->authattrs_digest_size;
	} else {
		if (ctx->authattrs_digest_size)
			return -EINVAL;

		sig.raw_data = pkcs7->data;
		sig.raw_data_len = pkcs7->data_len;
	}

	CKINT(public_key_generate_signature(sig_gen_data, &sig, data,
					    avail_datalen));

out:
	lc_memset_secure(&sig, 0, sizeof(sig));
	return 0;
}

/*
 * Report if we have more signer infos
 */
int pkcs7_note_signed_info_enc(void *context, uint8_t *data,
			       size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generate_context *ctx = context;
	const struct lc_pkcs7_signed_info *current_sinfo = ctx->current_sinfo;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	if (!current_sinfo)
		return 0;

	/* Iterate to the next certificate */
	ctx->current_sinfo = current_sinfo->next;

	/* Clear out the authenticated attributes setting */
	ctx->aa_set_applied = 0;
	current_sinfo = ctx->current_sinfo;
	if (!current_sinfo)
		return 0;

	return LC_ASN1_RET_CONTINUE;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

static inline int pkcs7_initialize_ctx(struct pkcs7_generate_context *ctx,
				       const struct lc_pkcs7_message *pkcs7)
{
	int ret = 0;

	CKNULL(pkcs7->certs, -EINVAL);
	CKNULL(pkcs7->signed_infos, -EINVAL);

	ctx->pkcs7 = pkcs7;
	ctx->current_x509 = pkcs7->certs;
	ctx->current_sinfo = pkcs7->signed_infos;

	CKINT(pkcs7_get_digest(&ctx->authattr_hash, ctx->current_sinfo));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_generate,
		      const struct lc_pkcs7_message *pkcs7, uint8_t *data,
		      size_t *avail_datalen)
{
	struct pkcs7_generate_context ctx = { 0 };
	int ret;

	CKNULL(pkcs7, -EINVAL);
	CKNULL(data, -EINVAL);
	CKNULL(avail_datalen, -EINVAL);

	CKNULL_LOG(
		pkcs7->data, -EINVAL,
		"Encapsulated data missing - perhaps you want to use the detached signature API?\n");

	CKINT(pkcs7_initialize_ctx(&ctx, pkcs7));

	/* Attempt to decode the signature */
	CKINT(asn1_ber_encoder(&pkcs7_encoder, &ctx, data, avail_datalen));

out:
	return ret;
}
