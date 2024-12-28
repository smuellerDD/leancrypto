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
#include "asn1_encoder.h"
#include "asym_key_dilithium.h"
#include "asym_key_dilithium_ed25519.h"
#include "asym_key_sphincs.h"
#include "conv_be_le.h"
#include "helper.h"
#include "lc_dilithium.h"
#include "lc_sphincs.h"
#include "lc_sha256.h"
#include "lc_sha512.h"
#include "lc_sha3.h"
#include "lc_x509_generator.h"
#include "math_helper.h"
#include "oid_registry.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"
#include "x509_algorithm_mapper.h"
#include "x509_cert_generator.h"
#include "x509_cert_parser.h"

#include "x509.asn1.h"
#include "x509_akid.asn1.h"
#include "x509_basic_constraints.asn1.h"
#include "x509_eku.asn1.h"
#include "x509_keyusage.asn1.h"
#include "x509_san.asn1.h"
#include "x509_skid.asn1.h"

int x509_set_bit_string(uint8_t *dst_data, size_t *dst_avail_datalen,
			const uint8_t *src_data, size_t src_datalen)
{
	int ret;

	/* Account for the BIT prefix */
	if (src_datalen)
		src_datalen += 1;

	CKINT(x509_sufficient_size(dst_avail_datalen, src_datalen));

	/* Set the BIT STRING metadata */
	if (src_datalen) {
		dst_data[0] = 0;
		memcpy(dst_data + 1, src_data, src_datalen - 1);
		*dst_avail_datalen -= src_datalen;
	}

out:
	return ret;
}

/******************************************************************************
 * Extensions
 ******************************************************************************/

static inline int x509_eku_unprocessed(struct x509_generate_context *ctx,
				       uint16_t check_eku)
{
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key *pub = &cert->pub;
	uint16_t key_eku = pub->key_eku & ~ctx->key_eku_processed;

	if (key_eku & check_eku)
		return 1;
	return 0;
}

int x509_eku_enc(void *context, uint8_t *data, size_t *avail_datalen,
		 uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const uint8_t *oid_data;
	size_t oid_datalen;
	int ret;

	(void)tag;

	if (x509_eku_unprocessed(ctx, LC_KEY_EKU_ANY)) {
		ctx->key_eku_processed |= LC_KEY_EKU_ANY;
		CKINT(OID_to_data(OID_anyExtendedKeyUsage, &oid_data,
				  &oid_datalen));
	} else if (x509_eku_unprocessed(ctx, LC_KEY_EKU_SERVER_AUTH)) {
		ctx->key_eku_processed |= LC_KEY_EKU_SERVER_AUTH;
		CKINT(OID_to_data(OID_id_kp_serverAuth, &oid_data,
				  &oid_datalen));
	} else if (x509_eku_unprocessed(ctx, LC_KEY_EKU_CLIENT_AUTH)) {
		ctx->key_eku_processed |= LC_KEY_EKU_CLIENT_AUTH;
		CKINT(OID_to_data(OID_id_kp_clientAuth, &oid_data,
				  &oid_datalen));
	} else if (x509_eku_unprocessed(ctx, LC_KEY_EKU_CODE_SIGNING)) {
		ctx->key_eku_processed |= LC_KEY_EKU_CODE_SIGNING;
		CKINT(OID_to_data(OID_id_kp_codeSigning, &oid_data,
				  &oid_datalen));
	} else if (x509_eku_unprocessed(ctx, LC_KEY_EKU_EMAIL_PROTECTION)) {
		ctx->key_eku_processed |= LC_KEY_EKU_EMAIL_PROTECTION;
		CKINT(OID_to_data(OID_id_kp_emailProtection, &oid_data,
				  &oid_datalen));
	} else if (x509_eku_unprocessed(ctx, LC_KEY_EKU_TIME_STAMPING)) {
		ctx->key_eku_processed |= LC_KEY_EKU_TIME_STAMPING;
		CKINT(OID_to_data(OID_id_kp_timeStamping, &oid_data,
				  &oid_datalen));
	} else if (x509_eku_unprocessed(ctx, LC_KEY_EKU_OCSP_SIGNING)) {
		ctx->key_eku_processed |= LC_KEY_EKU_OCSP_SIGNING;
		CKINT(OID_to_data(OID_id_kp_OCSPSigning, &oid_data,
				  &oid_datalen));
	} else {
		return -EINVAL;
	}

	bin2print_debug(oid_data, oid_datalen, stdout, "OID");

	CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

	memcpy(data, oid_data, oid_datalen);
	*avail_datalen -= oid_datalen;

out:
	return ret;
}

static inline int x509_pathlen_unprocessed(struct x509_generate_context *ctx)
{
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key *pub = &cert->pub;
	uint8_t pathlen = pub->ca_pathlen & (uint8_t)~LC_KEY_CA_CRITICAL;

	if (pathlen != ctx->pathlen_processed)
		return 1;
	return 0;
}

/*
 * Set the basic constraints CA field
 */
int x509_basic_constraints_ca_enc(void *context, uint8_t *data,
				  size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key *pub = &cert->pub;

	(void)tag;

	if (x509_pathlen_unprocessed(ctx)) {
		if (*avail_datalen < 1)
			return -EOVERFLOW;

		if (pub->ca_pathlen & (uint8_t)~LC_KEY_CA_CRITICAL)
			*data = ASN1_TRUE;
		else
			*data = ASN1_FALSE;

		*avail_datalen -= 1;

		ctx->pathlen_processed = LC_KEY_CA_MAXLEN;

		printf_debug("Setting CA: %u\n", *data);
	}

	return 0;
}

/*
 * Extract the basic constraints pathlen
 */
int x509_basic_constraints_pathlen_enc(void *context, uint8_t *data,
				       size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key *pub = &cert->pub;

	(void)tag;

	if (x509_pathlen_unprocessed(ctx)) {
		if (*avail_datalen < 1)
			return -EOVERFLOW;

		*data = pub->ca_pathlen & (uint8_t)~LC_KEY_CA_CRITICAL;
		*avail_datalen -= 1;

		ctx->pathlen_processed = *data;
	}

	return 0;
}

int x509_name_unprocessed(const struct lc_x509_certificate_name *name,
			  uint8_t processed)
{
	if (name->c.size && !(processed & X509_C_PROCESSED))
		return 1;
	if (name->cn.size && !(processed & X509_CN_PROCESSED))
		return 1;
	if (name->o.size && !(processed & X509_O_PROCESSED))
		return 1;
	if (name->email.size && !(processed & X509_EMAIL_PROCESSED))
		return 1;
	if (name->st.size && !(processed & X509_ST_PROCESSED))
		return 1;
	if (name->ou.size && !(processed & X509_OU_PROCESSED))
		return 1;

	return 0;
}

int x509_name_OID_enc(const struct lc_x509_certificate_name *name,
		      uint8_t processed, uint8_t *data, size_t *avail_datalen)
{
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	int ret = 0;

	/*
	 * Note, the order of entries MUST match the order in
	 * x509_name_segment_enc
	 */
	if (name->c.size && !(processed & X509_C_PROCESSED)) {
		CKINT(OID_to_data(OID_countryName, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID C");
	} else if (name->st.size && !(processed & X509_ST_PROCESSED)) {
		CKINT(OID_to_data(OID_stateOrProvinceName, &oid_data,
				  &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID ST");
	} else if (name->o.size && !(processed & X509_O_PROCESSED)) {
		CKINT(OID_to_data(OID_organizationName, &oid_data,
				  &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID O");
	} else if (name->ou.size && !(processed & X509_OU_PROCESSED)) {
		CKINT(OID_to_data(OID_organizationUnitName, &oid_data,
				  &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID OU");
	} else if (name->cn.size && !(processed & X509_CN_PROCESSED)) {
		CKINT(OID_to_data(OID_commonName, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID CN");
	} else if (name->email.size && !(processed & X509_EMAIL_PROCESSED)) {
		CKINT(OID_to_data(OID_email_address, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID Email");
	}

	if (oid_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

int x509_san_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
		     uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;

	(void)tag;

	return x509_name_OID_enc(&cert->san_directory_name_segments,
				 ctx->san_processed, data, avail_datalen);
}

int x509_name_segment_enc(const struct lc_x509_certificate_name *name,
			  uint8_t *processed, uint8_t *data,
			  size_t *avail_datalen)
{
	const char *name_data = NULL;
	size_t name_datalen = 0;
	int ret = 0;

	printf_debug("Set name component");

	/*
	 * Note, the order of entries MUST match the order in
	 * x509_name_OID_enc
	 */
	if (name->c.size && !(*processed & X509_C_PROCESSED)) {
		name_data = name->c.value;
		name_datalen = name->c.size;
		*processed |= X509_C_PROCESSED;
		printf_debug(" C ");
	} else if (name->st.size && !(*processed & X509_ST_PROCESSED)) {
		name_data = name->st.value;
		name_datalen = name->st.size;
		*processed |= X509_ST_PROCESSED;
		printf_debug(" ST ");
	} else if (name->o.size && !(*processed & X509_O_PROCESSED)) {
		name_data = name->o.value;
		name_datalen = name->o.size;
		*processed |= X509_O_PROCESSED;
		printf_debug(" O ");
	} else if (name->ou.size && !(*processed & X509_OU_PROCESSED)) {
		name_data = name->ou.value;
		name_datalen = name->ou.size;
		*processed |= X509_OU_PROCESSED;
		printf_debug(" OU ");
	} else if (name->cn.size && !(*processed & X509_CN_PROCESSED)) {
		name_data = name->cn.value;
		name_datalen = name->cn.size;
		*processed |= X509_CN_PROCESSED;
		printf_debug(" CN ");
	} else if (name->email.size && !(*processed & X509_EMAIL_PROCESSED)) {
		name_data = name->email.value;
		name_datalen = name->email.size;
		*processed |= X509_EMAIL_PROCESSED;
		printf_debug(" Email ");
	}

	if (name_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, name_datalen));

		memcpy(data, name_data, name_datalen);
		*avail_datalen -= name_datalen;
	}

	if (name_data) {
		char buf[128] __maybe_unused;

		name_datalen = min_size(name_datalen, sizeof(buf) - 1);
		memcpy(buf, name_data, name_datalen);
		buf[name_datalen] = '\0';

		printf_debug("%s", buf);
	}
	printf_debug("\n");

out:
	return ret;
}

int x509_extract_name_segment_enc(void *context, uint8_t *data,
				  size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;

	*tag = ASN1_UTF8STR;

	return x509_name_segment_enc(&cert->san_directory_name_segments,
				     &ctx->san_processed, data, avail_datalen);
}

static int x509_san_unprocessed(struct x509_generate_context *ctx)
{
	const struct lc_x509_certificate *cert = ctx->cert;

	if (cert->san_dns_len && !(ctx->san_processed & X509_SAN_DNS_PROCESSED))
		return 1;
	if (cert->san_ip_len && !(ctx->san_processed & X509_SAN_IP_PROCESSED))
		return 1;
	return x509_name_unprocessed(&cert->san_directory_name_segments,
				     ctx->san_processed);
}

/*
 * Set the subject alternative name - DNS parameter
 */
int x509_san_dns_enc(void *context, uint8_t *data, size_t *avail_datalen,
		     uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;

	(void)tag;

	if (cert->san_dns_len &&
	    !(ctx->san_processed & X509_SAN_DNS_PROCESSED)) {
		if (*avail_datalen < cert->san_dns_len)
			return -EOVERFLOW;

		memcpy(data, cert->san_dns, cert->san_dns_len);
		*avail_datalen -= cert->san_dns_len;

		ctx->san_processed |= X509_SAN_DNS_PROCESSED;
	}

	return 0;
}

/*
 * Set the subject alternative name - IP parameter
 */
int x509_san_ip_enc(void *context, uint8_t *data, size_t *avail_datalen,
		    uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;

	(void)tag;

	if (cert->san_ip_len && !(ctx->san_processed & X509_SAN_IP_PROCESSED)) {
		if (*avail_datalen < cert->san_ip_len)
			return -EOVERFLOW;

		memcpy(data, cert->san_ip, cert->san_ip_len);
		*avail_datalen -= cert->san_ip_len;

		ctx->san_processed |= X509_SAN_IP_PROCESSED;
	}

	return 0;
}

static inline int x509_keyusage_unprocessed(struct x509_generate_context *ctx,
					    uint16_t check_keyusage)
{
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key *pub = &cert->pub;
	uint16_t key_usage = pub->key_usage & ~ctx->key_usage_processed;

	if (key_usage & check_keyusage)
		return 1;
	return 0;
}

/*
 * Set the key usage
 */
int x509_keyusage_enc(void *context, uint8_t *data, size_t *avail_datalen,
		      uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key *pub = &cert->pub;
	uint16_t key_usage = pub->key_usage & LC_KEY_USAGE_MASK;
	int ret;

	(void)tag;

	CKINT(x509_sufficient_size(avail_datalen, sizeof(key_usage)));

	/*
	 * BIT STRING is handled as a big-endian value which implies that we
	 * need to convert it here.
	 */
	key_usage = be_bswap16(key_usage);

	memcpy(data, (uint8_t *)&key_usage, sizeof(key_usage));
	*avail_datalen -= sizeof(key_usage);

	ctx->key_usage_processed = pub->key_usage;

out:
	return ret;
}

static inline int x509_skid_unprocessed(struct x509_generate_context *ctx)
{
	if (ctx->skid_processed)
		return 0;
	return 1;
}

/*
 * Set the subject key ID
 */
int x509_skid_enc(void *context, uint8_t *data, size_t *avail_datalen,
		  uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	int ret;

	(void)tag;

	if (cert->raw_skid_size) {
		CKINT(x509_sufficient_size(avail_datalen, cert->raw_skid_size));

		memcpy(data, cert->raw_skid, cert->raw_skid_size);
		*avail_datalen -= cert->raw_skid_size;
		bin2print_debug(cert->raw_skid, cert->raw_skid_size, stdout,
				"SKID");
	} else {
		const struct lc_x509_key_data *gendata = &cert->pub_gen_data;

		CKINT(x509_sufficient_size(avail_datalen,
					   sizeof(gendata->pk_digest)));
		memcpy(data, gendata->pk_digest, sizeof(gendata->pk_digest));
		*avail_datalen -= sizeof(gendata->pk_digest);
		bin2print_debug(gendata->pk_digest, sizeof(gendata->pk_digest),
				stdout, "SKID");
	}

	ctx->skid_processed = 1;

out:
	return ret;
}

static inline int x509_akid_unprocessed(struct x509_generate_context *ctx)
{
	const struct lc_x509_certificate *cert = ctx->cert;

	if (cert->raw_akid_size && !ctx->akid_processed)
		return 1;
	if (ctx->akid_raw_issuer_size && !ctx->akid_serial_processed)
		return 1;
	return 0;
}

/*
 * Note a key identifier-based AuthorityKeyIdentifier
 */
int x509_akid_note_kid_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	int ret;

	(void)tag;

	CKINT(x509_sufficient_size(avail_datalen, cert->raw_akid_size));

	memcpy(data, cert->raw_akid, cert->raw_akid_size);
	*avail_datalen -= cert->raw_akid_size;
	bin2print_debug(cert->raw_akid, cert->raw_akid_size, stdout, "AKID");

	ctx->akid_processed = 1;

out:
	return ret;
}

/*
 * Note a directoryName in an AuthorityKeyIdentifier
 */
int x509_akid_note_name_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;

	return 0;
}

/*
 * Note a serial number in an AuthorityKeyIdentifier
 */
int x509_akid_note_serial_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	int ret;

	(void)tag;

	//TODO ctx->akid_raw_issuer is not accessible from the API
	CKINT(x509_sufficient_size(avail_datalen, ctx->akid_raw_issuer_size));

	memcpy(data, ctx->akid_raw_issuer, ctx->akid_raw_issuer_size);
	*avail_datalen -= ctx->akid_raw_issuer_size;
	bin2print_debug(ctx->akid_raw_issuer, ctx->akid_raw_issuer_size, stdout,
			"AKID (issuer)");

	ctx->akid_serial_processed = 1;

out:
	return ret;
}

int x509_akid_note_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

/******************************************************************************
 * Common extension code base
 ******************************************************************************/

int x509_extension_continue_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	if (x509_eku_unprocessed(ctx, LC_KEY_EKU_MASK))
		return LC_ASN1_RET_CONTINUE;
	else if (x509_pathlen_unprocessed(ctx))
		return LC_ASN1_RET_CONTINUE;
	else if (x509_san_unprocessed(ctx))
		return LC_ASN1_RET_CONTINUE;
	else if (x509_keyusage_unprocessed(ctx, LC_KEY_USAGE_MASK))
		return LC_ASN1_RET_CONTINUE;
	else if (x509_skid_unprocessed(ctx))
		return LC_ASN1_RET_CONTINUE;
	else if (x509_akid_unprocessed(ctx))
		return LC_ASN1_RET_CONTINUE;

	return 0;
}

int x509_extension_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	int ret = 0;

	(void)tag;

	if (x509_eku_unprocessed(ctx, LC_KEY_EKU_MASK)) {
		CKINT(OID_to_data(OID_extKeyUsage, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID EKU");
	} else if (x509_pathlen_unprocessed(ctx)) {
		CKINT(OID_to_data(OID_basicConstraints, &oid_data,
				  &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID BC");
	} else if (x509_san_unprocessed(ctx)) {
		CKINT(OID_to_data(OID_subjectAltName, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID SAN");
	} else if (x509_keyusage_unprocessed(ctx, LC_KEY_USAGE_MASK)) {
		CKINT(OID_to_data(OID_keyUsage, &oid_data, &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID Key Usage");
	} else if (x509_skid_unprocessed(ctx)) {
		CKINT(OID_to_data(OID_subjectKeyIdentifier, &oid_data,
				  &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID SKID");
	} else if (x509_akid_unprocessed(ctx)) {
		CKINT(OID_to_data(OID_authorityKeyIdentifier, &oid_data,
				  &oid_datalen));
		bin2print_debug(oid_data, oid_datalen, stdout, "OID AKID");
	}

	if (oid_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

int x509_extension_critical_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key *pub = &cert->pub;
#define X509_EXTENSION_UNSET 0xffffffff
	unsigned int val = X509_EXTENSION_UNSET;

	(void)tag;

	if (x509_eku_unprocessed(ctx, LC_KEY_EKU_MASK)) {
		val = pub->key_eku & LC_KEY_EKU_CRITICAL;
	} else if (x509_pathlen_unprocessed(ctx)) {
		val = pub->ca_pathlen & LC_KEY_CA_CRITICAL;
	} else if (x509_san_unprocessed(ctx)) {
		return 0; /* SAN does not have criticality */
	} else if (x509_keyusage_unprocessed(ctx, LC_KEY_USAGE_MASK)) {
		val = pub->key_usage & LC_KEY_USAGE_CRITICAL;
	} else if (x509_skid_unprocessed(ctx)) {
		return 0; /* SKID does not have criticality */
	} else if (x509_akid_unprocessed(ctx)) {
		return 0; /* SKID does not have criticality */
	}

	/* No value was set */
	if (val == X509_EXTENSION_UNSET)
		return 0;

	if (*avail_datalen < 1)
		return -EOVERFLOW;

	if (val)
		*data = ASN1_TRUE;
	else
		*data = ASN1_FALSE;

	*avail_datalen -= 1;

	return 0;
}

int x509_process_extension_enc(void *context, uint8_t *data,
			       size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	size_t avail = *avail_datalen;
	int ret = 0;

	(void)tag;

	/*
	 * NOTE: all extension generating callbacks MUST have the same order of
	 * processing the input data.
	 */

	/* extended key usage */
	if (x509_eku_unprocessed(ctx, LC_KEY_EKU_MASK)) {
		CKINT(asn1_ber_encoder_small(&x509_eku_encoder, ctx, data,
					     &avail));

		/* basic constraints */
	} else if (x509_pathlen_unprocessed(ctx)) {
		CKINT(asn1_ber_encoder_small(&x509_basic_constraints_encoder,
					     ctx, data, &avail));

		/* subject alternative name */
	} else if (x509_san_unprocessed(ctx)) {
		CKINT(asn1_ber_encoder(&x509_san_encoder, ctx, data, &avail));

		/* key usage */
	} else if (x509_keyusage_unprocessed(ctx, LC_KEY_USAGE_MASK)) {
		CKINT(asn1_ber_encoder_small(&x509_keyusage_encoder, ctx, data,
					     &avail));

		/* SKID */
	} else if (x509_skid_unprocessed(ctx)) {
		CKINT(asn1_ber_encoder_small(&x509_skid_encoder, ctx, data,
					     &avail));

		/* authority key identifier */
	} else if (x509_akid_unprocessed(ctx)) {
		CKINT(asn1_ber_encoder(&x509_akid_encoder, ctx, data, &avail));
	}

	*avail_datalen = avail;

out:
	return ret;
}

/******************************************************************************
 * Regular callbacks
 ******************************************************************************/

/*
 * Save the position of the TBS data so that we can check the signature over it
 * later.
 */
int x509_note_tbs_certificate_enc(void *context, uint8_t *data,
				  size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;

	return 0;
}

int x509_signature_algorithm_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;

	return 0;
}

int x509_note_algorithm_OID_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key_signature *sig = &cert->sig;
	enum lc_sig_types pkey_algo = sig->pkey_algo;
	const uint8_t *oid_data = NULL;
	enum OID oid;
	size_t oid_datalen = 0;
	int ret = 0;

	(void)tag;

	ctx->sig_algo_set++;

	if (ctx->sig_algo_set == sig_algo_pubkey) {
		const struct lc_public_key *pkey = &cert->pub;

		pkey_algo = pkey->pkey_algo;
	}

	CKINT(lc_x509_sig_type_to_oid(pkey_algo, &oid));
	CKINT(OID_to_data(oid, &oid_data, &oid_datalen));
	bin2print_debug(oid_data, oid_datalen, stdout,
			lc_x509_sig_type_to_name(pkey_algo));

	if (oid_datalen) {
		CKINT(x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

int x509_signature_reserve_room(uint8_t *data, size_t *avail_datalen,
				size_t siglen)
{
	size_t datalen = 0;
	int ret;

	if (siglen)
		datalen = siglen + 1;

	CKINT(x509_sufficient_size(avail_datalen, datalen));

	/* Set the BIT STRING metadata */
	if (datalen) {
		data[0] = 0;
		lc_memset_secure(data + 1, 0xff, siglen);
		*avail_datalen -= datalen;
	}

	printf_debug("Set signature length %zu\n", siglen);

out:
	return ret;
}

/*
 * Calculate the signature
 */
int x509_note_signature_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_public_key_signature *sig = &cert->sig;
	size_t siglen = 0;
	int ret;

	(void)tag;

	/* Get the signature length */
	CKINT(public_key_signature_size(&siglen, sig->pkey_algo));

	CKINT(x509_signature_reserve_room(data, avail_datalen, siglen));

out:
	return ret;
}

/*
 * Note the certificate serial number
 */
int x509_note_serial_enc(void *context, uint8_t *data, size_t *avail_datalen,
			 uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	int ret = 0;

	(void)tag;

	CKINT(x509_sufficient_size(avail_datalen, cert->raw_serial_size));

	memcpy(data, cert->raw_serial, cert->raw_serial_size);
	*avail_datalen -= cert->raw_serial_size;
	bin2print_debug(cert->raw_serial, cert->raw_serial_size, stdout,
			"Serial");

out:
	return ret;
}

int x509_note_sig_algo_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

int x509_note_issuer_enc(void *context, uint8_t *data, size_t *avail_datalen,
			 uint8_t *tag)
{
	struct x509_generate_context *ctx = context;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	/* issuer set, now point to subject */
	ctx->subject_attribute_processing = 1;
	ctx->issuer_attribute_processing = 0;

	return 0;
}

int x509_note_subject_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	struct x509_generate_context *ctx = context;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	ctx->subject_attribute_processing = 0;
	ctx->issuer_attribute_processing = 0;

	return 0;
}

int x509_note_params_enc(void *context, uint8_t *data, size_t *avail_datalen,
			 uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;
	return 0;
}

static int x509_attribute_value_unprocessed(struct x509_generate_context *ctx)
{
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_x509_certificate_name *name = &cert->issuer_segments;
	uint8_t processed = ctx->issuer_attrib_processed;

	if (ctx->subject_attribute_processing) {
		name = &cert->subject_segments;
		processed = ctx->subject_attrib_processed;
	}

	return x509_name_unprocessed(name, processed);
}

/*
 * Note some of the name segments from which we'll fabricate a name.
 */
int x509_extract_attribute_name_segment_enc(void *context, uint8_t *data,
					    size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_x509_certificate_name *name = &cert->issuer_segments;
	uint8_t *processed = &ctx->issuer_attrib_processed;

	*tag = ASN1_UTF8STR;

	if (ctx->subject_attribute_processing) {
		name = &cert->subject_segments;
		processed = &ctx->subject_attrib_processed;
	}

	return x509_name_segment_enc(name, processed, data, avail_datalen);
}

int x509_note_attribute_type_OID_enc(void *context, uint8_t *data,
				     size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	const struct lc_x509_certificate_name *name = &cert->issuer_segments;
	uint8_t processed = ctx->issuer_attrib_processed;

	(void)tag;

	if (ctx->subject_attribute_processing) {
		name = &cert->subject_segments;
		processed = ctx->subject_attrib_processed;
	}

	return x509_name_OID_enc(name, processed, data, avail_datalen);
}

int x509_attribute_value_continue_enc(void *context, uint8_t *data,
				      size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	if (x509_attribute_value_unprocessed(ctx))
		return LC_ASN1_RET_CONTINUE;

	return 0;
}

int x509_set_uct_time_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	/* UCTTime: YYMMDDHHMMSSZ */
#define X509_UCTTIM_SIZE 13
	/*
	 * Add 2 trailing bytes to shut up the stupid compiler check that cannot
	 * detect the modulo operation.
	 */
	char datestr[X509_UCTTIM_SIZE + 2];
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	struct tm *time_detail;
	time64_t tmp_time;
	int ret;

	(void)tag;

	/* Ensure that only one time is set at one round */
	if (ctx->time_already_set)
		return 0;

	CKINT(x509_sufficient_size(avail_datalen, X509_UCTTIM_SIZE));

	/* First the start time is set, then the end time */
	tmp_time = ctx->time_to_set;
	if (!ctx->time_to_set)
		ctx->time_to_set = cert->valid_from;
	else
		ctx->time_to_set = cert->valid_to;

	/*
	 * The value is the time since EPOCH for 2050-01-01
	 *
	 * Use `date -d "2050-01-01" -u "+%s"` to verify
	 *
	 * UCTTIM is only applicable for times before 2050
	 */
	if (ctx->time_to_set >= 2524608000) {
		ctx->time_to_set = tmp_time;
		return 0;
	}

	/*
	 * NOTE: The caller is assumed to have set the time in UTC time.
	 */
	time_detail = gmtime((time_t *)&ctx->time_to_set);
	snprintf(datestr, sizeof(datestr), "%02d%02d%02d%02d%02d%02dZ",
		 time_detail->tm_year % 100, time_detail->tm_mon + 1,
		 time_detail->tm_mday, time_detail->tm_hour,
		 time_detail->tm_min, time_detail->tm_sec);

	memcpy(data, datestr, X509_UCTTIM_SIZE);
	*avail_datalen -= X509_UCTTIM_SIZE;

	ctx->time_already_set = 1;
	printf_debug("Set certificate time %s\n", datestr);

out:
	return ret;
}

int x509_set_gen_time_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	/* GenTime: YYYYMMDDHHMMSSZ */
#define X509_GENTIM_SIZE 15
	char datestr[X509_GENTIM_SIZE + 1];
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;
	struct tm *time_detail;
	time64_t tmp_time;
	int ret;

	(void)tag;

	/* Ensure that only one time is set at one round */
	if (ctx->time_already_set)
		return 0;

	CKINT(x509_sufficient_size(avail_datalen, X509_GENTIM_SIZE));

	/* First the start time is set, then the end time */
	tmp_time = ctx->time_to_set;
	if (!ctx->time_to_set)
		ctx->time_to_set = cert->valid_from;
	else
		ctx->time_to_set = cert->valid_to;

	/*
	 * The value is the time since EPOCH for 2050-01-01
	 *
	 * Use `date -d "2050-01-01" -u "+%s"` to verify
	 *
	 * GENTIM is only applicable for times beyond 2050
	 */
	if (ctx->time_to_set < 2524608000) {
		ctx->time_to_set = tmp_time;
		return 0;
	}

	/*
	 * NOTE: The caller is assumed to have set the time in UTC time.
	 */
	time_detail = gmtime((time_t *)&ctx->time_to_set);
	snprintf(datestr, sizeof(datestr), "%.4d%.2d%.2d%.2d%.2d%.2dZ",
		 time_detail->tm_year + 1900, time_detail->tm_mon + 1,
		 time_detail->tm_mday, time_detail->tm_hour,
		 time_detail->tm_min, time_detail->tm_sec);

	memcpy(data, datestr, X509_GENTIM_SIZE);
	*avail_datalen -= X509_GENTIM_SIZE;

	ctx->time_already_set = 1;
	printf_debug("Set certificate time %s\n", datestr);

out:
	return ret;
}

/*
 * Process the time the certificate becomes valid
 */
int x509_note_not_before_enc(void *context, uint8_t *data,
			     size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	/* Sanity check */
	if (ctx->time_to_set != cert->valid_from) {
		printf_debug("Parser error: validity not before wrong\n");
		return -EFAULT;
	}

	/* Now, reset the flag to allow for the next round */
	ctx->time_already_set = 0;

	return 0;
}

/*
 * Process the time when the certificate becomes invalid
 */
int x509_note_not_after_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	const struct lc_x509_certificate *cert = ctx->cert;

	(void)data;
	(void)avail_datalen;
	(void)tag;

	/* Sanity check */
	if (ctx->time_to_set != cert->valid_to) {
		printf_debug("Parser error: validity not after wrong\n");
		return -EFAULT;
	}

	/* Now, reset the flag to allow for the next round */
	ctx->time_already_set = 0;

	return 0;
}

int x509_extract_key_data_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	struct x509_generate_context *ctx = context;
	size_t orig = *avail_datalen;
	int ret;

	(void)tag;

	/* Account for the BIT STRING prefix */
	CKINT(x509_sufficient_size(avail_datalen, 1));
	data[0] = 0;
	data++;
	*avail_datalen -= 1;

	CKINT(public_key_extract(ctx, data, avail_datalen));

	(void)orig;
	printf_debug("Set public key of size %zu\n", orig - *avail_datalen);

out:
	return ret;
}

int x509_version_enc(void *context, uint8_t *data, size_t *avail_datalen,
		     uint8_t *tag)
{
	/*
	 * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
	 *
	 * We set the version hard-coded to version 3, as usually the
	 * certificates contain extensions.
	 */
	static const uint8_t x509_version = 0x02;
	int ret;

	(void)context;
	(void)tag;

	CKINT(x509_sufficient_size(avail_datalen, 1));
	data[0] = x509_version;
	*avail_datalen -= 1;
	printf_debug("Set X.509 version to %u\n", x509_version);

out:
	return ret;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_x509_cert_encode,
		      const struct lc_x509_certificate *x509, uint8_t *data,
		      size_t *avail_datalen)
{
	struct workspace {
		struct x509_generate_context gctx;
		struct x509_parse_context pctx;
		struct lc_x509_certificate parsed_x509;
	};
	size_t datalen = *avail_datalen;
	uint8_t *sigdstptr;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKNULL(x509, -EINVAL);
	CKNULL(data, -EINVAL);

	ws->gctx.cert = x509;

	/*
	 * Attempt to encode the certificate
	 */
	CKINT(asn1_ber_encoder(&x509_encoder, &ws->gctx, data, avail_datalen));

	datalen -= *avail_datalen;

	/*
	 * Parse the encoded signature to detect the TBSCertificate
	 */
	ws->pctx.cert = &ws->parsed_x509;
	ws->pctx.data = data;
	CKINT(asn1_ber_decoder(&x509_decoder, &ws->pctx, data, datalen));

	/*
	 * Grab the signature bits
	 */
	CKINT(x509_get_sig_params(&ws->parsed_x509));

	/*
	 * Copy the signature to its destination
	 * We can unconstify the raw_sig pointer here, because we know the
	 * data buffer is in the just parsed data.
	 */
	sigdstptr = (uint8_t *)ws->parsed_x509.raw_sig;

	/*
	 * Generate the signature over the TBSCertificate and place it
	 * into the signature location of the certificate.
	 */
	CKINT(public_key_generate_signature(&x509->sig_gen_data,
					    &ws->parsed_x509.sig, sigdstptr,
					    &ws->parsed_x509.raw_sig_size));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_sk_encode,
		      const struct lc_x509_key_data *keys, uint8_t *data,
		      size_t *avail_datalen)
{
	struct x509_generate_privkey_context ctx = { 0 };
	int ret = 0;

	CKNULL(keys, -EINVAL);
	CKNULL(data, -EINVAL);

	ctx.keys = keys;

	CKINT(privkey_key_encode(&ctx, data, avail_datalen));

out:
	lc_memset_secure(&ctx, 0, sizeof(ctx));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_get_signature_size_from_sk, size_t *siglen,
		      const struct lc_x509_key_data *keys)
{
	if (!siglen || !keys)
		return -EINVAL;
	return public_key_signature_size(siglen, keys->sig_type);
}

LC_INTERFACE_FUNCTION(int, lc_x509_get_signature_size_from_cert, size_t *siglen,
		      const struct lc_x509_certificate *cert)
{
	const struct lc_public_key *pub;

	if (!siglen || !cert)
		return -EINVAL;

	pub = &cert->pub;
	return public_key_signature_size(siglen, pub->pkey_algo);
}

LC_INTERFACE_FUNCTION(int, lc_x509_signature_gen, uint8_t *sig_data,
		      size_t *siglen, const struct lc_x509_key_data *keys,
		      const uint8_t *m, size_t mlen,
		      const struct lc_hash *prehash_algo)
{
	struct lc_public_key_signature sig = { 0 };
	size_t available_siglen = *siglen;
	int ret = 0;

	CKNULL(keys, -EINVAL);
	CKNULL(sig_data, -EINVAL);
	CKNULL(m, -EINVAL);

	if (prehash_algo) {
		if (mlen > LC_SHA_MAX_SIZE_DIGEST)
			return -EOVERFLOW;

		memcpy(sig.digest, m, mlen);
		sig.digest_size = mlen;
		sig.hash_algo = prehash_algo;
		sig.request_prehash = 1;
	} else {
		sig.raw_data = m;
		sig.raw_data_len = mlen;
	}

	CKINT(public_key_generate_signature(keys, &sig, sig_data,
					    &available_siglen));

	*siglen -= available_siglen;

out:
	lc_memset_secure(&sig, 0, sizeof(sig));
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_x509_cert_set_signer,
		      struct lc_x509_certificate *signed_x509,
		      const struct lc_x509_key_data *signer_key_data,
		      const struct lc_x509_certificate *signer_x509)
{
	return asym_set_signer(signed_x509, signer_key_data, signer_x509);
}

LC_INTERFACE_FUNCTION(int, lc_x509_keypair_gen,
		      struct lc_x509_certificate *cert,
		      struct lc_x509_key_data *keys,
		      enum lc_sig_types create_keypair_algo)
{
	return asym_keypair_gen(cert, keys, create_keypair_algo);
}

LC_INTERFACE_FUNCTION(int, lc_x509_keypair_load,
		      struct lc_x509_certificate *cert,
		      const struct lc_x509_key_data *keys,
		      enum lc_sig_types keypair_algo)
{
	return asym_keypair_load(cert, keys, keypair_algo);
}
