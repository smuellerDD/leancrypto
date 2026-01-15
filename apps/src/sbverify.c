/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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
/*
 * This implementation is intended to provide a drop-in replacement for the
 * sbsign tool from
 * http://git.kernel.org/pub/scm/linux/kernel/git/jejb/sbsigntools.git.
 *
 * The following differences exist though:
 *
 * - Unlike OpenSSL, leancrypto's certificate parsing only supports one
 *   certificate per PEM file (OpenSSL supports multiple PEM-formatted
 *   certificate blobs in one file). Thus, if you have multiple additional
 *   certificates you want to provide with --cert, have one DER or PEM
 *   formatted certificate per file, but supply each file with a separate
 *   --cert option.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <getopt.h>

#include "authenticode_SpcIndirectDataContent_asn1.h"
#include "image.h"
#include "lc_memcmp_secure.h"
#include "lc_pkcs7_generator_helper.h"
#include "lc_status.h"
#include "lc_x509_generator_file_helper.h"
#include "math_helper.h"
#include "ret_checkers.h"
#include "small_stack_support.h"

struct lc_sbverify_ctx {
	const struct lc_hash *hash;
	const uint8_t *decoded_image_digest;
	size_t decoded_image_digestlen;
};

static const char *toolname = "sbverify";

static const struct option options[] = {
	{ "cert", required_argument, NULL, 'c' },
	{ "list", no_argument, NULL, 'l' },
	{ "detached", required_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options] --cert <certfile> <efi-boot-image>\n"
	       "Verify a UEFI secure boot image.\n\n"
	       "Options:\n"
	       "\t--cert <certfile>  certificate (x509 certificate)\n"
	       "\t--list             list all signatures (but don't verify)\n"
	       "\t--detached <file>  read signature from <file>, instead of\n"
	       "\t                    looking for an embedded signature\n",
	       toolname);
}

static void version(void)
{
	char version[500];

	memset(version, 0, sizeof(version));
	lc_status(version, sizeof(version));

	fprintf(stderr, "Leancrypto %s\n", toolname);
	fprintf(stderr, "%s\n", version);
}

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

	printf("%s ", prefix);
	i = 0;
	print_x509_name_component(&i, "C = ", &name->c);
	print_x509_name_component(&i, "ST = ", &name->st);
	print_x509_name_component(&i, "O = ", &name->o);
	print_x509_name_component(&i, "OU = ", &name->ou);
	print_x509_name_component(&i, "CN = ", &name->cn);
	print_x509_name_component(&i, "Email = ", &name->email);
	printf("\n");
}

static int print_signature_info(const struct pkcs7_generator_opts *parsed_opts)
{
	const struct lc_pkcs7_message *pkcs7_msg = parsed_opts->pkcs7;
	const struct lc_x509_certificate *cert = pkcs7_msg->certs;
	const struct lc_pkcs7_signed_info *sinfos = pkcs7_msg->list_head_sinfo;

	printf("image signature issuers:\n");
	while (sinfos) {
		/* Print signer */
		if (sinfos->signer)
			print_x509_name(" -", &cert->issuer_segments);
		else
			printf("--- NO SIGNER PRESENT ---\n");
		sinfos = sinfos->next;
	}

	printf("image signature certificates:\n");
	while (cert) {
		print_x509_name(" - subject: ", &cert->subject_segments);
		print_x509_name("   issuer:  ", &cert->issuer_segments);

		cert = cert->next;
	}

	return 0;
}

static int
print_certificate_store_certs(const struct pkcs7_generator_opts *parsed_opts)
{
	const struct lc_pkcs7_trust_store *trust_store =
		&parsed_opts->trust_store;
	const struct lc_x509_certificate *cert = trust_store->anchor_cert;

	printf("certificate store:\n");

	while (cert) {
		print_x509_name(" - subject: ", &cert->subject_segments);
		print_x509_name("   issuer:  ", &cert->issuer_segments);

		cert = cert->next;
	}

	return 0;
}

int lc_spc_attribute_type_OID(void *context, size_t hdrlen, unsigned char tag,
			      const uint8_t *value, size_t vlen)
{
	/* SPC_PE_IMAGE_DATAOBJ OID (1.3.6.1.4.1.311.2.1.15) */
	static const uint8_t spc_indirect_data_objid[] = {
		0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x1, 0xf,
	};

	(void)context;
	(void)hdrlen;
	(void)tag;

	if (lc_memcmp_secure(value, vlen, spc_indirect_data_objid,
			     sizeof(spc_indirect_data_objid)))
		return -EINVAL;

	return 0;
}

int lc_spc_pe_image_data(void *context, size_t hdrlen, unsigned char tag,
			 const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	/*
	 * We are not decoding lc_authenticode_SpcPeImageData_encoder
	 */
	return 0;
}

int lc_spc_digest_algorithm_OID(void *context, size_t hdrlen, unsigned char tag,
				const uint8_t *value, size_t vlen)
{
	struct lc_sbverify_ctx *authenticode_ctx = context;
	enum OID oid;
	int ret;

	(void)hdrlen;
	(void)tag;

	oid = lc_look_up_OID(value, vlen);
	if (oid == OID__NR) {
		bin2print_debug(value, vlen, stdout, "PKCS7: Unknown OID\n");
		return -EINVAL;
	}

	CKINT(lc_x509_oid_to_hash(oid, &authenticode_ctx->hash));

out:
	return ret;
}

int lc_spc_file_digest(void *context, size_t hdrlen, unsigned char tag,
		       const uint8_t *value, size_t vlen)
{
	struct lc_sbverify_ctx *authenticode_ctx = context;

	(void)hdrlen;
	(void)tag;

	authenticode_ctx->decoded_image_digest = value;
	authenticode_ctx->decoded_image_digestlen = vlen;

	return 0;
}

static int sbverify_dump_file(struct pkcs7_generator_opts *opts, int verbose)
{
//	static const uint8_t spc_sp_opus_info_objid[] = {
//		0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x1, 0xc,
//	};
#define LC_AUTHENTICODE_SPC_INDIRECT_DATA_CONTENT_SIZE 256
	struct workspace {
		struct image image;
		struct lc_pkcs7_parse_context ctx;
		struct lc_sbverify_ctx authenticode_ctx;
		uint8_t image_digest[LC_SHA_MAX_SIZE_DIGEST];
	};
	struct lc_pkcs7_message *pkcs7 = opts->pkcs7;
	const uint8_t *avail_data;
	uint8_t *image_buf = NULL, *detached_sig_buf = NULL, *signature;
	size_t image_size = 0, detached_sig_buflen = 0, signaturelen,
	       avail_datalen;
	unsigned int signum = 0;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(get_data(opts->infile, &image_buf, &image_size,
		       lc_pem_flag_nopem));

	/* Parse image */
	CKINT(image_load(image_buf, image_size, &ws->image));

	for (;;) {
		if (opts->pkcs7_msg) {
			if (signum > 0)
				break;

			CKINT(get_data(opts->infile, &detached_sig_buf,
				       &detached_sig_buflen,
				       lc_pem_flag_nopem));

			signature = detached_sig_buf;
			signaturelen = detached_sig_buflen;
		} else {
			ret = image_get_signature(&ws->image, signum,
						  &signature, &signaturelen);
			if (ret) {
				if (signum > 0) {
					ret = 0;
					break;
				} else {
					fprintf(stderr,
						"Unable to read signature data from %s\n",
						opts->infile);
					ret = -EINVAL;
					goto out;
				}
			}
		}

		if (verbose || opts->print_pkcs7)
			printf("signature %d\n", signum);

		CKINT(lc_pkcs7_decode_ctx_init(&ws->ctx));

		CKINT(lc_pkcs7_decode_ctx_set_pkcs7(&ws->ctx, pkcs7));

		CKINT(lc_pkcs7_decode_ctx_set_aa_content_type(
			&ws->ctx, OID_msIndirectData));

		CKINT_LOG(lc_pkcs7_decode_ctx(&ws->ctx, signature,
					      signaturelen),
			  "Unable to parse signature data\n");

		/*
		 * Now, if we have data with the PKCS7 message, attempt to verify it
		 * (i.e. perform a signature verification).
		 */
		CKINT(lc_pkcs7_get_content_data(opts->pkcs7, &avail_data,
						&avail_datalen));
		CKINT_LOG(lc_pkcs7_verify(
				  opts->pkcs7,
				  opts->use_trust_store ? &opts->trust_store :
							  NULL,
				  opts->verify_rules_set ? &opts->verify_rules :
							   NULL),
			  "Unable to verify signature\n");

		/* Attempt to decode the signature */
		CKINT(lc_asn1_ber_decoder(
			&lc_authenticode_SpcIndirectDataContent_decoder,
			&ws->authenticode_ctx, avail_data, avail_datalen));

		/* Calculating the PE Image Hash */
		CKINT(image_hash(&ws->image, ws->authenticode_ctx.hash,
				 ws->image_digest, &opts->aux_datalen));

		if (lc_memcmp_secure(
			    ws->image_digest, opts->aux_datalen,
			    ws->authenticode_ctx.decoded_image_digest,
			    ws->authenticode_ctx.decoded_image_digestlen)) {
			fprintf(stderr, "Image fails hash check\n");
			ret = -EBADMSG;
			goto out;
		}

		if (verbose || opts->print_pkcs7) {
			CKINT(print_signature_info(opts));
			if (verbose > 1)
				CKINT(print_certificate_store_certs(opts));
		}

		signum++;
	}

out:
	if (ws->image.buf != image_buf)
		free((uint8_t *)ws->image.buf);
	release_data(image_buf, image_size, lc_pem_flag_nopem);
	release_data(detached_sig_buf, detached_sig_buflen, lc_pem_flag_nopem);
	image_release(&ws->image);
	LC_RELEASE_MEM(ws);
	return ret;
}

int main(int argc, char **argv)
{
	PKCS7_ALLOC
	struct pkcs7_generator_opts parsed_opts = { 0 };
	int ret, c, verbose = 0;

	parsed_opts.infile_flags = lc_pkcs7_set_data_embed;
	parsed_opts.pkcs7 = pkcs7_msg;

	/* Should that be turned into an option? */
	parsed_opts.aa_set = sinfo_has_content_type | sinfo_has_signing_time |
			     sinfo_has_message_digest;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "c:d:lvVh", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			parsed_opts.trust_anchor = optarg;
			CKINT(pkcs7_collect_trust(&parsed_opts));
			break;
		case 'd':
			parsed_opts.infile_flags = lc_pkcs7_set_data_noflag;
			parsed_opts.pkcs7_msg = optarg;
			break;
		case 'l':
			parsed_opts.print_pkcs7 = 1;
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			version();
			ret = 0;
			goto out;
		case 'h':
			usage();
			ret = 0;
			goto out;
		}
	}

	if (argc != optind + 1) {
		usage();
		ret = -EINVAL;
		goto out;
	}

	parsed_opts.infile = argv[optind];

	if (parsed_opts.infile)
		CKINT(pkcs7_set_data(&parsed_opts));

	CKINT(sbverify_dump_file(&parsed_opts, verbose));

out:
	pkcs7_clean_opts(&parsed_opts);
	PKCS7_FREE
	return -ret;
}
