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
 *   certificates you want to provide with --addcert, have one DER or PEM
 *   formatted certificate per file, but supply each file with a separate
 *   --addcert option.
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

#include <getopt.h>

#include "asn1.h"
#include "authenticode_SpcIndirectDataContent_asn1.h"
#include "authenticode_SpcPeImageData_asn1.h"
#include "image.h"
#include "lc_hash.h"
#include "lc_memory_support.h"
#include "lc_pkcs7_generator_helper.h"
#include "lc_status.h"
#include "lc_x509_generator.h"
#include "lc_x509_generator_file_helper.h"
#include "ret_checkers.h"
#include "small_stack_support.h"

static const char *toolname = "sbsign";

static struct option options[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "cert", required_argument, NULL, 'c' },
	{ "key", required_argument, NULL, 'k' },
	{ "detached", no_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "engine", required_argument, NULL, 'e' },
	{ "addcert", required_argument, NULL, 'a' },
	{ NULL, 0, NULL, 0 },
};

static void usage(void)
{
	printf("Usage: %s [options] --key <keyfile> --cert <certfile> "
	       "<efi-boot-image>\n"
	       "Sign an EFI boot image for use with secure boot.\n\n"
	       "Options:\n"
	       "\t--engine <eng>     [compatibility argument - unused]\n"
	       "\t--key <keyfile>    signing key (PEM or DER encoded"
	       "private key)\n"
	       "\t--cert <certfile>  certificate (x509 certificate)\n"
	       "\t--addcert <addcertfile> additional intermediate certificates in a file\n"
	       "\t--detached         write a detached signature, instead of\n"
	       "\t                    a signed binary\n"
	       "\t--output <file>    write signed data to <file>\n"
	       "\t                    (default <efi-boot-image>.signed,\n"
	       "\t                    or <efi-boot-image>.pk7 for detached\n"
	       "\t                    signatures)\n",
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

static int set_default_outfilename(struct pkcs7_generator_opts *opts,
				   char **outfile)
{
	const char *extension;
	size_t len;
	int ret;

	if (opts->infile_flags == lc_pkcs7_set_data_embed) {
		extension = "signed";
		len = 7;
	} else {
		extension = "pk7";
		len = 3;
	}

	/* Add filename, a dot and the trailing NULL */
	len += strlen(opts->infile) + 1 + 1;
	CKINT(lc_alloc_aligned((void **)outfile, sizeof(uint64_t), len));
	snprintf(*outfile, len, "%s.%s", opts->infile, extension);
	opts->outfile = *outfile;
	outfile = NULL;

out:
	return ret;
}

int lc_spc_attribute_type_OID_enc(void *context, uint8_t *data,
				  size_t *avail_datalen, uint8_t *tag)
{
	/* SPC_PE_IMAGE_DATAOBJ OID (1.3.6.1.4.1.311.2.1.15) */
	static const uint8_t spc_indirect_data_objid[] = {
		0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x1, 0xf,
	};
	int ret;

	(void)context;
	(void)tag;

	CKINT(lc_x509_sufficient_size(avail_datalen,
				      sizeof(spc_indirect_data_objid)));

	memcpy(data, spc_indirect_data_objid, sizeof(spc_indirect_data_objid));
	*avail_datalen -= sizeof(spc_indirect_data_objid);

out:
	return ret;
}

int lc_spc_filename_obsolete_enc(void *context, uint8_t *data,
				 size_t *avail_datalen, uint8_t *tag)
{
	static const uint8_t obsolete[] = { 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c,
					    0x00, 0x4f, 0x00, 0x62, 0x00, 0x73,
					    0x00, 0x6f, 0x00, 0x6c, 0x00, 0x65,
					    0x00, 0x74, 0x00, 0x65, 0x00, 0x3e,
					    0x00, 0x3e, 0x00, 0x3e };
	int ret;

	(void)context;
	(void)tag;

	CKINT(lc_x509_sufficient_size(avail_datalen, sizeof(obsolete)));

	memcpy(data, obsolete, sizeof(obsolete));
	*avail_datalen -= sizeof(obsolete);

out:
	return ret;
}

int lc_spc_pe_image_data_enc(void *context, uint8_t *data,
			     size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generator_opts *opts = context;
	size_t avail = *avail_datalen;
	int ret;

	(void)tag;

	/* Set SpcPeImageData */
	CKINT(lc_asn1_ber_encoder_small(&lc_authenticode_SpcPeImageData_encoder,
					opts, data, &avail));

	*avail_datalen = avail;

out:
	return ret;
}

int lc_spc_digest_algorithm_OID_enc(void *context, uint8_t *data,
				    size_t *avail_datalen, uint8_t *tag)
{
	struct pkcs7_generator_opts *opts = context;
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	enum OID oid;
	int ret;

	(void)tag;

	/*
	 * RFC5652 section 5.1 explicitly allows setting no entries here.
	 * This is applied with the return code of 2.
	 */
	if (!opts->hash)
		return LC_ASN1_RET_SET_ZERO_CONTENT;

	/*
	 * "Windows Authenticode Portable Executable Signature Format":
	 * "This field specifies the digest algorithm that is used to hash the
	 * file. The value must match the digestAlgorithm value specified in
	 * SignerInfo and the parent PKCS #7 digestAlgorithms fields."
	 */
	CKINT(lc_x509_hash_to_oid(opts->hash, &oid));
	CKINT(lc_OID_to_data(oid, &oid_data, &oid_datalen));
	bin2print_debug(oid_data, oid_datalen, stdout,
			"OID signed hash algorithm");

	if (oid_datalen) {
		CKINT(lc_x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

int lc_spc_file_digest_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	struct pkcs7_generator_opts *opts = context;
	int ret;

	(void)tag;

	CKNULL(opts->aux_data, -ENODATA);

	CKINT(lc_x509_sufficient_size(avail_datalen, opts->aux_datalen));

	memcpy(data, opts->aux_data, opts->aux_datalen);
	*avail_datalen -= opts->aux_datalen;

out:
	return ret;
}

#include "binhexbin.h"
static int pkcs7_gen_message_sbsign(struct pkcs7_generator_opts *opts)
{
	static const uint8_t spc_indirect_data_objid[] = {
		0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x1, 0x4,
	};
//	static const uint8_t spc_sp_opus_info_objid[] = {
//		0x2b, 0x6, 0x1, 0x4, 0x1, 0x82, 0x37, 0x2, 0x1, 0xc,
//	};
#define LC_AUTHENTICODE_SPC_INDIRECT_DATA_CONTENT_SIZE 256
	struct workspace {
		struct image image;
		struct pkcs7_generate_context ctx;
		uint8_t authenticode_SpcIndirectDataContent
			[LC_AUTHENTICODE_SPC_INDIRECT_DATA_CONTENT_SIZE];
		uint8_t data[ASN1_MAX_DATASIZE];
		uint8_t image_digest[LC_SHA_MAX_SIZE_DIGEST];
	};
	struct lc_pkcs7_message *pkcs7 = opts->pkcs7;
	uint8_t *image_buf = NULL;
	const char *outfile_p;
	char *outfile = NULL;
	size_t image_size = 0;
	size_t avail_datalen = ASN1_MAX_DATASIZE, datalen;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (!opts->outfile) {
		CKINT(set_default_outfilename(opts, &outfile));
		outfile_p = outfile;
	} else {
		outfile_p = opts->outfile;
	}

	CKINT(get_data_memory(opts->infile, &image_buf, &image_size,
			      lc_pem_flag_nopem));

	/* Parse image */
	CKINT(image_load(image_buf, image_size, &ws->image));
	/* Calculating the PE Image Hash */
	CKINT(image_hash(&ws->image, opts->hash, ws->image_digest,
			 &opts->aux_datalen));
	opts->aux_data = ws->image_digest;
	bin2print(ws->image_digest, opts->aux_datalen, stdout, "digest");

	/*
	 * As defined in the "Windows Authenticode Portable Executable Signature
	 * Format" The content must be set to SpcIndirectDataContent
	 */
	avail_datalen = LC_AUTHENTICODE_SPC_INDIRECT_DATA_CONTENT_SIZE;
	CKINT(lc_asn1_ber_encoder(
		&lc_authenticode_SpcIndirectDataContent_encoder, opts,
		ws->authenticode_SpcIndirectDataContent, &avail_datalen));
	datalen =
		LC_AUTHENTICODE_SPC_INDIRECT_DATA_CONTENT_SIZE - avail_datalen;

	CKINT(lc_pkcs7_encode_ctx_init(&ws->ctx));

	/*
	 * Set and embed the SpcIndirectDataContent into the PKCS#7 message.
	 */
	CKINT(lc_pkcs7_set_data(pkcs7, ws->authenticode_SpcIndirectDataContent,
				datalen, lc_pkcs7_set_data_embed));
	CKINT(lc_pkcs7_encode_ctx_set_pkcs7(&ws->ctx, pkcs7));

	/*
	 * As defined in the "Windows Authenticode Portable Executable Signature
	 * Format" The contentType must be set to
	 * SPC_INDIRECT_DATA_OBJID (1.3.6.1.4.1.311.2.1.4).
	 */
	CKINT(lc_pkcs7_encode_ctx_set_signed_data_content_type(
		&ws->ctx, spc_indirect_data_objid,
		sizeof(spc_indirect_data_objid)));

	/*
	 * As defined in the "Windows Authenticode Portable Executable Signature
	 * Format" The following additional authenticated attribute must be set:
	 * SPC_SP_OPUS_INFO_OBJID (1.3.6.1.4.1.311.2.1.12).
	 */
	// CKINT(lc_pkcs7_encode_ctx_set_additional_aa(
	// 	&ws->ctx, spc_sp_opus_info_objid,
	// 	sizeof(spc_sp_opus_info_objid),
	// ));

	avail_datalen = ASN1_MAX_DATASIZE;
	CKINT_LOG(lc_pkcs7_encode_ctx(&ws->ctx, ws->data, &avail_datalen),
		  "Message generation failed\n");
	datalen = ASN1_MAX_DATASIZE - avail_datalen;

	CKINT(image_add_signature(&ws->image, ws->data, datalen));
	if (opts->infile_flags == lc_pkcs7_set_data_embed) {
		image_write(&ws->image, outfile_p);
	} else {
		int i;
		uint8_t *buf;
		size_t len;

		for (i = 0; !image_get_signature(&ws->image, i, &buf, &len);
		     i++)
			;
		CKINT(image_write_detached(&ws->image, i - 1, outfile_p));
	}

out:
	if (outfile)
		lc_free(outfile);
	if (ws->image.buf != image_buf)
		free((uint8_t *)ws->image.buf);
	release_data_memory(image_buf, image_size, lc_pem_flag_nopem);
	image_release(&ws->image);
	LC_RELEASE_MEM(ws);
	return ret;
}

int main(int argc, char **argv)
{
	PKCS7_ALLOC
	struct workspace {
		struct pkcs7_generator_opts parsed_opts;
	};
	int ret, c;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	ws->parsed_opts.infile_flags = lc_pkcs7_set_data_embed;
	/*
	 * This tool defaults to SHA2-512. The original sbsign tool uses
	 * SHA2-256. However, The security strength of SHA2-256 is 128 bits and
	 * thus too low for ML-DSA65 or 87. Considering that all PQC algos
	 * require the presence of Keccak, using SHA3 makes more sense - it
	 * would not artifically require to add the presence of SHA2-512 support
	 * to the library. But then, NIAP with their, well, statement in CNSA
	 * 2.0 to not allow SHA3 would be violated. Thus, we leave SHA2-512 here
	 * for now.
	 *
	 * Furthermore, RFC9882 section 3.3 suggests the use of SHA2-512 as a
	 * default.
	 */
	ws->parsed_opts.hash = lc_sha512;
	ws->parsed_opts.pkcs7 = pkcs7_msg;

	/* To comply with RFC9882, we use authenticated attributes. */
	ws->parsed_opts.aa_set = sinfo_has_content_type |
				 sinfo_has_signing_time |
				 sinfo_has_message_digest;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "o:c:k:dvVhe:a:", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			CKINT(pkcs7_check_file(optarg));
			ws->parsed_opts.outfile = optarg;
			break;
		case 'c':
			ws->parsed_opts.x509_signer_file = optarg;
			CKINT(pkcs7_collect_signer(&ws->parsed_opts));
			break;
		case 'k':
			ws->parsed_opts.signer_sk_file = optarg;
			CKINT(pkcs7_collect_signer(&ws->parsed_opts));
			break;
		case 'd':
			ws->parsed_opts.infile_flags = lc_pkcs7_set_data_noflag;
			break;
		case 'v':
			printf("Verbose option ignored\n");
			break;
		case 'V':
			version();
			ret = 0;
			goto out;
		case 'h':
			usage();
			ret = 0;
			goto out;
		case 'e':
			printf("Engine option ignored\n");
			break;
		case 'a':
			ws->parsed_opts.x509_file = optarg;
			CKINT(pkcs7_collect_x509(&ws->parsed_opts));
			break;
		}
	}

	if (argc != optind + 1) {
		usage();
		ret = -EINVAL;
		goto out;
	}

	ws->parsed_opts.infile = argv[optind];

	CKINT(pkcs7_gen_message_sbsign(&ws->parsed_opts));

out:
	pkcs7_clean_opts(&ws->parsed_opts);
	LC_RELEASE_MEM(ws);
	PKCS7_FREE
	return -ret;
}
