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

#include "lc_status.h"
#include "lc_pkcs7_generator_helper.h"
#include "lc_x509_generator_file_helper.h"
#include "math_helper.h"
#include "ret_checkers.h"

static const char *toolname = "sbverify";

static struct option options[] = {
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

static int sbverify_dump_file(struct pkcs7_generator_opts *opts, int verbose)
{
	const uint8_t *avail_data;
	uint8_t *pkcs7_data = NULL;
	size_t pkcs7_datalen = 0, avail_datalen;
	int ret;

	if (!opts->pkcs7_msg && !opts->checker)
		return 0;

	CKINT_LOG(get_data(opts->pkcs7_msg, &pkcs7_data, &pkcs7_datalen,
			   lc_pem_flag_cms),
		  "Loading of file %s failed\n", opts->pkcs7_msg);

	CKINT_LOG(lc_pkcs7_decode(opts->pkcs7, pkcs7_data, pkcs7_datalen),
		  "Parsing of input file %s failed\n", opts->pkcs7_msg);

	/*
	 * If caller provided data, set it - if data is found in the CMS
	 * structure, the following call will error out.
	 */
	if (opts->data) {
		CKINT(lc_pkcs7_set_data(opts->pkcs7, opts->data, opts->datalen,
					0));
	}

	/*
	 * Now, if we have data with the PKCS7 message, attempt to verify it
	 * (i.e. perform a signature verification).
	 */
	ret = lc_pkcs7_get_content_data(opts->pkcs7, &avail_data,
					&avail_datalen);
	if (!ret) {
		ret = lc_pkcs7_verify(
			opts->pkcs7,
			opts->use_trust_store ? &opts->trust_store : NULL,
			opts->verify_rules_set ? &opts->verify_rules : NULL);
	} else {
		printf("Verification of PKCS#7 message skipped\n");
	}

	if (verbose || opts->print_pkcs7) {
		CKINT(print_signature_info(opts));
		if (verbose > 1)
			CKINT(print_certificate_store_certs(opts));
	}

	/*
	 * Mimic the original sbverify tool and not print out the signature
	 * verification result when listing information.
	 */
	if (opts->print_pkcs7) {
		ret = 0;
		goto out;
	}

	if (ret)
		printf("Signature verification failed\n");
	else
		printf("Signature verification OK\n");

out:
	release_data(pkcs7_data, pkcs7_datalen, lc_pem_flag_cms);
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
			parsed_opts.infile = optarg;
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

	parsed_opts.pkcs7_msg = argv[optind];

	if (parsed_opts.infile)
		CKINT(pkcs7_set_data(&parsed_opts));

	CKINT(sbverify_dump_file(&parsed_opts, verbose));

out:
	pkcs7_clean_opts(&parsed_opts);
	PKCS7_FREE
	return -ret;
}
