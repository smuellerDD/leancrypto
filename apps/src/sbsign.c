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

#include "lc_memory_support.h"
#include "lc_pkcs7_generator_helper.h"
#include "lc_status.h"
#include "ret_checkers.h"

static const char *toolname = "sbsign";

static struct option options[] = {
	{ "output", required_argument, NULL, 'o' },
	{ "cert", required_argument, NULL, 'c' },
	{ "key", required_argument, NULL, 'k' },
	{ "detached", no_argument, NULL, 'd' },
	{ "verbose", no_argument, NULL, 'v' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'V' },
	{ "engine", required_argument, NULL, 'e'},
	{ "addcert", required_argument, NULL, 'a'},
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

int main(int argc, char **argv)
{
	PKCS7_ALLOC
	struct pkcs7_generator_opts parsed_opts = { 0 };
	char *outfile = NULL;
	int ret, c;

	parsed_opts.infile_flags = lc_pkcs7_set_data_embed;
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
	parsed_opts.hash = lc_sha512;
	parsed_opts.pkcs7 = pkcs7_msg;

	/* Should that be turned into an option? */
	parsed_opts.aa_set = sinfo_has_content_type | sinfo_has_signing_time |
			     sinfo_has_message_digest;

	for (;;) {
		int idx;
		c = getopt_long(argc, argv, "o:c:k:dvVhe:a:", options, &idx);
		if (c == -1)
			break;

		switch (c) {
		case 'o':
			CKINT(pkcs7_check_file(optarg));
			parsed_opts.outfile = optarg;
			break;
		case 'c':
			parsed_opts.x509_signer_file = optarg;
			CKINT(pkcs7_collect_signer(&parsed_opts));
			break;
		case 'k':
			parsed_opts.signer_sk_file = optarg;
			CKINT(pkcs7_collect_signer(&parsed_opts));
			break;
		case 'd':
			parsed_opts.infile_flags = lc_pkcs7_set_data_noflag;
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
			parsed_opts.x509_file = optarg;
			CKINT(pkcs7_collect_x509(&parsed_opts));
			break;
		}
	}

	if (argc != optind + 1) {
		usage();
		ret = -EINVAL;
		goto out;
	}

	parsed_opts.infile = argv[optind];
	if (!parsed_opts.outfile)
		CKINT(set_default_outfilename(&parsed_opts, &outfile));

	CKINT(pkcs7_set_data(&parsed_opts));
	CKINT(pkcs7_gen_message(&parsed_opts));

out:
	if (outfile)
		lc_free(outfile);
	pkcs7_clean_opts(&parsed_opts);
	PKCS7_FREE
	return -ret;
}

