/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include <getopt.h>
#include <stdio.h>

#include "lc_pkcs7_generator_helper.h"
#include "lc_status.h"
#include "lc_x509_generator.h"
#include "ret_checkers.h"

static void pkcs7_generator_version(void)
{
	char version[500];

	memset(version, 0, sizeof(version));
	lc_status(version, sizeof(version));

	fprintf(stderr, "Leancrypto PKCS#7 / CMS Message Generator\n");
	fprintf(stderr, "%s\n", version);
}

static void pkcs7_generator_usage(void)
{
	fprintf(stderr, "\nLeancrypto PKCS#7 / CMS Message Generator\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]\n");

	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr,
		"\t-o --outfile <FILE>\t\tFile to write certificate to\n");
	fprintf(stderr,
		"\t-i --infile <FILE>\t\tFile with data to be protected\n");
	fprintf(stderr, "\t\t\t\t\t\tNOTE: Only detached signatures\n");
	fprintf(stderr, "\t\t\t\t\t\tare created\n");

	fprintf(stderr, "\n\tOptions for X.509 signer:\n");
	fprintf(stderr,
		"\t   --md <DIGEST>\t\tMessage digest to use (default SHA3-512)\n");
	fprintf(stderr, "\t\t\t\t\t\tQuery algorithms with \"?\"\n");
	fprintf(stderr,
		"\t   --x509-signer <FILE>\t\tX.509 certificate of signer\n");
	fprintf(stderr, "\t\t\t\t\t\tIf not set, create a self-signed\n");
	fprintf(stderr, "\t\t\t\t\t\tcertificate\n");
	fprintf(stderr,
		"\t   --signer-sk-file <FILE>\tFile with signer secret\n");

	fprintf(stderr, "\n\tOptions for additional X.509:\n");
	fprintf(stderr,
		"\t   --x509-cert <FILE>\t\tX.509 additional certificate\n");
	fprintf(stderr,
		"\t   --pem-output\t\t\tKey / certificate files are created\n");
	fprintf(stderr, "\t\t\t\t\tin PEM format (input data PEM format\n");
	fprintf(stderr, "\t\t\t\t\tis autodetected)\n");

	fprintf(stderr,
		"\n\tOptions for analyzing generated / loaded PKCS#7 messages:\n");
	fprintf(stderr,
		"\t   --print\t\t\tParse the generated PKCS#7 message,\n");
	fprintf(stderr, "\t\t\t\t\tverify protected data, and\n");
	fprintf(stderr, "\t\t\t\t\tprint its contents\n");
	fprintf(stderr,
		"\t   --verify-pkcs7 <FILE>\tParse the PKCS#7 message and\n");
	fprintf(stderr, "\t\t\t\t\tverify protected data\n");
	fprintf(stderr,
		"\t   --print-pkcs7 <FILE>\t\tParse the PKCS#7 message,\n");
	fprintf(stderr, "\t\t\t\t\tverify protected data, and\n");
	fprintf(stderr, "\t\t\t\t\tprint its contents\n");
	fprintf(stderr,
		"\t   --print-pkcs7-noverify <FILE>\tParse the PKCS#7 message,\n");
	fprintf(stderr, "\t\t\t\t\tand print its contents\n");
	fprintf(stderr, "\t   --noout\t\t\tNo generation of output files\n");
	fprintf(stderr,
		"\t   --trust-anchor <FILE>\tTrust anchor X.509 certificate\n");
	fprintf(stderr,
		"\t   --expected-keyusage <KU>\tKey Usage flag signer must have\n");
	fprintf(stderr, "\t\t\t\t\t\tQuery flags with \"?\"\n");
	fprintf(stderr,
		"\t   --expected-eku <EKU>\t\tExetended Key Usage flag signer\n");
	fprintf(stderr, "\t\t\t\t\t\tmust have - Query flags with \"?\"\n");

	fprintf(stderr,
		"\n\tOptions for checking generated / loaded X.509 certificate:\n");
	fprintf(stderr, "\t   --check-ca\t\t\tcheck presence of CA\n");
	fprintf(stderr, "\t   --check-rootca\t\tcheck if root CA\n");
	fprintf(stderr, "\t   --check-noca\t\t\tcheck absence of CA\n");
	fprintf(stderr,
		"\t   --check-ca-conformant\tcheck presence of RFC5280 conformant CA\n");
	fprintf(stderr, "\t\t\t\t\tdefinition\n");
	fprintf(stderr, "\t   --check-issuer-cn\t\tcheck issuer CN\n");
	fprintf(stderr, "\t   --check-subject-cn\t\tcheck subject CN\n");
	fprintf(stderr,
		"\t   --check-selfsigned\t\tcheck that cert is self-signed\n");
	fprintf(stderr,
		"\t   --check-noselfsigned\t\tcheck that cert is not self-signed\n");
	fprintf(stderr,
		"\t   --check-eku <EKU>\t\tmatch extended key usage (use KEY_EKU_*\n");
	fprintf(stderr,
		"\t   --check-keyusage <EKU>\tmatch key usage (use KEY_USAGE_*\n");
	fprintf(stderr, "\t\t\t\t\tflags)\n");
	fprintf(stderr, "\t   --check-data <DATA>\tmatch data\n");
	fprintf(stderr, "\t   --check-kid <KID>\tmatch KID\n");

	fprintf(stderr, "\n\t-h  --help\t\t\tPrint this help text\n");
}

int main(int argc, char *argv[])
{
	struct pkcs7_generator_opts parsed_opts = { 0 };
	struct x509_checker_options *checker_opts = &parsed_opts.checker_opts;
	struct lc_verify_rules *verify_rules = &parsed_opts.verify_rules;
	PKCS7_ALLOC
	int ret = 0, opt_index = 0;

	static const char *opts_short = "ho:i:v";
	static const struct option opts[] = {
		{ "help", 0, 0, 'h' },
		{ "version", 0, 0, 'v' },

		{ "outfile", 1, 0, 'o' },
		{ "infile", 1, 0, 'i' },

		{ "md", 1, 0, 0 },
		{ "x509-signer", 1, 0, 0 },
		{ "signer-sk-file", 1, 0, 0 },
		{ "x509-cert", 1, 0, 0 },

		{ "print", 0, 0, 0 },
		{ "noout", 0, 0, 0 },
		{ "print-pkcs7", 1, 0, 0 },
		{ "print-pkcs7-noverify", 1, 0, 0 },
		{ "trust-anchor", 1, 0, 0 },

		{ "expected-keyusage", 1, 0, 0 },
		{ "expected-eku", 1, 0, 0 },

		{ "check-ca", 0, 0, 0 },
		{ "check-ca-conformant", 0, 0, 0 },
		{ "check-issuer-cn", 1, 0, 0 },
		{ "check-subject-cn", 1, 0, 0 },
		{ "check-noselfsigned", 0, 0, 0 },
		{ "check-eku", 1, 0, 0 },
		{ "check-noca", 0, 0, 0 },
		{ "check-selfsigned", 0, 0, 0 },
		{ "check-rootca", 0, 0, 0 },
		{ "check-keyusage", 1, 0, 0 },
		{ "check-data", 1, 0, 0 },
		{ "check-kid", 1, 0, 0 },

		{ "verify-pkcs7", 1, 0, 0 },
		{ "pem-output", 0, 0, 0 },

		{ 0, 0, 0, 0 }
	};

	parsed_opts.pkcs7 = pkcs7_msg;

	/* Should that be turned into an option? */
	parsed_opts.aa_set = sinfo_has_content_type | sinfo_has_signing_time |
			     sinfo_has_message_digest;

	opterr = 0;
	while (1) {
		int c = getopt_long(argc, argv, opts_short, opts, &opt_index);

		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			/* help */
			case 0:
				pkcs7_generator_usage();
				goto out;
			/* version */
			case 1:
				pkcs7_generator_version();
				goto out;

			/* outfile */
			case 2:
				CKINT(pkcs7_check_file(optarg));
				parsed_opts.outfile = optarg;
				break;
			/* infile */
			case 3:
				parsed_opts.infile = optarg;
				break;

			/* md */
			case 4:
				if (parsed_opts.signer_set) {
					printf("The option --md must be set before the first signer to take effect\n");
					ret = -EINVAL;
					goto out;
				}
				CKINT(lc_x509_name_to_hash(optarg,
							   &parsed_opts.hash));
				break;

			/* x509-signer */
			case 5:
				parsed_opts.x509_signer_file = optarg;
				CKINT(pkcs7_collect_signer(&parsed_opts));
				break;
			/* signer-sk-file */
			case 6:
				parsed_opts.signer_sk_file = optarg;
				CKINT(pkcs7_collect_signer(&parsed_opts));
				break;

			/* x509-cert */
			case 7:
				parsed_opts.x509_file = optarg;
				CKINT(pkcs7_collect_x509(&parsed_opts));
				break;

			/* print */
			case 8:
				parsed_opts.print_pkcs7 = 1;
				break;
			/* noout */
			case 9:
				parsed_opts.noout = 1;
				break;
			/* print-pkcs7 */
			case 10:
				parsed_opts.pkcs7_msg = optarg;
				parsed_opts.print_pkcs7 = 1;
				break;
			/* print-pkcs7-noverify */
			case 11:
				parsed_opts.pkcs7_msg = optarg;
				parsed_opts.print_pkcs7 = 1;
				parsed_opts.skip_signature_verification = 1;
				break;
			/* trust-anchor */
			case 12:
				parsed_opts.trust_anchor = optarg;
				CKINT(pkcs7_collect_trust(&parsed_opts));
				break;

			/* expected-keyusage */
			case 13:
				CKINT(lc_x509_name_to_keyusage(
					optarg,
					&verify_rules->required_keyusage));
				parsed_opts.verify_rules_set = 1;
				break;
			/* expected-eku */
			case 14:
				CKINT(lc_x509_name_to_eku(
					optarg, &verify_rules->required_eku));
				parsed_opts.verify_rules_set = 1;
				break;

			/* check-ca */
			case 15:
				checker_opts->check_ca = 1;
				parsed_opts.checker = 1;
				break;
			/* check-ca-conformant */
			case 16:
				checker_opts->check_ca_conformant = 1;
				parsed_opts.checker = 1;
				break;
			/* check-issuer-cn */
			case 17:
				checker_opts->issuer_cn = optarg;
				parsed_opts.checker = 1;
				break;
			/* check-subject-cn */
			case 18:
				checker_opts->subject_cn = optarg;
				parsed_opts.checker = 1;
				break;
			/* check-noselfsigned */
			case 19:
				checker_opts->check_no_selfsigned = 1;
				parsed_opts.checker = 1;
				break;
			/* check-eku */
			case 20:
				checker_opts->eku =
					(unsigned int)strtoul(optarg, NULL, 10);
				parsed_opts.checker = 1;
				break;
			/* check-noca */
			case 21:
				checker_opts->check_no_ca = 1;
				parsed_opts.checker = 1;
				break;
			/* check-selfsigned */
			case 22:
				checker_opts->check_selfsigned = 1;
				parsed_opts.checker = 1;
				break;
			/* check-rootca */
			case 23:
				checker_opts->check_root_ca = 1;
				parsed_opts.checker = 1;
				break;
			/* check-keyusage */
			case 24:
				checker_opts->keyusage =
					(unsigned int)strtoul(optarg, NULL, 10);
				parsed_opts.checker = 1;
				break;
			/* check-data */
			case 25:
				checker_opts->data = optarg;
				parsed_opts.checker = 1;
				break;
			/* check-data */
			case 26:
				checker_opts->skid = optarg;
				parsed_opts.checker = 1;
				break;
			/* verify-pkcs7 */
			case 27:
				parsed_opts.pkcs7_msg = optarg;
				break;
			/* pem-output */
			case 28:
				parsed_opts.pem_format_output = 1;
				break;
			}
			break;

		case 'o':
			CKINT(pkcs7_check_file(optarg));
			parsed_opts.outfile = optarg;
			break;
		case 'i':
			parsed_opts.infile = optarg;
			break;
		case 'h':
			pkcs7_generator_usage();
			goto out;
		case 'v':
			pkcs7_generator_version();
			goto out;

		default:
			pkcs7_generator_usage();
			ret = -1;
			goto out;
		}
	}

	if (parsed_opts.pkcs7_msg) {
		if (parsed_opts.infile)
			CKINT(pkcs7_set_data(&parsed_opts));

		CKINT(pkcs7_dump_file(&parsed_opts));
		goto out;
	}

	CKINT(pkcs7_set_data(&parsed_opts));
	CKINT(pkcs7_gen_message(&parsed_opts));

out:
	pkcs7_clean_opts(&parsed_opts);
	PKCS7_FREE
	return -ret;
}
