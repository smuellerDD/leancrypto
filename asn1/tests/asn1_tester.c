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

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <time.h>

#include "asn1_test_helper.h"
#include "lc_pkcs7_parser.h"
#include "lc_x509_parser.h"
#include "ret_checkers.h"
#include "x509_checker.h"
#include "x509_print.h"

#include "../src/x509_algorithm_mapper.h"
#include "../src/x509_cert_parser.h"

static int x509_load(const struct x509_checker_options *parsed_opts)
{
	struct lc_x509_certificate x509_msg;
	size_t datalen = 0;
	uint8_t *data = NULL;
	int ret;

	CKNULL_LOG(parsed_opts->file, -EINVAL, "Pathname missing\n");

	CKINT_LOG(get_data(parsed_opts->file, &data, &datalen),
		  "mmap failure\n");

	CKINT_LOG(lc_x509_cert_decode(&x509_msg, data, datalen),
		  "Parsing of message failed\n");

	CKINT(apply_checks_x509(&x509_msg, parsed_opts));

out:
	release_data(data, datalen);
	lc_x509_cert_clear(&x509_msg);
	return ret;
}

static int pkcs7_load(const struct x509_checker_options *parsed_opts)
{
	struct lc_pkcs7_message pkcs7_msg;
	size_t datalen = 0;
	uint8_t *data = NULL;
	int ret;

	CKNULL_LOG(parsed_opts->file, -EINVAL, "Pathname missing\n");

	CKINT_LOG(get_data(parsed_opts->file, &data, &datalen),
		  "mmap failure\n");

	CKINT_LOG(lc_pkcs7_decode(&pkcs7_msg, data, datalen),
		  "Parsing of message failed\n");

	CKINT(apply_checks_pkcs7(&pkcs7_msg, parsed_opts));

out:
	release_data(data, datalen);
	lc_pkcs7_message_clear(&pkcs7_msg);
	return ret;
}

/******************************************************************************
 * PKCS7 verify
 ******************************************************************************/

static int pkcs7_load_and_verify(const struct x509_checker_options *parsed_opts)
{
	struct lc_pkcs7_message pkcs7_msg;
	size_t datalen = 0, verified_datalen = 0;
	uint8_t *data = NULL, *verified_data = NULL;
	int ret;

	CKNULL(parsed_opts->verified_file, -EINVAL);

	CKNULL_LOG(parsed_opts->file, -EINVAL, "Pathname missing\n");

	CKINT_LOG(get_data(parsed_opts->file, &data, &datalen),
		  "mmap failure\n");
	CKINT_LOG(get_data(parsed_opts->verified_file, &verified_data,
			   &verified_datalen),
		  "mmap failure\n");

	/* Parse message */
	CKINT_LOG(lc_pkcs7_decode(&pkcs7_msg, data, datalen),
		  "Parsing of message failed\n");

	/* Supply detached data */
	CKINT(lc_pkcs7_supply_detached_data(&pkcs7_msg, verified_data,
					    verified_datalen));

	/* Verify data */
	CKINT_LOG(lc_pkcs7_verify(&pkcs7_msg, NULL, NULL),
		  "Verification failure\n");

out:
	release_data(data, datalen);
	release_data(verified_data, verified_datalen);
	lc_pkcs7_message_clear(&pkcs7_msg);
	return ret;
}

static void asn1_usage(void)
{
	fprintf(stderr, "\nASN.1 tester\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]... FILE...\n");

	fprintf(stderr, "\nOptions:\n");

	fprintf(stderr, "\t-f --file FILE\t\tinput file to be checked\n");
	fprintf(stderr, "\t-x --x509\t\tprocess input as X.509 data\n");
	fprintf(stderr, "\t-p --pkcs7\t\tprocess input as PKCS#7 data\n");
	fprintf(stderr,
		"\t-v --verify <FILE>\t\tverify input as PKCS#7 data\n");

	fprintf(stderr, "\t   --check-ca\t\tcheck presence of CA\n");
	fprintf(stderr,
		"\t   --check-ca-conformant\t\tcheck presence of RFC5280 conformant CA definition\n");
	fprintf(stderr,
		"\t   --check-time\t\tcheck time-validity of the certificate\n");
	fprintf(stderr,
		"\t   --check-selfsigned\t\tcheck cert is self-signed\n");
	fprintf(stderr, "\t   --issuer-cn\t\tcheck issuer CN\n");
	fprintf(stderr, "\t   --subject-cn\t\tcheck subject CN\n");
	fprintf(stderr,
		"\t   --check-noselfsigned\t\tcheck that cert is not self-signed\n");
	fprintf(stderr,
		"\t   --valid-from <EPOCH time>\t\tcheck validity of time\n");
	fprintf(stderr,
		"\t   --valid-to <EPOCH time>\t\tcheck validity of time\n");
	fprintf(stderr,
		"\t   --cunsupported-sig\t\tmark certificate to have unsupported signature\n");
	fprintf(stderr, "\t   --print\t\tprint details\n");
	fprintf(stderr,
		"\t   --eku\t\tmatch estended key usage (use EKY_EKU_* flags)\n");
	fprintf(stderr, "\t   --san-dns <NAME>\t\tmatch SAN DNS\n");
	fprintf(stderr, "\t   --san-ip <IP-Hex>\t\tmatch SAN IP\n");
	fprintf(stderr, "\t   --skid <HEX>\t\tmatch subject key ID\n");
	fprintf(stderr, "\t   --akid <HEX>\t\tmatch authority key ID\n");

	fprintf(stderr, "\t-h  --help\t\tPrint this help text\n");
}

int main(int argc, char *argv[])
{
	struct x509_checker_options parsed_opts = { 0 };
	int ret = 0, opt_index = 0;

	static const char *opts_short = "f:hxpv:";
	static const struct option opts[] = { { "help", 0, 0, 'h' },
					      { "file", 1, 0, 'f' },
					      { "x509", 0, 0, 'x' },
					      { "pkcs7", 0, 0, 'p' },

					      { "check-ca", 0, 0, 0 },
					      { "check-selfsigned", 0, 0, 0 },
					      { "issuer-cn", 1, 0, 0 },
					      { "subject-cn", 1, 0, 0 },
					      { "check-noselfsigned", 0, 0, 0 },
					      { "check-noca", 0, 0, 0 },
					      { "valid-from", 1, 0, 0 },
					      { "valid-to", 1, 0, 0 },
					      { "unsupported-sig", 0, 0, 0 },
					      { "print", 0, 0, 0 },
					      { "eku", 1, 0, 0 },
					      { "san-dns", 1, 0, 0 },
					      { "san-ip", 1, 0, 0 },
					      { "skid", 1, 0, 0 },
					      { "akid", 1, 0, 0 },
					      { "check-ca-conformant", 0, 0,
						0 },
					      { "check-time", 0, 0, 0 },
					      { "verify", 1, 0, 'v' },

					      { 0, 0, 0, 0 } };

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
				asn1_usage();
				goto out;

			/* file */
			case 1:
				parsed_opts.file = optarg;
				break;

			/* x509 */
			case 2:
				parsed_opts.asn1_type = asn1_type_x509;
				break;

			/* pkcs7 */
			case 3:
				parsed_opts.asn1_type = asn1_type_pkcs7;
				break;

			/* check-ca */
			case 4:
				parsed_opts.check_ca = 1;
				break;
			/* check-selfsigned */
			case 5:
				parsed_opts.check_selfsigned = 1;
				break;
			/* issuer-cn */
			case 6:
				parsed_opts.issuer_cn = optarg;
				break;
			/* subject-cn */
			case 7:
				parsed_opts.subject_cn = optarg;
				break;
			/* check-noselfsigned */
			case 8:
				parsed_opts.check_no_selfsigned = 1;
				break;
			/* check-noca */
			case 9:
				parsed_opts.check_no_ca = 1;
				break;
			/* valid-from */
			case 10:
				parsed_opts.valid_from =
					strtoull(optarg, NULL, 10);
				break;
			/* valid-to */
			case 11:
				parsed_opts.valid_to =
					strtoull(optarg, NULL, 10);
				break;
			/* unsupported-sig */
			case 12:
				parsed_opts.unsupported_sig = 1;
				break;
			/* print */
			case 13:
				parsed_opts.print_cert_details = 1;
				break;
			/* eku */
			case 14:
				parsed_opts.eku =
					(unsigned int)strtoul(optarg, NULL, 10);
				break;
			/* san-dns */
			case 15:
				parsed_opts.san_dns = optarg;
				break;
			/* san-ip */
			case 16:
				parsed_opts.san_ip = optarg;
				break;
			/* skid */
			case 17:
				parsed_opts.skid = optarg;
				break;
			/* akid */
			case 18:
				parsed_opts.akid = optarg;
				break;

			/* check-ca-conformant */
			case 19:
				parsed_opts.check_ca_conformant = 1;
				break;

			/* check-time */
			case 20:
				parsed_opts.check_time = 1;
				break;

			/* verify */
			case 21:
				parsed_opts.asn1_type = asn1_type_verify;
				parsed_opts.verified_file = optarg;
				break;
			}
			break;

		case 'h':
			asn1_usage();
			goto out;

		case 'f':
			parsed_opts.file = optarg;
			break;

		case 'x':
			parsed_opts.asn1_type = asn1_type_x509;
			break;

		case 'p':
			parsed_opts.asn1_type = asn1_type_pkcs7;
			break;
		case 'v':
			parsed_opts.asn1_type = asn1_type_verify;
			parsed_opts.verified_file = optarg;
			break;

		default:
			asn1_usage();
			ret = -1;
			goto out;
		}
	}

	switch (parsed_opts.asn1_type) {
	case asn1_type_pkcs7:
		CKINT(pkcs7_load(&parsed_opts));
		break;
	case asn1_type_x509:
		CKINT(x509_load(&parsed_opts));
		break;
	case asn1_type_verify:
		CKINT(pkcs7_load_and_verify(&parsed_opts));
		break;
	case asn1_type_undefined:
	default:
		printf("Wrong ASN.1 test type\n");
		ret = -EINVAL;
		goto out;
	}

out:
	return -ret;
}
