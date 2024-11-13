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
#include "binhexbin.h"
#include "lc_pkcs7_parser.h"
#include "lc_x509_parser.h"
#include "math_helper.h"
#include "ret_checkers.h"
#include "x509_print.h"

#include "../src/x509_algorithm_mapper.h"
#include "../src/x509_cert_parser.h"

enum asn1_test_type {
	asn1_type_undefined,
	asn1_type_pkcs7,
	asn1_type_x509,
	asn1_type_verify,
};

struct pkcs7_options {
	const char *file;
	const char *verified_file;
	enum asn1_test_type asn1_type;

	unsigned int check_ca : 1;
	unsigned int check_ca_conformant : 1;
	unsigned int check_time : 1;
	unsigned int check_no_ca : 1;
	unsigned int check_selfsigned : 1;
	unsigned int check_no_selfsigned : 1;
	unsigned int unsupported_sig : 1;
	unsigned int print_cert_details : 1;
	unsigned int eku;
	const char *issuer_cn;
	const char *subject_cn;
	const char *san_dns;
	const char *san_ip;
	const char *skid;
	const char *akid;
	uint64_t valid_from;
	uint64_t valid_to;
};

/******************************************************************************
 * X.509 tests
 ******************************************************************************/

static int apply_checks_x509(const struct lc_x509_certificate *x509,
			     const struct pkcs7_options *parsed_opts)
{
	const struct lc_public_key *pub = &x509->pub;
	x509_pol_ret_t ret;

	CKINT(lc_x509_policy_cert_valid(x509))
	if (ret == LC_X509_POL_FALSE) {
		printf("Invalid certificate detected\n");
		return -EINVAL;
	}

	if (parsed_opts->check_ca) {
		/* Check whether CA basic constraint is present */
		if (!(pub->ca_pathlen & LC_KEY_CA_MASK)) {
			printf("Certificate is not marked as CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as CA\n");
		}
	}

	if (parsed_opts->check_ca_conformant) {
		CKINT(lc_x509_policy_is_ca(x509));

		if (ret == LC_X509_POL_FALSE) {
			printf("Certificate is not marked as an RFC5280 conformant CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as an RFC5280 as CA\n");
		}
	}

	if (parsed_opts->check_no_ca) {
		CKINT(lc_x509_policy_is_ca(x509));

		if (ret == LC_X509_POL_TRUE) {
			printf("Certificate is marked as CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is not marked as CA\n");
		}
	}

	if (parsed_opts->check_selfsigned) {
		/*
		 * The signature is only verified for self-signed certificates.
		 * For other certificates, the certificate chain needs to be
		 * followed using the PKCS7 handling.
		 */
		if (parsed_opts->unsupported_sig) {
			if (!x509->unsupported_sig) {
				printf("Certificate has supported signature\n");
				return -EINVAL;
			} else {
				printf("Certificate has unsupported signature\n");
			}
		} else {
			if (!x509->self_signed) {
				printf("Certificate is not self-signed\n");
				return -EINVAL;
			} else {
				printf("Certificate is self-signed\n");
			}
		}
	}
	if (parsed_opts->check_no_selfsigned) {
		if (x509->self_signed) {
			printf("Certificate is self-signed\n");
			return -EINVAL;
		} else {
			printf("Certificate is not self-signed\n");
		}
	}

	if (parsed_opts->valid_from) {
		if (parsed_opts->valid_from != (uint64_t)x509->valid_from) {
			struct tm *exp_detail, *act_detail;

			// localtime_r(&x509->valid_from, &act_detail);
			// localtime_r((int64_t *)&parsed_opts->valid_from,
			// 	    &exp_detail);
			act_detail = localtime(&x509->valid_from);
			exp_detail =
				localtime((int64_t *)&parsed_opts->valid_from);
			printf("Certificate valid_from time mismatch, expected %d-%.2d-%.2d %.2d:%.2d:%.2d (%" PRIu64
			       "), actual %d-%.2d-%.2d %.2d:%.2d:%.2d (%" PRId64
			       ")\n",
			       exp_detail->tm_year + 1900,
			       exp_detail->tm_mon + 1, exp_detail->tm_mday,
			       exp_detail->tm_hour, exp_detail->tm_min,
			       exp_detail->tm_sec, parsed_opts->valid_from,
			       act_detail->tm_year + 1900,
			       act_detail->tm_mon + 1, act_detail->tm_mday,
			       act_detail->tm_hour, act_detail->tm_min,
			       act_detail->tm_sec, x509->valid_from);
			return -EINVAL;
		} else {
			printf("Certificate valid_from time successfully verified\n");
		}
	}

	if (parsed_opts->valid_to) {
		if (parsed_opts->valid_to != (uint64_t)x509->valid_to) {
			struct tm *exp_detail, *act_detail;

			// localtime_r(&x509->valid_to, &act_detail);
			// localtime_r((int64_t *)&parsed_opts->valid_to,
			// 	    &exp_detail);
			act_detail = localtime(&x509->valid_to);
			exp_detail =
				localtime((int64_t *)&parsed_opts->valid_to);
			printf("Certificate valid_to time mismatch, expected %d-%.2d-%.2d %.2d:%.2d:%.2d (%" PRIu64
			       "), actual %d-%.2d-%.2d %.2d:%.2d:%.2d (%" PRId64
			       ")\n",
			       exp_detail->tm_year + 1900,
			       exp_detail->tm_mon + 1, exp_detail->tm_mday,
			       exp_detail->tm_hour, exp_detail->tm_min,
			       exp_detail->tm_sec, parsed_opts->valid_to,
			       act_detail->tm_year + 1900,
			       act_detail->tm_mon + 1, act_detail->tm_mday,
			       act_detail->tm_hour, act_detail->tm_min,
			       act_detail->tm_sec, x509->valid_to);
			return -EINVAL;
		} else {
			printf("Certificate valid_to time successfully verified\n");
		}
	}

	if (parsed_opts->issuer_cn) {
		if (strncmp(x509->issuer, parsed_opts->issuer_cn,
			    sizeof(x509->issuer))) {
			printf("Issuers mismatch, expected %s, actual %s\n",
			       parsed_opts->issuer_cn, x509->issuer);
			return -EINVAL;
		} else {
			printf("Issuer matches expected value\n");
		}
	}
	if (parsed_opts->subject_cn) {
		if (strncmp(x509->subject, parsed_opts->subject_cn,
			    sizeof(x509->subject))) {
			printf("Subject mismatch, expected %s, actual %s\n",
			       parsed_opts->subject_cn, x509->subject);
			return -EINVAL;
		} else {
			printf("Subject matches expected value\n");
		}
	}

	if (parsed_opts->print_cert_details) {
		ret = print_x509_cert(x509);

		if (ret)
			return ret;
	}

	if (parsed_opts->eku) {
		CKINT(lc_x509_policy_match_extended_key_usage(
			x509, (uint16_t)parsed_opts->eku));

		if (ret == LC_X509_POL_TRUE) {
			printf("EKU field matches\n");
		} else {
			printf("EKU field mismatches (expected %u, actual %u)\n",
			       parsed_opts->eku, pub->key_eku);
			return -EINVAL;
		}
	}

	if (parsed_opts->san_dns) {
		size_t exp_len = strlen(parsed_opts->san_dns);

		if (exp_len != x509->san_dns_len) {
			printf("SAN DNS: lengths differ (expected %zu, actual %zu)\n",
			       exp_len, x509->san_dns_len);
			return -EINVAL;
		}

		if (memcmp(parsed_opts->san_dns, x509->san_dns, exp_len)) {
			char buf[128];

			memcpy(buf, x509->san_dns,
			       min_size(sizeof(buf), x509->san_dns_len));

			printf("SAN DNS: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->san_dns, buf);
			return -EINVAL;
		} else {
			printf("SAN DNS match\n");
		}
	}
	if (parsed_opts->san_ip) {
		uint8_t exp_ip_bin[16];
		size_t exp_len = strlen(parsed_opts->san_ip);

		hex2bin(parsed_opts->san_ip, exp_len, exp_ip_bin,
			sizeof(exp_ip_bin));

		if (exp_len / 2 != x509->san_ip_len) {
			printf("SAN IP: lengths differ (expected %zu, actual %zu)\n",
			       exp_len, x509->san_ip_len);
			return -EINVAL;
		}

		if (memcmp(exp_ip_bin, x509->san_ip, x509->san_ip_len)) {
			char buf[33] = { 0 };

			bin2hex(x509->san_ip, x509->san_ip_len, buf,
				sizeof(buf) - 1, 1);

			printf("SAN IP: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->san_ip, buf);
			return -EINVAL;
		} else {
			printf("SAN IP match\n");
		}
	}

	if (parsed_opts->skid) {
		uint8_t exp_id_bin[32];
		size_t exp_id_len = strlen(parsed_opts->skid);

		hex2bin(parsed_opts->skid, exp_id_len, exp_id_bin,
			sizeof(exp_id_bin));

		if (exp_id_len / 2 != x509->raw_skid_size) {
			printf("SKID: lengths differ (expected %zu, actual %zu)\n",
			       exp_id_len, x509->raw_skid_size);
			return -EINVAL;
		}

		if (memcmp(exp_id_bin, x509->raw_skid, x509->raw_skid_size)) {
			char buf[65] = { 0 };

			bin2hex(x509->raw_skid, x509->raw_skid_size, buf,
				sizeof(buf) - 1, 1);

			printf("SKID: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->skid, buf);
			return -EINVAL;
		} else {
			CKINT(lc_x509_policy_match_skid(x509, exp_id_bin,
							exp_id_len / 2));

			if (ret == LC_X509_POL_FALSE) {
				printf("SKID x509_policy_match_skid failed\n");
				return -EINVAL;
			}

			printf("SKID match\n");
		}
	}
	if (parsed_opts->akid) {
		uint8_t exp_id_bin[32];
		size_t exp_id_len = strlen(parsed_opts->akid);

		hex2bin(parsed_opts->akid, exp_id_len, exp_id_bin,
			sizeof(exp_id_bin));

		if (exp_id_len / 2 != x509->raw_akid_size) {
			printf("AKID: lengths differ (expected %zu, actual %zu)\n",
			       exp_id_len, x509->raw_akid_size);
			return -EINVAL;
		}

		if (memcmp(exp_id_bin, x509->raw_akid, x509->raw_akid_size)) {
			char buf[65] = { 0 };

			bin2hex(x509->raw_akid, x509->raw_akid_size, buf,
				sizeof(buf) - 1, 1);

			printf("AKID: names mismatch (expected %s, actual %s)\n",
			       parsed_opts->akid, buf);
			return -EINVAL;
		} else {
			/* Check the API */
			CKINT(lc_x509_policy_match_akid(x509, exp_id_bin,
							exp_id_len / 2));

			if (ret == LC_X509_POL_FALSE) {
				printf("AKID x509_policy_match_akid failed\n");
				return -EINVAL;
			}

			printf("AKID match\n");
		}
	}

	if (parsed_opts->check_time) {
		CKINT(lc_x509_policy_time_valid(x509, time(NULL)));

		if (ret == LC_X509_POL_FALSE) {
			printf("Time check: certificate is currently not valid\n");
			return -EINVAL;
		}

		CKINT(lc_x509_policy_time_valid(x509, 1));
		if (ret == LC_X509_POL_TRUE) {
			printf("Time check: certificate marked as valid with unlikely time (1 second after EPOCH)\n");
			return -EINVAL;
		}
		CKINT(lc_x509_policy_time_valid(x509, 9999999999));
		if (ret == LC_X509_POL_TRUE) {
			printf("Time check: certificate marked as valid with unlikely time (way in the future)\n");
			return -EINVAL;
		}

		printf("Time check: certificate is valid\n");
	}

	return 0;

out:
	return ret;
}

static int x509_load(const struct pkcs7_options *parsed_opts)
{
	struct lc_x509_certificate x509_msg;
	size_t datalen = 0;
	uint8_t *data = NULL;
	int ret;

	CKNULL_LOG(parsed_opts->file, -EINVAL, "Pathname missing\n");

	CKINT_LOG(get_data(parsed_opts->file, &data, &datalen),
		  "mmap failure\n");

	CKINT_LOG(lc_x509_cert_parse(&x509_msg, data, datalen),
		  "Parsing of message failed\n");

	CKINT(apply_checks_x509(&x509_msg, parsed_opts));

out:
	release_data(data, datalen);
	lc_x509_cert_clear(&x509_msg);
	return ret;
}

/******************************************************************************
 * PKCS7 load tests
 ******************************************************************************/

static int apply_checks_pkcs7(const struct pkcs7_message *pkcs7_msg,
			      const struct pkcs7_options *parsed_opts)
{
	int ret = 0;

	if (parsed_opts->print_cert_details) {
		print_pkcs7_data(pkcs7_msg);
	}

	if (parsed_opts->check_ca) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			const struct lc_public_key *pub = &x509->pub;

			if (pub->ca_pathlen & LC_KEY_CA_MASK) {
				found = 1;
				break;
			}

			x509 = x509->next;
		}

		/* Check whether CA basic constraint is present */
		if (!found) {
			printf("Certificate is not marked as CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as CA\n");
		}
	}

	if (parsed_opts->check_ca_conformant) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;

		while (x509) {
			ret = lc_x509_policy_is_ca(x509);
			if (ret >= 0)
				break;

			x509 = x509->next;
		}

		if (ret == LC_X509_POL_FALSE) {
			printf("Certificate is not marked as an RFC5280 conformant CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is marked as an RFC5280 as CA\n");
		}
	}

	if (parsed_opts->check_no_ca) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;

		while (x509) {
			ret = lc_x509_policy_is_ca(x509);
			if (ret == LC_X509_POL_FALSE)
				break;

			x509 = x509->next;
		}
		if (ret < 0)
			return ret;

		if (ret == LC_X509_POL_TRUE) {
			printf("Certificate is marked as CA\n");
			return -EINVAL;
		} else {
			printf("Certificate is not marked as CA\n");
		}
	}

	if (parsed_opts->check_selfsigned) {
		/*
		 * The signature is only verified for self-signed certificates.
		 * For other certificates, the certificate chain needs to be
		 * followed using the PKCS7 handling.
		 */
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			if (parsed_opts->unsupported_sig) {
				if (x509->unsupported_sig) {
					found = 1;
					break;
				}
			} else {
				if (x509->self_signed) {
					found = 1;
					break;
				}
			}

			x509 = x509->next;
		}

		if (parsed_opts->unsupported_sig) {
			if (!found) {
				printf("Certificate has supported signature\n");
				return -EINVAL;
			} else {
				printf("Certificate has unsupported signature\n");
			}
		} else {
			if (!found) {
				printf("Certificate is not self-signed\n");
				return -EINVAL;
			} else {
				printf("Certificate is self-signed\n");
			}
		}
	}

	if (parsed_opts->check_no_selfsigned) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			if (!x509->self_signed) {
				found = 1;
				break;
			}

			x509 = x509->next;
		}

		if (found) {
			printf("Certificate is not self-signed\n");
		} else {
			printf("Certificate is not self-signed\n");
			return -EINVAL;
		}
	}

	if (parsed_opts->issuer_cn) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			if (!strncmp(x509->issuer, parsed_opts->issuer_cn,
				     sizeof(x509->issuer))) {
				found = 1;
				break;
			}

			x509 = x509->next;
		}

		if (!found) {
			printf("Issuers mismatch, expected %s, actual %s\n",
			       parsed_opts->issuer_cn, x509->issuer);
			return -EINVAL;
		} else {
			printf("Issuer matches expected value\n");
		}
	}
	if (parsed_opts->subject_cn) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;
		int found = 0;

		while (x509) {
			if (!strncmp(x509->subject, parsed_opts->subject_cn,
				     sizeof(x509->subject))) {
				found = 1;
				break;
			}

			x509 = x509->next;
		}

		if (!found) {
			printf("Subject mismatch, expected %s, actual %s\n",
			       parsed_opts->subject_cn, x509->subject);
			return -EINVAL;
		} else {
			printf("Subject matches expected value\n");
		}
	}

	if (parsed_opts->eku) {
		const struct lc_x509_certificate *x509 = pkcs7_msg->certs;

		while (x509) {
			ret = lc_x509_policy_match_extended_key_usage(
				x509, (uint16_t)parsed_opts->eku);
			if (ret == LC_X509_POL_TRUE)
				break;

			x509 = x509->next;
		}

		if (ret == LC_X509_POL_TRUE) {
			printf("EKU field matches\n");
		} else {
			printf("EKU field mismatches (expected %u, actual %u)\n",
			       parsed_opts->eku, x509->pub.key_eku);
			return -EINVAL;
		}
	}

	ret = 0;

	return ret;
}

static int pkcs7_load(const struct pkcs7_options *parsed_opts)
{
	struct pkcs7_message pkcs7_msg;
	size_t datalen = 0;
	uint8_t *data = NULL;
	int ret;

	CKNULL_LOG(parsed_opts->file, -EINVAL, "Pathname missing\n");

	CKINT_LOG(get_data(parsed_opts->file, &data, &datalen),
		  "mmap failure\n");

	CKINT_LOG(lc_pkcs7_message_parse(&pkcs7_msg, data, datalen),
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

static int pkcs7_load_and_verify(const struct pkcs7_options *parsed_opts)
{
	struct pkcs7_message pkcs7_msg;
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
	CKINT_LOG(lc_pkcs7_message_parse(&pkcs7_msg, data, datalen),
		  "Parsing of message failed\n");

	/* Supply detached data */
	CKINT(lc_pkcs7_supply_detached_data(&pkcs7_msg, verified_data,
					    verified_datalen));

	/* Verify data */
	CKINT_LOG(lc_pkcs7_verify(&pkcs7_msg), "Verification failure\n");

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
	struct pkcs7_options parsed_opts = { 0 };
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
