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

#include "asn1_test_helper.h"
#include "lc_pkcs7_parser.h"
#include "ret_checkers.h"

struct pkcs7_trust_options {
#define MAX_FILES 10
	const char *file[MAX_FILES];
	unsigned int num_files;
	unsigned int expected;
	const char *pkcs7_file;
	const char *verified_file;
};

static int pkcs7_trust_store(struct pkcs7_trust_options *opts)
{
	struct lc_pkcs7_trust_store trust_store = { 0 };
	struct lc_x509_certificate x509[MAX_FILES];
	struct lc_pkcs7_message pkcs7 = { 0 };
	uint8_t *data[MAX_FILES] = { 0 };
	size_t datalen[MAX_FILES] = { 0 };
	uint8_t *pkcs7_data = NULL;
	size_t pkcs7_datalen = 0;
	uint8_t *verified_data = NULL;
	size_t verified_datalen = 0;
	unsigned int i;
	int ret = 0;

	for (i = 0; i < opts->num_files; i++) {
		CKINT_LOG(get_data(opts->file[i], &data[i], &datalen[i]),
			  "Loading of file %s\n", opts->file[i]);
		CKINT_LOG(lc_x509_cert_parse(&x509[i], data[i], datalen[i]),
			  "Parsing of certificate %u\n", i);
		CKINT_LOG(lc_pkcs7_trust_store_add(&trust_store, &x509[i]),
			  "Loading certificate %u into trust store\n", i);
	}

	if (opts->pkcs7_file) {
		CKINT_LOG(get_data(opts->pkcs7_file, &pkcs7_data,
				   &pkcs7_datalen),
			  "Loading of file %s\n", opts->pkcs7_file);
		CKINT_LOG(get_data(opts->verified_file, &verified_data,
				   &verified_datalen),
			  "Reading verification data\n");
		CKINT_LOG(lc_pkcs7_message_parse(&pkcs7, pkcs7_data,
						 pkcs7_datalen),
			  "Parsing of PKCS#7 message\n");
		/* Supply detached data */
		CKINT(lc_pkcs7_supply_detached_data(&pkcs7, verified_data,
						    verified_datalen));

		CKINT_LOG(lc_pkcs7_verify(&pkcs7, NULL),
			  "PKCS#7 verification\n");
		CKINT_LOG(lc_pkcs7_trust_validate(&pkcs7, &trust_store),
			  "PKCS#7 trust verification\n");
	}

out:
	for (i = 0; i < opts->num_files; i++) {
		release_data(data[i], datalen[i]);
		lc_x509_cert_clear(&x509[i]);
	}
	release_data(pkcs7_data, pkcs7_datalen);
	release_data(verified_data, verified_datalen);

	/*
	 * A conversion to support testing on different systems where the
	 * error codes are different.
	 */
	if (ret == -EKEYREJECTED)
		ret = -250;
	if (ret == -ENOKEY)
		ret = -249;

	lc_pkcs7_trust_store_clear(&trust_store);
	return ret;
}

static void pkcs7_trust_usage(void)
{
	fprintf(stderr, "\nPKCS#7 trust store tester\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]... FILE...\n");

	fprintf(stderr, "\nOptions:\n");

	fprintf(stderr, "\t-f --file FILE\t\tinput file to be checked\n");
	fprintf(stderr, "\t-p --pkcs7 FILE\t\tPKCS#7 file\n");
	fprintf(stderr, "\t-e --expected ERRNO\t\texpected error number\n");
	fprintf(stderr,
		"\t-v --verify <FILE>\t\tverify input as PKCS#7 data\n");

	fprintf(stderr, "\t-h  --help\t\tPrint this help text\n");
}

int main(int argc, char *argv[])
{
	struct pkcs7_trust_options parsed_opts = { 0 };
	int ret = 0, opt_index = 0;

	static const char *opts_short = "f:e:p:v:";
	static const struct option opts[] = { { "help", 0, 0, 'h' },
					      { "file", 1, 0, 'f' },
					      { "expected", 1, 0, 'e' },
					      { "pkcs7", 1, 0, 'p' },
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
				pkcs7_trust_usage();
				goto out;

			/* file */
			case 1:
				if (parsed_opts.num_files >= MAX_FILES) {
					printf("Too many input files\n");
					ret = -EINVAL;
					goto out;
				}
				parsed_opts.file[parsed_opts.num_files++] =
					optarg;
				break;

			/* expected */
			case 2:
				parsed_opts.expected =
					(unsigned int)strtoul(optarg, NULL, 10);
				if (parsed_opts.expected > 255) {
					printf("Expected error too large\n");
					ret = -EFAULT;
					goto out;
				}
				break;
			/* pkcs7 */
			case 3:
				parsed_opts.pkcs7_file = optarg;
				break;
			/* verify */
			case 4:
				parsed_opts.verified_file = optarg;
				break;
			}

			break;

		case 'h':
			pkcs7_trust_usage();
			goto out;

		case 'f':
			if (parsed_opts.num_files >= MAX_FILES) {
				printf("Too many input files\n");
				ret = -EINVAL;
				goto out;
			}
			parsed_opts.file[parsed_opts.num_files++] = optarg;
			break;

		case 'e':
			parsed_opts.expected =
				(unsigned int)strtoul(optarg, NULL, 10);
			if (parsed_opts.expected > 255) {
				printf("Expected error too large\n");
				ret = -EFAULT;
				goto out;
			}
			break;
		case 'p':
			parsed_opts.pkcs7_file = optarg;
			break;
		case 'v':
			parsed_opts.verified_file = optarg;
			break;

		default:
			pkcs7_trust_usage();
			ret = -1;
			goto out;
		}
	}

	CKINT(pkcs7_trust_store(&parsed_opts));

out:
	ret = -ret;
	if (parsed_opts.expected) {
		if (parsed_opts.expected == (unsigned int)ret)
			ret = 0;
		else
			ret = -EFAULT;
	}
	return -ret;
}
