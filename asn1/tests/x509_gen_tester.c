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

#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "binhexbin.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "lc_x509_generator.h"
#include "lc_x509_parser.h"

#include "../../apps/src/lc_x509_generator_helper.h"

struct x509_checker_options {
	struct lc_x509_key_input_data key_input_data;
	struct lc_x509_key_data key_data;
	struct lc_x509_certificate cert;
	struct lc_dilithium_sk sk;
	struct lc_dilithium_pk pk;
	uint8_t ipaddr[16];
	uint8_t *raw_skid;
	size_t raw_skid_size;
	uint8_t *raw_akid;
	size_t raw_akid_size;
	uint8_t *raw_serial;
	size_t raw_serial_size;

	unsigned int selfsigned : 1;
	unsigned int noselfsigned : 1;
};

static int x509_gen_cert(struct x509_checker_options *opts)
{
#define DATASIZE 65536
	struct workspace {
		struct lc_x509_certificate parsed_x509;
		uint8_t data[DATASIZE];
	};
	struct lc_x509_certificate *gcert = &opts->cert;
	size_t avail_datalen = DATASIZE, datalen;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT(lc_x509_cert_encode(gcert, ws->data, &avail_datalen));
	datalen = DATASIZE - avail_datalen;

	bin2print(ws->data, datalen, stdout, "X.509 Certificate");

	CKINT(lc_x509_cert_decode(&ws->parsed_x509, ws->data, datalen));

	if (opts->selfsigned) {
		if (lc_x509_policy_is_selfsigned(&ws->parsed_x509) !=
		    LC_X509_POL_TRUE) {
			printf("Certificate is not self-signed\n");
			ret = -EFAULT;
			goto out;
		}
		printf("Certificate is self-signed\n");
	}

	if (opts->noselfsigned) {
		if (lc_x509_policy_is_selfsigned(&ws->parsed_x509) ==
		    LC_X509_POL_TRUE) {
			printf("Certificate is self-signed\n");
			ret = -EFAULT;
			goto out;
		}
		printf("Certificate is not self-signed\n");
	}

out:
	lc_x509_cert_clear(&ws->parsed_x509);
	LC_RELEASE_MEM(ws);
	return ret;
}

static int x509_enc_eku(struct x509_checker_options *opts,
			const char *opt_optarg)
{
	unsigned long val;

	val = strtoul(opt_optarg, NULL, 10);
	if (val == USHRT_MAX)
		return -ERANGE;

	opts->cert.pub.key_eku = (uint16_t)val;

	return 0;
}

static int x509_enc_keyusage(struct x509_checker_options *opts,
			     const char *opt_optarg)
{
	unsigned long val;

	val = strtoul(opt_optarg, NULL, 10);
	if (val == USHRT_MAX)
		return -ERANGE;

	opts->cert.pub.key_usage = (uint16_t)val;

	return 0;
}

static int x509_enc_ca(struct x509_checker_options *opts)
{
	opts->cert.pub.basic_constraint = LC_KEY_CA |
					  LC_KEY_BASIC_CONSTRAINT_CRITICAL;

	return 0;
}

static int x509_enc_san_dns(struct x509_checker_options *opts,
			    const char *opt_optarg)
{
	if (!opt_optarg)
		return -EINVAL;

	opts->cert.san_dns = opt_optarg;
	opts->cert.san_dns_len = strlen(opt_optarg);

	return 0;
}

static int x509_enc_skid(struct x509_checker_options *opts,
			 const char *opt_optarg)
{
	int ret;

	if (!opt_optarg)
		return -EINVAL;

	CKINT(hex2bin_alloc(opt_optarg, strlen(opt_optarg), &opts->raw_skid,
			    &opts->raw_skid_size));

	opts->cert.raw_skid = opts->raw_skid;
	opts->cert.raw_skid_size = opts->raw_skid_size;

out:
	return ret;
}

static int x509_enc_akid(struct x509_checker_options *opts,
			 const char *opt_optarg)
{
	int ret;

	if (!opt_optarg)
		return -EINVAL;

	CKINT(hex2bin_alloc(opt_optarg, strlen(opt_optarg), &opts->raw_akid,
			    &opts->raw_akid_size));

	opts->cert.raw_akid = opts->raw_akid;
	opts->cert.raw_akid_size = opts->raw_akid_size;

out:
	return ret;
}

static void x509_clean_opts(struct x509_checker_options *opts)
{
	if (!opts)
		return;

	if (opts->raw_skid)
		free(opts->raw_skid);
	if (opts->raw_akid)
		free(opts->raw_akid);
	if (opts->raw_serial)
		free(opts->raw_serial);
}

static int x509_enc_san_ip(struct x509_checker_options *opts, char *opt_optarg)
{
	unsigned long val;
	char *saveptr = NULL;
	char *res = NULL;
	const char *tok = ".";
	unsigned int i, upper = 4;
	int ret = 0, base = 10;

	if (!opt_optarg)
		return -EINVAL;

	/* Check for IPv6 */
	if (strstr(opt_optarg, ":")) {
		tok = ":";
		upper = 16;
		base = 16;
	}

	res = strtok_r(opt_optarg, tok, &saveptr);
	for (i = 0; i < upper; i++) {
		CKNULL(res, -EINVAL);
		val = strtoul(res, NULL, base);
		if (val > 255)
			return -EINVAL;
		opts->ipaddr[i] = (uint8_t)val;
		res = strtok_r(NULL, tok, &saveptr);
	}

	opts->cert.san_ip = opts->ipaddr;
	opts->cert.san_ip_len = i;

out:
	return ret;
}

static int x509_enc_valid_from(struct x509_checker_options *opts,
			       const char *opt_optarg)
{
	unsigned long long val;

	val = strtoull(opt_optarg, NULL, 10);
	if (val == ULLONG_MAX)
		return -ERANGE;

	opts->cert.valid_from = (time64_t)val;

	return 0;
}

static int x509_enc_valid_to(struct x509_checker_options *opts,
			     const char *opt_optarg)
{
	unsigned long long val;

	val = strtoull(opt_optarg, NULL, 10);
	if (val == ULLONG_MAX)
		return -ERANGE;

	opts->cert.valid_to = (time64_t)val;

	return 0;
}

static int x509_enc_subject_cn(struct x509_checker_options *opts,
			       const char *opt_optarg)
{
	size_t len = strlen(opt_optarg);

	if (len > 0xff)
		return -EOVERFLOW;

	opts->cert.subject_segments.cn.value = opt_optarg;
	opts->cert.subject_segments.cn.size = (uint8_t)len;
	return 0;
}

static int x509_enc_issuer_cn(struct x509_checker_options *opts,
			      const char *opt_optarg)
{
	size_t len = strlen(opt_optarg);

	if (len > 0xff)
		return -EOVERFLOW;

	opts->cert.issuer_segments.cn.value = opt_optarg;
	opts->cert.issuer_segments.cn.size = (uint8_t)len;
	return 0;
}

static int x509_enc_serial(struct x509_checker_options *opts,
			   const char *opt_optarg)
{
	int ret;

	if (!opt_optarg)
		return -EINVAL;

	CKINT(hex2bin_alloc(opt_optarg, strlen(opt_optarg), &opts->raw_serial,
			    &opts->raw_serial_size));

	opts->cert.raw_serial = opts->raw_serial;
	opts->cert.raw_serial_size = opts->raw_serial_size;

out:
	return ret;
}

static int x509_enc_crypto_algo(struct x509_checker_options *opts)
{
	struct lc_x509_certificate *gcert = &opts->cert;
	struct lc_x509_key_input_data *key_input_data = &opts->key_input_data;
	struct lc_x509_key_data *keys = &opts->key_data;
	int ret;

	LC_X509_LINK_INPUT_DATA(keys, key_input_data);

	CKINT(lc_x509_keypair_gen(gcert, keys, LC_SIG_DILITHIUM_44));

out:
	return 0;
}

static void asn1_usage(void)
{
	fprintf(stderr, "\nASN.1 Encoder tester\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]... FILE...\n");

	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr,
		"\t   --eku\t\tencode extended key usage (use LC_KEY_EKU_* flags)\n");
	fprintf(stderr,
		"\t   --keyusage\t\tencode key usage (use LC_KEY_USAGE* flags)\n");
	fprintf(stderr,
		"\t   --ca\t\tencode CA basic constraint with criticality\n");
	fprintf(stderr, "\t   --san-dns\t\tencode SAN DNS name\n");
	fprintf(stderr, "\t   --san-ip\t\tencode SAN IP name\n");
	fprintf(stderr, "\t   --skid\t\tencode SKID (in hex form)\n");
	fprintf(stderr, "\t   --akid\t\tencode AKID (in hex form)\n");
	fprintf(stderr, "\t   --valid-from\t\tencode start time\n");
	fprintf(stderr, "\t   --valid-to\t\tencode end time\n");
	fprintf(stderr, "\t   --subject-cn\t\tencode subject CN\n");
	fprintf(stderr, "\t   --issuer-cn\t\tencode subject CN\n");
	fprintf(stderr, "\t   --serial\t\tencode serial numer (in hex form)\n");

	fprintf(stderr, "\t   --check-selfsigned\t\tCheck for self-signed\n");
	fprintf(stderr, "\t   --check-noselfsigned\t\tCheck for self-signed\n");

	fprintf(stderr, "\t-h  --help\t\tPrint this help text\n");
}

int main(int argc, char *argv[])
{
	struct workspace {
		struct x509_checker_options parsed_opts;
	};
	int ret = 0, opt_index = 0;

	static const char *opts_short = "h";
	static const struct option opts[] = { { "help", 0, 0, 'h' },

					      { "eku", 1, 0, 0 },
					      { "ca", 0, 0, 0 },
					      { "san-dns", 1, 0, 0 },
					      { "san-ip", 1, 0, 0 },
					      { "keyusage", 1, 0, 0 },
					      { "skid", 1, 0, 0 },
					      { "akid", 1, 0, 0 },
					      { "valid-from", 1, 0, 0 },
					      { "valid-to", 1, 0, 0 },
					      { "subject-cn", 1, 0, 0 },
					      { "issuer-cn", 1, 0, 0 },
					      { "serial", 1, 0, 0 },

					      { "check-selfsigned", 0, 0, 0 },
					      { "check-noselfsigned", 0, 0, 0 },

					      { 0, 0, 0, 0 } };

	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

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

			/* eku */
			case 1:
				CKINT(x509_enc_eku(&ws->parsed_opts, optarg));
				break;
			/* ca */
			case 2:
				CKINT(x509_enc_ca(&ws->parsed_opts));
				break;
			/* san-dns */
			case 3:
				CKINT(x509_enc_san_dns(&ws->parsed_opts,
						       optarg));
				break;
			/* san-ip */
			case 4:
				CKINT(x509_enc_san_ip(&ws->parsed_opts,
						      optarg));
				break;
			/* keyusage */
			case 5:
				CKINT(x509_enc_keyusage(&ws->parsed_opts,
							optarg));
				break;
			/* skid */
			case 6:
				CKINT(x509_enc_skid(&ws->parsed_opts, optarg));
				break;
			/* akid */
			case 7:
				CKINT(x509_enc_akid(&ws->parsed_opts, optarg));
				break;
			/* valid-from */
			case 8:
				CKINT(x509_enc_valid_from(&ws->parsed_opts,
							  optarg));
				break;
			/* valid-to */
			case 9:
				CKINT(x509_enc_valid_to(&ws->parsed_opts,
							optarg));
				break;
			/* subject-cn */
			case 10:
				CKINT(x509_enc_subject_cn(&ws->parsed_opts,
							  optarg));
				break;
			/* issuer-cn */
			case 11:
				CKINT(x509_enc_issuer_cn(&ws->parsed_opts,
							 optarg));
				break;
			/* serial */
			case 12:
				CKINT(x509_enc_serial(&ws->parsed_opts,
						      optarg));
				break;

			/* check-selfsigned */
			case 13:
				ws->parsed_opts.selfsigned = 1;
				break;
			/* check-selfsigned */
			case 14:
				ws->parsed_opts.noselfsigned = 1;
				break;
			}
			break;

		case 'h':
			asn1_usage();
			goto out;

		default:
			asn1_usage();
			ret = -1;
			goto out;
		}
	}

	CKINT(x509_enc_crypto_algo(&ws->parsed_opts));

	CKINT(x509_gen_cert(&ws->parsed_opts));

out:
	x509_clean_opts(&ws->parsed_opts);
	LC_RELEASE_MEM(ws);
	return -ret;
}
