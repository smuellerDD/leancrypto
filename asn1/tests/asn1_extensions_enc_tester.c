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
#include <string.h>
#include <time.h>

#include "asn1_encoder.h"
#include "asn1_decoder.h"
#include "binhexbin.h"
#include "lc_dilithium.h"
#include "lc_sha3.h"
#include "lc_x509_generator.h"
#include "lc_x509_parser.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509.asn1.h"
#include "x509_akid.asn1.h"
#include "x509_basic_constraints.asn1.h"
#include "x509_eku.asn1.h"
#include "x509_extensions_test.asn1.h"
#include "x509_cert_generator.h"
#include "x509_cert_parser.h"

struct x509_checker_options {
	struct lc_x509_certificate cert;
	uint8_t ipaddr[16];
	uint8_t *raw_skid;
	size_t raw_skid_size;
	uint8_t *raw_akid;
	size_t raw_akid_size;
	uint8_t *raw_serial;
	size_t raw_serial_size;
};

static int x509_gen_cert_extensions(struct x509_checker_options *opts)
{
#define DATASIZE 1024
	struct workspace {
		struct lc_x509_certificate pcert;
		struct x509_parse_context pctx;
		struct x509_generate_context gctx;
		uint8_t data[DATASIZE];
	};
	struct lc_x509_certificate *gcert = &opts->cert;
	size_t avail_datalen = DATASIZE, datalen;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	printf("In-Key Usage: %u\n", gcert->pub.key_usage);
	printf("In-EKU: %u\n", gcert->pub.key_eku);
	printf("In-CA: %u\n", gcert->pub.ca_pathlen);
	printf("In-SAN-DNS: %s\n", gcert->san_dns ? gcert->san_dns : "(unset)");
	if (gcert->san_ip) {
		bin2print(gcert->san_ip, gcert->san_ip_len, stdout,
			  "In-SAN IP");
	}
	if (gcert->raw_skid) {
		bin2print(gcert->raw_skid, gcert->raw_skid_size, stdout,
			  "SKID");
	}

	/* Encode the input data */
	ws->gctx.cert = &opts->cert;
	CKINT(asn1_ber_encoder(&x509_extensions_test_encoder, &ws->gctx,
			       ws->data, &avail_datalen));
	datalen = DATASIZE - avail_datalen;

	bin2print(ws->data, datalen, stdout, "X.509 extension");

	/* Decode the just encoded data into new output structure */
	ws->pctx.cert = &ws->pcert;
	CKINT(asn1_ber_decoder(&x509_extensions_test_decoder, &ws->pctx,
			       ws->data, datalen));

	if (gcert->raw_akid_size) {
		CKINT(asn1_ber_decoder(&x509_akid_decoder, &ws->pctx,
				       ws->pctx.raw_akid,
				       ws->pctx.raw_akid_size));
	}

	/*
	 * Remove the present flag for the comparison as this is artificially
	 * added by the parser.
	 */
	ws->pcert.pub.key_usage &= (uint16_t)~(LC_KEY_USAGE_EXTENSION_PRESENT);
	printf("Out-Key Usage: %u\n", ws->pcert.pub.key_usage);

	if (gcert->pub.key_usage != ws->pcert.pub.key_usage) {
		printf("Key Usage mismatch: original %u, parsed %u\n",
		       gcert->pub.key_usage, ws->pcert.pub.key_usage);
		ret = -EINVAL;
	}

	/*
	 * Remove the present flag for the comparison as this is artificially
	 * added by the parser.
	 */
	ws->pcert.pub.key_eku &= (uint16_t)~LC_KEY_EKU_EXTENSION_PRESENT;
	printf("Out-EKU: %u\n", ws->pcert.pub.key_eku);

	if (gcert->pub.key_eku != ws->pcert.pub.key_eku) {
		printf("EKU mismatch: original EKU %u, parsed EKU %u\n",
		       gcert->pub.key_eku, ws->pcert.pub.key_eku);
		ret = -EINVAL;
	}

	printf("Out-CA: %u\n", ws->pcert.pub.ca_pathlen);
	if (gcert->pub.ca_pathlen != ws->pcert.pub.ca_pathlen) {
		printf("CA mismatch: original CA %u, parsed CA %u\n",
		       gcert->pub.ca_pathlen, ws->pcert.pub.ca_pathlen);
		ret = -EINVAL;
	}

	if (ws->pcert.san_dns_len != gcert->san_dns_len) {
		printf("SAN DNS name length mismatch (original %zu, received %zu)\n",
		       gcert->san_dns_len, ws->pcert.san_dns_len);
		ret = -EINVAL;
	} else {
		if (memcmp(ws->pcert.san_dns, gcert->san_dns,
			   gcert->san_dns_len)) {
			printf("SAN DNS name mismatch (original %s, received %s)\n",
			       gcert->san_dns, ws->pcert.san_dns);
			ret = -EINVAL;
		} else {
			printf("SAN DNS name matches\n");
		}
	}

	if (ws->pcert.san_ip_len != gcert->san_ip_len) {
		printf("SAN IP name length mismatch (original %zu, received %zu)\n",
		       gcert->san_ip_len, ws->pcert.san_ip_len);
		ret = -EINVAL;
	} else {
		if (memcmp(ws->pcert.san_ip, gcert->san_ip,
			   gcert->san_ip_len)) {
			bin2print(gcert->san_ip, gcert->san_ip_len, stdout,
				  "SAN IP mismatch original");
			bin2print(ws->pcert.san_ip, ws->pcert.san_ip_len,
				  stdout, "SAN IP mismatch received");
			ret = -EINVAL;
		} else {
			printf("SAN IP name matches\n");
		}
	}

	if (gcert->raw_skid_size == 0 &&
	    ws->pcert.raw_skid_size == LC_X509_SKID_DEFAULT_HASHSIZE) {
		printf("New SKID created\n");
	} else if (ws->pcert.raw_skid_size != gcert->raw_skid_size) {
		printf("SKID name length mismatch (original %zu, received %zu)\n",
		       gcert->raw_skid_size, ws->pcert.raw_skid_size);
		ret = -EINVAL;
	} else {
		if (memcmp(ws->pcert.raw_skid, gcert->raw_skid,
			   gcert->raw_skid_size)) {
			bin2print(gcert->raw_skid, gcert->raw_skid_size, stdout,
				  "SKID mismatch original");
			bin2print(ws->pcert.raw_skid, ws->pcert.raw_skid_size,
				  stdout, "SKID mismatch received");
			ret = -EINVAL;
		} else {
			printf("SKID name matches\n");
		}
	}

	if (ws->pcert.raw_akid_size != gcert->raw_akid_size) {
		printf("AKID name length mismatch (original %zu, received %zu)\n",
		       gcert->raw_akid_size, ws->pcert.raw_akid_size);
		ret = -EINVAL;
	} else {
		if (memcmp(ws->pcert.raw_akid, gcert->raw_akid,
			   gcert->raw_akid_size)) {
			bin2print(gcert->raw_akid, gcert->raw_akid_size, stdout,
				  "AKID mismatch original");
			bin2print(ws->pcert.raw_akid, ws->pcert.raw_akid_size,
				  stdout, "AKID mismatch received");
			ret = -EINVAL;
		} else {
			printf("AKID name matches\n");
		}
	}

out:
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
	opts->cert.pub.ca_pathlen = LC_KEY_CA_CRITICAL | LC_KEY_CA_MAXLEN;

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
	opts->cert.sig.pkey_algo = LC_SIG_DILITHIUM_44;
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

	//TODO
	CKINT(x509_enc_crypto_algo(&ws->parsed_opts));

	CKINT(x509_gen_cert_extensions(&ws->parsed_opts));

out:
	x509_clean_opts(&ws->parsed_opts);
	LC_RELEASE_MEM(ws);
	return -ret;
}
