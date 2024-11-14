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
#include "lc_x509_generator.h"
#include "lc_x509_parser.h"
#include "ret_checkers.h"
#include "x509_eku.asn1.h"
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

static int x509_gen_cert_eku(struct x509_checker_options *opts)
{
	struct lc_x509_certificate pcert = { 0 };
	struct lc_x509_certificate *gcert = &opts->cert;
	struct x509_parse_context pctx = { 0 };
	struct x509_generate_context gctx = { 0 };
	uint8_t data[1024] = { 0 };
	size_t avail_datalen = sizeof(data), datalen;
	int ret;

	printf("In-EKU: %u\n", gcert->pub.key_eku);
	gctx.cert = gcert;
	CKINT(asn1_ber_encoder(&x509_eku_encoder, &gctx, data, &avail_datalen));
	datalen = sizeof(data) - avail_datalen;

	/* 300a06082b06010505070301 */
	bin2print(data, datalen, stdout, "EKU");

	/* Decode the just encoded data into new output structure */
	pctx.cert = &pcert;
	CKINT(asn1_ber_decoder(&x509_eku_decoder, &pctx, data, datalen));

	/*
	 * Remove the present flag for the comparison as this is artificially
	 * added by the parser.
	 */
	pcert.pub.key_eku &= (uint16_t)~LC_KEY_EKU_EXTENSION_PRESENT;
	printf("Out-EKU: %u\n", pcert.pub.key_eku);

	if (gcert->pub.key_eku != pcert.pub.key_eku) {
		printf("EKU mismatch: original EKU %u, parsed EKU %u\n",
		       gcert->pub.key_eku, pcert.pub.key_eku);
		ret = -EINVAL;
	}

out:
	return ret;
}

static int x509_enc_eku(struct x509_checker_options *opts, const char *opt_optarg)
{
	unsigned long val;

	val = strtoul(opt_optarg, NULL, 10);
	if (val == USHRT_MAX)
		return -ERANGE;

	opts->cert.pub.key_eku = (uint16_t)val;

	return 0;
}

static void asn1_usage(void)
{
	fprintf(stderr,
		"\nASN.1 Encoder tester - ONLY ONE EKU flag is processed\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]... FILE...\n");

	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr,
		"\t   --eku\t\tencode extended key usage (use LC_KEY_EKU_* flags)\n");

	fprintf(stderr, "\t-h  --help\t\tPrint this help text\n");
}

int main(int argc, char *argv[])
{
	struct x509_checker_options parsed_opts = { 0 };
	int ret = 0, opt_index = 0;

	static const char *opts_short = "h";
	static const struct option opts[] = { { "help", 0, 0, 'h' },

					      { "eku", 1, 0, 0 },

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

			/* eku */
			case 1:
				CKINT(x509_enc_eku(&parsed_opts, optarg));
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

	CKINT(x509_gen_cert_eku(&parsed_opts));

out:
	return -ret;
}
