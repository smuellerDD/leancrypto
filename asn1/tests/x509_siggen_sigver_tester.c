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
#include <sys/stat.h>
#include <time.h>

#include "asn1_test_helper.h"
#include "lc_x509_generator.h"
#include "lc_x509_parser.h"
#include "../../apps/src/lc_x509_generator_helper.h"
#include "ret_checkers.h"

struct x509_generator_opts {
	struct lc_x509_certificate cert;
	struct lc_x509_key_data key_data;
	struct lc_x509_key_input_data key_input_data;

	const char *sk_file;
	const char *x509_cert_file;

	uint8_t *sk_data;
	size_t sk_len;
	uint8_t *x509_cert_data;
	size_t x509_cert_data_len;
};

static void x509_clean_opts(struct x509_generator_opts *opts)
{
	if (!opts)
		return;

	lc_x509_cert_clear(&opts->cert);

	release_data(opts->sk_data, opts->sk_len);
	release_data(opts->x509_cert_data, opts->x509_cert_data_len);

	lc_memset_secure(opts, 0, sizeof(*opts));
}

static int x509_enc_set_key(struct x509_generator_opts *opts)
{
	struct lc_x509_certificate *gcert = &opts->cert;
	struct lc_x509_key_input_data *key_input_data = &opts->key_input_data;
	struct lc_x509_key_data *keys = &opts->key_data;
	int ret = 0;

	LC_X509_LINK_INPUT_DATA(keys, key_input_data);

	/* Caller set X.509 certificate, perhaps for signing. */

	/* Secret key must be present */
	CKNULL_LOG(opts->sk_file, -EINVAL,
		   "Secret key corresponding to certificate missing\n");

	/* Access the X.509 certificate file */
	CKINT_LOG(get_data(opts->x509_cert_file, &opts->x509_cert_data,
			   &opts->x509_cert_data_len),
		  "X.509 certificate mmap failure\n");
	/* Parse the X.509 certificate */
	CKINT_LOG(lc_x509_cert_parse(gcert, opts->x509_cert_data,
				     opts->x509_cert_data_len),
		  "Loading of X.509 certificate failed\n");

	/* Access the X.509 certificate file */
	CKINT_LOG(get_data(opts->sk_file, &opts->sk_data,
				&opts->sk_len),
			"Secret key mmap failure\n");
	/* Parse the X.509 secret key */
	CKINT_LOG(lc_x509_sk_parse(keys, gcert->pub.pkey_algo,
					opts->sk_data, opts->sk_len),
			"Parsing of secret key failed\n");


out:
	return ret;
}

static int x509_enc_crypto_algo(struct x509_generator_opts *opts)
{
	int ret;

	if (!opts->sk_file) {
		printf("A secret key file for the generation the signature is missing!\n");
		return -EINVAL;
	}

	if (!opts->x509_cert_file) {
		printf("A public key file for the generation the X.509 certificate is missing as no key pair shall be generated!\n");
		return -EINVAL;
	}

	/*
	 * Set the public key
	 */
	CKINT_LOG(x509_enc_set_key(opts),
		  "Setting X.509 public key / secret key failed\n");

out:
	return ret;
}

static int x509_sign_data(struct x509_generator_opts *opts)
{
	const struct lc_x509_certificate *cert = &opts->cert;
	const struct lc_x509_key_data *key_data = &opts->key_data;
	static const uint8_t data[] = { 0x01, 0x02, 0x03 };
	size_t siglen;
	uint8_t *sigptr = NULL;
	int ret;

	CKINT(lc_x509_get_signature_size_from_sk(&siglen, key_data));

	CKINT(lc_alloc_aligned((void **)&sigptr, 8, siglen));

	CKINT(lc_x509_gen_signature(sigptr, &siglen, key_data, data,
				    sizeof(data), NULL));

	/* Successful verification */
	CKINT_LOG(lc_x509_verify_signature(sigptr, siglen, cert, data,
					   sizeof(data), NULL),
		  "Verification of data failed\n");

	/* Failure */
	sigptr[0] ^= 0x01;
	ret = lc_x509_verify_signature(sigptr, siglen, cert, data, sizeof(data),
				       NULL);
	if (ret != -EBADMSG) {
		  printf("Modification in data not detected\n");
		  ret = -EFAULT;
		  goto out;
	}
	ret = 0;

	bin2print(sigptr, siglen, stdout, "Signature");

out:
	lc_free(sigptr);
	return ret;
}

static void x509_generator_usage(void)
{
	fprintf(stderr, "\nLeancrypto X.509 Siggen Sigver Tester\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]\n");

	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr,
		"\t   --sk-file <FILE>\t\tFile with secret key used for signature\n");
	fprintf(stderr,
		"\t   --x509-cert <FILE>\t\tCertificate for signing\n");

	fprintf(stderr, "\n\t-h  --help\t\t\tPrint this help text\n");
}

int main(int argc, char *argv[])
{
	struct x509_generator_opts parsed_opts = { 0 };
	int ret = 0, opt_index = 0;

	static const char *opts_short = "h";
	static const struct option opts[] = { { "help", 0, 0, 'h' },

					      { "sk-file", 1, 0, 0 },
					      { "x509-cert", 1, 0, 0 },

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
				x509_generator_usage();
				goto out;

			/* sk-file */
			case 1:
				parsed_opts.sk_file = optarg;
				break;
			/* x509-cert */
			case 2:
				parsed_opts.x509_cert_file = optarg;
				break;
			}
			break;

		case 'h':
			x509_generator_usage();
			goto out;

		default:
			x509_generator_usage();
			ret = -1;
			goto out;
		}
	}

	CKINT(x509_enc_crypto_algo(&parsed_opts));

	CKINT(x509_sign_data(&parsed_opts));

out:
	x509_clean_opts(&parsed_opts);
	return -ret;
}
