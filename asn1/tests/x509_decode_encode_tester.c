/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include "binhexbin.h"
#include "lc_memcmp_secure.h"
#include "lc_pkcs8_generator.h"
#include "lc_pkcs8_parser.h"
#include "lc_x509_generator.h"
#include "lc_x509_parser.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "status_algorithms.h"
#include "x509_print.h"

#include "../../apps/src/lc_x509_generator_file_helper.h"

#define DATASIZE 65536

struct x509_generator_opts {
	struct lc_x509_certificate cert;
	struct lc_x509_certificate cert_tmp;
	struct lc_pkcs8_message pkcs8;

	uint8_t scratchbuffer[DATASIZE];

	const char *sk_file;
	const char *x509_cert_file;

	uint8_t *sk_data;
	size_t sk_len;
	uint8_t *x509_cert_data;
	size_t x509_cert_data_len;

	unsigned int sk_is_pkcs8 : 1;
};

static int x509_sk_encode(struct x509_generator_opts *opts,
			  struct lc_x509_key_data *keys, uint8_t *data,
			  size_t *avail_datalen)
{
	int ret;

	if (opts->sk_is_pkcs8) {
		struct lc_pkcs8_message pkcs8;

		CKINT(lc_pkcs8_set_privkey(&pkcs8, keys));
		CKINT(lc_pkcs8_encode(&pkcs8, data, avail_datalen));
	} else {
		CKINT(lc_x509_sk_encode(keys, data, avail_datalen));
	}

out:
	return ret;
}

static int x509_sk_decode(struct x509_generator_opts *opts,
			  struct lc_x509_key_data *keys,
			  enum lc_sig_types pkey_type, const uint8_t *data,
			  size_t datalen)
{
	int ret;

	/*
	 * The input data can be either a plain buffer string of encoded
	 * private key or a PKCS#8 buffer. This function therefore tries to
	 * parse the data in both ways with the PKCS#8 first, as it has more
	 * stringent format checks.
	 */
	CKINT(lc_pkcs8_set_privkey(&opts->pkcs8, keys));
	ret = lc_pkcs8_decode(&opts->pkcs8, data, datalen);

	if (!ret) {
		opts->sk_is_pkcs8 = 1;
		return 0;
	}

	CKINT(lc_x509_sk_decode(keys, pkey_type, data, datalen));

out:
	return ret;
}

static void x509_clean_opts(struct x509_generator_opts *opts)
{
	if (!opts)
		return;

	lc_x509_cert_clear(&opts->cert);
	lc_x509_cert_clear(&opts->cert_tmp);
	lc_pkcs8_message_clear(&opts->pkcs8);

	release_data(opts->sk_data, opts->sk_len, lc_pem_flag_nopem);
	release_data(opts->x509_cert_data, opts->x509_cert_data_len,
		     lc_pem_flag_nopem);
}

static int x509_enc_set_key(struct x509_generator_opts *opts)
{
	struct lc_x509_certificate *cert = &opts->cert;
	size_t scratchbuflen = DATASIZE;
	int ret = 0;
#ifdef LC_MEM_ON_HEAP
	struct lc_x509_key_data *keys;

	CKINT(lc_x509_privkeys_alloc(&keys));
#else
	LC_X509_PRIVKEYS_ON_STACK(keys);
#endif

	/* Caller set X.509 certificate, perhaps for signing. */

	/* Secret key must be present */
	CKNULL_LOG(opts->sk_file, -EINVAL,
		   "Secret key corresponding to certificate missing\n");

	/* Access the X.509 certificate file */
	CKINT_LOG(get_data(opts->x509_cert_file, &opts->x509_cert_data,
			   &opts->x509_cert_data_len, lc_pem_flag_nopem),
		  "X.509 certificate mmap failure\n");

	/* Parse the X.509 certificate */
	CKINT_LOG(lc_x509_cert_decode(cert, opts->x509_cert_data,
				      opts->x509_cert_data_len),
		  "Loading of X.509 certificate failed\n");

	/* Access the secret key file */
	CKINT_LOG(get_data(opts->sk_file, &opts->sk_data, &opts->sk_len,
			   lc_pem_flag_nopem),
		  "Secret key mmap failure\n");
	/* Parse the secret key */
	CKINT_LOG(x509_sk_decode(opts, keys, cert->pub.pkey_algo,
				 opts->sk_data, opts->sk_len),
		  "Parsing of secret key failed\n");

	/*
	 * Load the secret key into the certificate for self-signing of the
	 * certificate during encoding. As we do not need the public key here,
	 * make sure its pointer is not set.
	 */
	CKINT(lc_x509_keypair_load(cert, keys));

	CKINT_LOG(lc_x509_cert_encode(cert, opts->scratchbuffer,
				      &scratchbuflen),
		  "X.509 certificate encoding failed\n");
	scratchbuflen = DATASIZE - scratchbuflen;

	/*
	 * NOTE: This check only works for self-signed certificates as otherwise
	 * we cannot re-establish the signature as we do not have the signing
	 * key.
	 */
	if (scratchbuflen != opts->x509_cert_data_len) {
		struct lc_x509_certificate *cert_tmp = &opts->cert_tmp;

		printf("Re-encoded X.509 certificate size %zu does not match originial buffer size %zu\n",
		       scratchbuflen, opts->x509_cert_data_len);

		printf("Original certificate:\n");
		print_x509_cert(cert);

		CKINT_LOG(lc_x509_cert_decode(cert_tmp, opts->scratchbuffer,
					      scratchbuflen),
			  "Loading of X.509 certificate failed\n");

		printf("Newly encoded certificate:\n");
		print_x509_cert(cert_tmp);

		ret = -EFAULT;
		goto out;
	}

	scratchbuflen = DATASIZE;
	CKINT_LOG(x509_sk_encode(opts, keys, opts->scratchbuffer,
				 &scratchbuflen),
		  "Secret key encoding failed\n");
	scratchbuflen = DATASIZE - scratchbuflen;

	if (lc_memcmp_secure(opts->sk_data, opts->sk_len, opts->scratchbuffer,
			     scratchbuflen)) {
		printf("Re-encoded secret key with size %zu does not match originial buffer with size %zu\n",
		       scratchbuflen, opts->sk_len);
		ret = -EFAULT;
		goto out;
	}

out:
#ifdef LC_MEM_ON_HEAP
	lc_x509_keys_zero_free(keys);
#else
	lc_x509_keys_zero(keys);
#endif
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

static void x509_generator_usage(void)
{
	fprintf(stderr, "\nLeancrypto X.509 Decapsulate Encapsulate Tester\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]\n");

	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr,
		"\t   --sk-file <FILE>\t\tFile with secret key used for signature\n");
	fprintf(stderr, "\t   --x509-cert <FILE>\t\tCertificate for signing\n");

	fprintf(stderr, "\n\t-h  --help\t\t\tPrint this help text\n");
}

int main(int argc, char *argv[])
{
	struct workspace {
		struct x509_generator_opts parsed_opts;
	};
	int ret = 0, opt_index = 0;

	static const char *opts_short = "h";
	static const struct option opts[] = { { "help", 0, 0, 'h' },

					      { "sk-file", 1, 0, 0 },
					      { "x509-cert", 1, 0, 0 },

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
				x509_generator_usage();
				goto out;

			/* sk-file */
			case 1:
				ws->parsed_opts.sk_file = optarg;
				break;
			/* x509-cert */
			case 2:
				ws->parsed_opts.x509_cert_file = optarg;
				break;

			default:
				x509_generator_usage();
				ret = -1;
				goto out;
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

	CKINT(x509_enc_crypto_algo(&ws->parsed_opts));

out:
	x509_clean_opts(&ws->parsed_opts);
	LC_RELEASE_MEM(ws);
	return -ret;
}
