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

#include <getopt.h>
#include <stdio.h>
#include <sys/stat.h>

#include "asn1.h"
#include "binhexbin.h"
#include "lc_pkcs7_generator.h"
#include "lc_pkcs7_parser.h"
#include "lc_x509_generator.h"
#include "lc_x509_generator_helper.h"
#include "lc_x509_generator_file_helper.h"
#include "ret_checkers.h"
#include "x509_print.h"

struct pkcs7_x509 {
	struct pkcs7_x509 *next;

	struct lc_x509_key_input_data signer_key_input_data;

	uint8_t *x509_data;
	size_t x509_data_len;
	uint8_t *signer_data;
	size_t signer_data_len;
	uint8_t *signer_sk_data;
	size_t signer_sk_data_len;
};

struct pkcs7_generator_opts {
	struct lc_pkcs7_message pkcs7;

	enum lc_sig_types in_key_type;

	const char *outfile;
	const char *infile;
	const char *print_pkcs7_msg;

	const char *x509_file;
	const char *x509_signer_file;
	const char *signer_sk_file;

	const char *trust_anchor;

	uint8_t *data;
	size_t datalen;

	struct lc_pkcs7_trust_store trust_store;
	struct lc_x509_certificate trust_anchor_x509;
	uint8_t *trust_anchor_data;
	size_t trust_anchor_data_len;

	unsigned int print_pkcs7 : 1;
	unsigned int noout : 1;
	unsigned int checker : 1;

	struct pkcs7_x509 *x509;
};

static void pkcs7_clean_opts(struct pkcs7_generator_opts *opts)
{
	struct pkcs7_x509 *x509;

	if (!opts)
		return;

	x509 = opts->x509;
	while (x509) {
		struct pkcs7_x509 *tmp_x509 = x509->next;

		release_data(x509->x509_data, x509->x509_data_len);
		release_data(x509->signer_sk_data, x509->signer_sk_data_len);
		release_data(x509->signer_data, x509->signer_data_len);

		lc_free(x509);

		x509 = tmp_x509;
	}

	opts->x509 = NULL;

	release_data(opts->data, opts->datalen);

	release_data(opts->trust_anchor_data, opts->trust_anchor_data_len);
	lc_pkcs7_trust_store_clear(&opts->trust_store);
	lc_x509_cert_clear(&opts->trust_anchor_x509);

	lc_pkcs7_message_clear(&opts->pkcs7);
	lc_memset_secure(opts, 0, sizeof(*opts));
}

static int pkcs7_check_file(const char *file)
{
	struct stat sb;

	if (!file)
		return -EINVAL;

	if (!stat(file, &sb)) {
		printf("File %s exists - reject to overwrite it\n", file);
		return -EEXIST;
	}

	return 0;
}

static int pkcs7_gen_file(struct pkcs7_generator_opts *opts,
			  const uint8_t *certdata, size_t certdata_len)
{
	FILE *f = NULL;
	size_t written;
	int ret = 0;

	if (opts->noout)
		return 0;

	CKNULL(opts->outfile, -EINVAL);

	CKINT(pkcs7_check_file(opts->outfile));

	f = fopen(opts->outfile, "w");
	CKNULL(f, -errno);

	written = fwrite(certdata, 1, certdata_len, f);
	if (written != certdata_len) {
		printf("Writing of X.509 certificate data failed: %zu bytes written, %zu bytes to write\n",
		       written, certdata_len);
		ret = -EFAULT;
		goto out;
	}

out:
	if (f)
		fclose(f);
	return ret;
}

static int pkcs_add_trust(struct pkcs7_generator_opts *opts)
{
	int ret = 0;

	/* If we have no trust anchor, ignore */
	CKNULL(opts->trust_anchor, 0);

	if (!opts->trust_anchor_data) {
		CKINT_LOG(get_data(opts->trust_anchor, &opts->trust_anchor_data,
				   &opts->trust_anchor_data_len),
			  "Loading of file %s failed\n", opts->trust_anchor);

		CKINT_LOG(lc_x509_cert_parse(&opts->trust_anchor_x509,
					     opts->trust_anchor_data,
					     opts->trust_anchor_data_len),
			  "Loading of X.509 trust anchor certificate failed\n");

		CKINT(lc_pkcs7_trust_store_add(&opts->trust_store,
					       &opts->trust_anchor_x509));
	}

out:
	return ret;
}

static int pkcs7_enc_dump(struct pkcs7_generator_opts *opts,
			  const uint8_t *pkcs7_data, size_t pkcs7_datalen)
{
	struct lc_pkcs7_message ppkcs7 = { 0 };
	int ret;

	if (!opts->print_pkcs7 && !opts->checker)
		return 0;

	CKINT(lc_pkcs7_message_parse(&ppkcs7, pkcs7_data, pkcs7_datalen));

	if (opts->data) {
		CKINT(lc_pkcs7_set_data(&ppkcs7, opts->data, opts->datalen, 0));
	}

	CKINT(pkcs_add_trust(opts));
	CKINT_LOG(lc_pkcs7_verify(&ppkcs7, &opts->trust_store),
		  "Verification of PKCS#7 message failed\n");

	//if (opts->checker)
	//	CKINT(apply_checks_pkcs7(&ppkcs7, &opts->checker_opts));

	if (opts->print_pkcs7) {
		CKINT(print_pkcs7_data(&ppkcs7));
	}

out:
	lc_pkcs7_message_clear(&ppkcs7);
	return ret;
}

static int pkcs7_dump_file(struct pkcs7_generator_opts *opts)
{
	struct lc_pkcs7_message ppkcs7 = { 0 };
	uint8_t *pkcs7_data = NULL;
	size_t pkcs7_datalen = 0;
	int ret;

	if (!opts->print_pkcs7_msg && !opts->checker)
		return 0;

	CKINT_LOG(get_data(opts->print_pkcs7_msg, &pkcs7_data, &pkcs7_datalen),
		  "Loading of file %s failed\n", opts->print_pkcs7_msg);

	CKINT_LOG(lc_pkcs7_message_parse(&ppkcs7, pkcs7_data, pkcs7_datalen),
		  "Parsing of input file %s failed\n", opts->print_pkcs7_msg);

	if (opts->data) {
		CKINT(lc_pkcs7_set_data(&ppkcs7, opts->data, opts->datalen, 0));
	}

	CKINT(pkcs_add_trust(opts));
	CKINT_LOG(lc_pkcs7_verify(&ppkcs7, &opts->trust_store),
		  "Verification of PKCS#7 message failed\n");

	//	if (opts->checker)
	//		CKINT(apply_checks_pkcs7(&ppkcs7, &opts->checker_opts));

	if (opts->print_pkcs7_msg)
		CKINT(print_pkcs7_data(&ppkcs7));

out:
	lc_memset_secure(&ppkcs7, 0, sizeof(ppkcs7));
	release_data(pkcs7_data, pkcs7_datalen);
	return ret;
}

static int pkcs7_gen_message(struct pkcs7_generator_opts *opts)
{
	struct lc_pkcs7_message *pkcs7 = &opts->pkcs7;
	uint8_t data[ASN1_MAX_DATASIZE] = { 0 };
	size_t avail_datalen = sizeof(data), datalen;
	int ret;

	CKINT(lc_pkcs7_generate(pkcs7, data, &avail_datalen));
	datalen = sizeof(data) - avail_datalen;

	if (!opts->outfile)
		bin2print(data, datalen, stdout, "PKCS7 Message");

	CKINT_LOG(pkcs7_gen_file(opts, data, datalen),
		  "Writing of X.509 certificate failed\n");

	CKINT(pkcs7_enc_dump(opts, data, datalen));

out:
	return ret;
}

static void pkcs7_add_x509(struct pkcs7_generator_opts *opts,
			   struct pkcs7_x509 *x509)
{
	struct pkcs7_x509 *tmp_x509;

	x509->next = NULL;

	if (!opts->x509) {
		opts->x509 = x509;
		return;
	}

	for (tmp_x509 = opts->x509; tmp_x509; tmp_x509 = tmp_x509->next) {
		if (!tmp_x509->next) {
			tmp_x509->next = x509;
			return;
		}
	}
}

static int pkcs7_load_signer(struct pkcs7_generator_opts *opts)
{
	struct lc_pkcs7_message *pkcs7 = &opts->pkcs7;
	struct pkcs7_x509 *x509;
	struct lc_x509_key_input_data *signer_key_input_data;
	struct lc_x509_certificate *newcert = NULL;
	int ret;

	CKNULL_LOG(opts->x509_signer_file, -EINVAL,
		   "A X.509 signer certificate is required\n");
	CKNULL_LOG(opts->signer_sk_file, -EINVAL,
		   "A X.509 signer secret key is required\n");

	CKINT(lc_alloc_aligned((void **)&x509, 8, sizeof(struct pkcs7_x509)));

	pkcs7_add_x509(opts, x509);

	signer_key_input_data = &x509->signer_key_input_data;

	CKINT_LOG(get_data(opts->x509_signer_file, &x509->signer_data,
			   &x509->signer_data_len),
		  "mmap failure\n");
	CKINT_LOG(get_data(opts->signer_sk_file, &x509->signer_sk_data,
			   &x509->signer_sk_data_len),
		  "Signer SK mmap failure\n");

	CKINT(lc_alloc_aligned((void **)&newcert, 8,
			       sizeof(struct lc_x509_certificate)));

	/* Parse the X.509 certificate */
	CKINT(lc_x509_cert_parse(newcert, x509->signer_data,
				 x509->signer_data_len));

	/* Set the private key to the newly create certificate */
	CKINT(lc_x509_cert_set_signer(newcert, signer_key_input_data, newcert,
				      x509->signer_sk_data,
				      x509->signer_sk_data_len));

	CKINT(lc_pkcs7_set_signer(pkcs7, newcert));

	newcert = NULL;

out:
	lc_free(newcert);
	return ret;
}

static int pkcs7_load_cert(struct pkcs7_generator_opts *opts)
{
	struct lc_pkcs7_message *pkcs7 = &opts->pkcs7;
	struct lc_x509_certificate *newcert = NULL;
	struct pkcs7_x509 *x509;
	int ret;

	CKNULL(opts->x509_file, 0);

	CKINT(lc_alloc_aligned((void **)&x509, 8, sizeof(struct pkcs7_x509)));

	pkcs7_add_x509(opts, x509);

	CKINT(get_data(opts->x509_file, &x509->x509_data,
		       &x509->x509_data_len));

	CKINT(lc_alloc_aligned((void **)&newcert, 8,
			       sizeof(struct lc_x509_certificate)));

	/* Parse the X.509 certificate */
	CKINT_LOG(lc_x509_cert_parse(newcert, x509->x509_data,
				     x509->x509_data_len),
		  "Loading of X.509 certificate failed\n");

	/*
	 * Add the certificate to the PKCS#7 structure for being added to the
	 * PKCS#7 message to be generated.
	 */
	CKINT_LOG(lc_pkcs7_set_certificate(pkcs7, newcert),
		  "Adding loaded X.509 certificate to PKCS#7 message failed\n");

	newcert = NULL;

out:
	lc_free(newcert);
	return ret;
}

static int pkcs7_set_data(struct pkcs7_generator_opts *opts)
{
	struct lc_pkcs7_message *pkcs7 = &opts->pkcs7;
	int ret;

	CKNULL_LOG(opts->infile, -EINVAL,
		   "Data file to be protected missing\n");

	CKINT_LOG(get_data(opts->infile, &opts->data, &opts->datalen),
			  "Loading of file %s failed\n", opts->infile);

	CKINT(lc_pkcs7_set_data(pkcs7, opts->data, opts->datalen, 0));

out:
	return ret;
}

static void pkcs7_generator_usage(void)
{
	fprintf(stderr, "\nLeancrypto X.509 Certificate Generator\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]\n");

	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr,
		"\t-o --outfile <FILE>\t\tFile to write certificate to\n");
	fprintf(stderr,
		"\t-i --infile <FILE>\t\tFile with data to be protected\n");

	fprintf(stderr, "\n\tOptions for X.509 signer:\n");
	fprintf(stderr,
		"\t   --x509-signer <FILE>\t\tX.509 certificate of signer\n");
	fprintf(stderr, "\t\t\t\t\t\tIf not set, create a self-signed\n");
	fprintf(stderr, "\t\t\t\t\t\tcertificate\n");
	fprintf(stderr,
		"\t   --signer-sk-file <FILE>\t\tFile with signer secret\n");

	fprintf(stderr, "\n\tOptions for additional X.509:\n");
	fprintf(stderr,
		"\t   --x509-cert <FILE>\t\tX.509 additional certificate\n");

	fprintf(stderr,
		"\n\tOptions for analyzing generated / loaded PKCS#7 messages:\n");
	fprintf(stderr,
		"\t   --print\t\t\tParse the generated PKCS#7 message and\n");
	fprintf(stderr, "\t\t\t\t\t print its contents\n");
	fprintf(stderr,
		"\t   --print-pkcs7 <FILE>\t\tParse the PKCS#7 message and\n");
	fprintf(stderr, "\t\t\t\t\tprint its contents\n");
	fprintf(stderr, "\t   --noout\t\t\tNo generation of output files\n");
	fprintf(stderr,
		"\t   --trust-anchor <FILE>\t\tTrust anchor X.509 certificate\n");

	fprintf(stderr, "\n\t-h  --help\t\t\tPrint this help text\n");
}

static int pkcs7_collect_signer(struct pkcs7_generator_opts *opts)
{
	int ret;

	CKNULL(opts->x509_signer_file, 0);
	CKNULL(opts->signer_sk_file, 0);

	CKINT(pkcs7_load_signer(opts));

	opts->x509_signer_file = NULL;
	opts->signer_sk_file = NULL;

out:
	return ret;
}

static int pkcs7_collect_x509(struct pkcs7_generator_opts *opts)
{
	int ret;

	CKNULL(opts->x509_file, 0);

	CKINT(pkcs7_load_cert(opts));

	opts->x509_file = NULL;

out:
	return ret;
}

int main(int argc, char *argv[])
{
	struct pkcs7_generator_opts parsed_opts = { 0 };
	int ret = 0, opt_index = 0;

	static const char *opts_short = "ho:i:";
	static const struct option opts[] = { { "help", 0, 0, 'h' },

					      { "outfile", 1, 0, 'o' },
					      { "infile", 1, 0, 'i' },

					      { "x509-signer", 1, 0, 0 },
					      { "signer-sk-file", 1, 0, 0 },
					      { "x509-cert", 1, 0, 0 },

					      { "print", 0, 0, 0 },
					      { "noout", 0, 0, 0 },
					      { "print-x509", 1, 0, 0 },
					      { "trust-anchor", 1, 0, 0 },

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
				pkcs7_generator_usage();
				goto out;

			/* outfile */
			case 1:
				CKINT(pkcs7_check_file(optarg));
				parsed_opts.outfile = optarg;
				break;
			/* outfile */
			case 2:
				parsed_opts.infile = optarg;
				break;

			/* x509-signer */
			case 3:
				parsed_opts.x509_signer_file = optarg;
				CKINT(pkcs7_collect_signer(&parsed_opts));
				break;
			/* signer-sk-file */
			case 4:
				parsed_opts.signer_sk_file = optarg;
				CKINT(pkcs7_collect_signer(&parsed_opts));
				break;

			/* x509-cert */
			case 5:
				parsed_opts.x509_file = optarg;
				CKINT(pkcs7_collect_x509(&parsed_opts));
				break;

			/* print */
			case 6:
				parsed_opts.print_pkcs7 = 1;
				break;
			/* noout */
			case 7:
				parsed_opts.noout = 1;
				break;
			/* print-pkcs7 */
			case 8:
				parsed_opts.print_pkcs7_msg = optarg;
				break;
			/* trust-anchor */
			case 9:
				parsed_opts.trust_anchor = optarg;
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

		default:
			pkcs7_generator_usage();
			ret = -1;
			goto out;
		}
	}

	if (parsed_opts.print_pkcs7_msg) {
		CKINT(pkcs7_dump_file(&parsed_opts));
		goto out;
	}

	CKINT(pkcs7_set_data(&parsed_opts));
	CKINT(pkcs7_gen_message(&parsed_opts));

out:
	pkcs7_clean_opts(&parsed_opts);
	return -ret;
}
