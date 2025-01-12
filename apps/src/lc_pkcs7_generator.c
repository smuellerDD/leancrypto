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
#include "small_stack_support.h"
#include "x509_checker.h"
#include "x509_print.h"

#ifdef LC_MEM_ON_HEAP
#define PKCS7_ALLOC struct lc_pkcs7_message pkcs7, *pkcs7_msg = &pkcs7;
#define PKCS7_FREE
#else
#define PKCS7_ALLOC LC_PKCS7_MSG_ON_STACK(pkcs7_msg, 1, 4);
#define PKCS7_FREE lc_memset_secure(pkcs7_msg, 0, LC_PKCS7_MSG_SIZE(1, 4));
#endif

struct pkcs7_x509 {
	struct pkcs7_x509 *next;

	struct lc_x509_key_input_data signer_key_input_data;
	struct lc_x509_key_data signer_key_data;
	struct lc_x509_certificate *x509;

	uint8_t *x509_data;
	size_t x509_data_len;
	uint8_t *signer_data;
	size_t signer_data_len;
	uint8_t *signer_sk_data;
	size_t signer_sk_data_len;
};

struct pkcs7_generator_opts {
	struct x509_checker_options checker_opts;
	struct lc_pkcs7_message *pkcs7;
	struct lc_verify_rules verify_rules;

	const struct lc_hash *hash;
	unsigned long aa_set;

	enum lc_sig_types in_key_type;

	const char *outfile;
	const char *infile;
	const char *pkcs7_msg;

	const char *x509_file;
	const char *x509_signer_file;
	const char *signer_sk_file;

	const char *trust_anchor;

	uint8_t *data;
	size_t datalen;

	struct lc_pkcs7_trust_store trust_store;

	unsigned int print_pkcs7 : 1;
	unsigned int noout : 1;
	unsigned int checker : 1;
	unsigned int use_trust_store : 1;
	unsigned int signer_set : 1;
	unsigned int verify_rules_set : 1;

	struct pkcs7_x509 *x509;
};

static void pkcs7_clean_opts(struct pkcs7_generator_opts *opts)
{
	struct pkcs7_x509 *x509;

	if (!opts)
		return;

	lc_pkcs7_trust_store_clear(&opts->trust_store);

	x509 = opts->x509;
	while (x509) {
		struct pkcs7_x509 *tmp_x509 = x509->next;

		release_data(x509->x509_data, x509->x509_data_len);
		release_data(x509->signer_sk_data, x509->signer_sk_data_len);
		release_data(x509->signer_data, x509->signer_data_len);

		lc_x509_cert_clear(x509->x509);
		lc_free(x509->x509);

		lc_free(x509);

		x509 = tmp_x509;
	}

	opts->x509 = NULL;

	release_data(opts->data, opts->datalen);

	lc_pkcs7_message_clear(opts->pkcs7);
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

static int pkcs7_enc_dump(struct pkcs7_generator_opts *opts,
			  const uint8_t *pkcs7_data, size_t pkcs7_datalen)
{
	PKCS7_ALLOC
	int ret;

	if (!opts->print_pkcs7 && !opts->checker)
		return 0;

	CKINT(lc_pkcs7_decode(pkcs7_msg, pkcs7_data, pkcs7_datalen));

	if (opts->data) {
		CKINT(lc_pkcs7_set_data(pkcs7_msg, opts->data, opts->datalen,
					0));
	}

	CKINT_LOG(lc_pkcs7_verify(
			  pkcs7_msg,
			  opts->use_trust_store ? &opts->trust_store : NULL,
			  opts->verify_rules_set ? &opts->verify_rules : NULL),
		  "Verification of PKCS#7 message failed\n");

	if (opts->checker)
		CKINT(apply_checks_pkcs7(pkcs7_msg, &opts->checker_opts));

	if (opts->print_pkcs7) {
		CKINT(print_pkcs7_data(pkcs7_msg));
	}

out:
	lc_pkcs7_message_clear(pkcs7_msg);
	PKCS7_FREE
	return ret;
}

static int pkcs7_dump_file(struct pkcs7_generator_opts *opts)
{
	uint8_t *pkcs7_data = NULL;
	size_t pkcs7_datalen = 0;
	PKCS7_ALLOC
	int ret;

	if (!opts->pkcs7_msg && !opts->checker)
		return 0;

	CKINT_LOG(get_data(opts->pkcs7_msg, &pkcs7_data, &pkcs7_datalen),
		  "Loading of file %s failed\n", opts->pkcs7_msg);

	CKINT_LOG(lc_pkcs7_decode(pkcs7_msg, pkcs7_data, pkcs7_datalen),
		  "Parsing of input file %s failed\n", opts->pkcs7_msg);

	if (opts->data) {
		CKINT(lc_pkcs7_set_data(pkcs7_msg, opts->data, opts->datalen,
					0));
		CKINT_LOG(lc_pkcs7_verify(
				  pkcs7_msg,
				  opts->use_trust_store ? &opts->trust_store :
							  NULL,
				  opts->verify_rules_set ? &opts->verify_rules :
							   NULL),
			  "Verification of PKCS#7 message failed\n");
	}

	if (opts->checker)
		CKINT(apply_checks_pkcs7(pkcs7_msg, &opts->checker_opts));

	if (opts->print_pkcs7)
		CKINT(print_pkcs7_data(pkcs7_msg));

out:
	lc_pkcs7_message_clear(pkcs7_msg);
	release_data(pkcs7_data, pkcs7_datalen);
	PKCS7_FREE
	return ret;
}

static int pkcs7_gen_message(struct pkcs7_generator_opts *opts)
{
	struct workspace {
		uint8_t data[ASN1_MAX_DATASIZE];
	};
	struct lc_pkcs7_message *pkcs7 = opts->pkcs7;
	size_t avail_datalen = ASN1_MAX_DATASIZE, datalen;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKINT_LOG(lc_pkcs7_encode(pkcs7, ws->data, &avail_datalen),
		  "Message generation failed\n");
	datalen = ASN1_MAX_DATASIZE - avail_datalen;

	if (!opts->outfile)
		bin2print(ws->data, datalen, stdout, "PKCS7 Message");

	CKINT_LOG(pkcs7_gen_file(opts, ws->data, datalen),
		  "Writing of X.509 certificate failed\n");

	CKINT_LOG(pkcs7_enc_dump(opts, ws->data, datalen),
		  "Printing of message failed\n");

out:
	LC_RELEASE_MEM(ws);
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
	struct lc_pkcs7_message *pkcs7 = opts->pkcs7;
	struct pkcs7_x509 *x509;
	struct lc_x509_key_input_data *signer_key_input_data;
	struct lc_x509_key_data *signer_key_data;
	struct lc_x509_certificate *newcert = NULL;
	enum lc_sig_types pkey_type;
	int ret;

	CKNULL_LOG(opts->x509_signer_file, -EINVAL,
		   "A X.509 signer certificate is required\n");
	CKNULL_LOG(opts->signer_sk_file, -EINVAL,
		   "A X.509 signer secret key is required\n");

	CKINT(lc_alloc_aligned((void **)&x509, 8, sizeof(struct pkcs7_x509)));

	pkcs7_add_x509(opts, x509);

	signer_key_input_data = &x509->signer_key_input_data;
	signer_key_data = &x509->signer_key_data;

	CKINT_LOG(get_data(opts->x509_signer_file, &x509->signer_data,
			   &x509->signer_data_len),
		  "mmap failure\n");
	CKINT_LOG(get_data(opts->signer_sk_file, &x509->signer_sk_data,
			   &x509->signer_sk_data_len),
		  "Signer SK mmap failure\n");

	CKINT(lc_alloc_aligned((void **)&newcert, 8,
			       sizeof(struct lc_x509_certificate)));
	newcert->allocated = 1;

	/* Parse the X.509 certificate */
	CKINT(lc_x509_cert_decode(newcert, x509->signer_data,
				  x509->signer_data_len));

	/* Set the private key to the newly create certificate */
	LC_X509_LINK_INPUT_DATA(signer_key_data, signer_key_input_data);
	CKINT(lc_x509_cert_get_pubkey(newcert, NULL, NULL, &pkey_type));
	CKINT_LOG(lc_x509_sk_decode(signer_key_data, pkey_type,
				    x509->signer_sk_data,
				    x509->signer_sk_data_len),
		  "Loading X.509 signer private key from file failed: %d\n",
		  ret);
	CKINT(lc_x509_cert_set_signer(newcert, signer_key_data, newcert));

	CKINT(lc_pkcs7_set_signer(pkcs7, newcert, opts->hash, opts->aa_set));

	opts->signer_set = 1;
	newcert = NULL;

out:
	lc_free(newcert);
	return ret;
}

static int pkcs7_load_cert(struct pkcs7_generator_opts *opts)
{
	struct lc_pkcs7_message *pkcs7 = opts->pkcs7;
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
	newcert->allocated = 1;

	/* Parse the X.509 certificate */
	CKINT_LOG(lc_x509_cert_decode(newcert, x509->x509_data,
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

static int pkcs7_load_trust(struct pkcs7_generator_opts *opts)
{
	struct lc_x509_certificate *newcert = NULL;
	struct pkcs7_x509 *x509;
	int ret = 0;

	/* If we have no trust anchor, ignore */
	CKNULL(opts->trust_anchor, 0);

	CKINT(lc_alloc_aligned((void **)&x509, 8, sizeof(struct pkcs7_x509)));

	pkcs7_add_x509(opts, x509);

	CKINT_LOG(get_data(opts->trust_anchor, &x509->x509_data,
			   &x509->x509_data_len),
		  "Loading of file %s failed\n", opts->trust_anchor);

	CKINT(lc_alloc_aligned((void **)&newcert, 8,
			       sizeof(struct lc_x509_certificate)));
	newcert->allocated = 1;

	CKINT_LOG(lc_x509_cert_decode(newcert, x509->x509_data,
				      x509->x509_data_len),
		  "Loading of X.509 trust anchor certificate failed\n");

	CKINT(lc_pkcs7_trust_store_add(&opts->trust_store, newcert));

	x509->x509 = newcert;
	newcert = NULL;
	opts->use_trust_store = 1;

out:
	lc_free(newcert);
	return ret;
}

static int pkcs7_set_data(struct pkcs7_generator_opts *opts)
{
	struct lc_pkcs7_message *pkcs7 = opts->pkcs7;
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
		"\n\tOptions for analyzing generated / loaded PKCS#7 messages:\n");
	fprintf(stderr,
		"\t   --print\t\t\tParse the generated PKCS#7 message,\n");
	fprintf(stderr, "\t\t\t\t\tverify protected data, and\n");
	fprintf(stderr, "\t\t\t\t\tprint its contents\n");
	fprintf(stderr,
		"\t   --print-pkcs7 <FILE>\t\tParse the PKCS#7 message and\n");
	fprintf(stderr, "\t\t\t\t\tverify protected data\n");
	fprintf(stderr,
		"\t   --verify-pkcs7 <FILE>\t\tParse the PKCS#7 message and\n");
	fprintf(stderr, "\t\t\t\t\tprint its contents\n");
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

	fprintf(stderr, "\n\t-h  --help\t\t\tPrint this help text\n");
}

static int pkcs7_collect_signer(struct pkcs7_generator_opts *opts)
{
	int ret;

	CKNULL(opts->x509_signer_file, 0);
	CKNULL(opts->signer_sk_file, 0);

	CKINT_LOG(pkcs7_load_signer(opts),
		  "Loading signer key/certificate failed\n");

	opts->x509_signer_file = NULL;
	opts->signer_sk_file = NULL;

out:
	return ret;
}

static int pkcs7_collect_x509(struct pkcs7_generator_opts *opts)
{
	int ret;

	CKNULL(opts->x509_file, 0);

	CKINT_LOG(pkcs7_load_cert(opts), "Loading certificate failed\n");

	opts->x509_file = NULL;

out:
	return ret;
}

static int pkcs7_collect_trust(struct pkcs7_generator_opts *opts)
{
	int ret;

	CKNULL(opts->trust_anchor, 0);

	CKINT_LOG(pkcs7_load_trust(opts),
		  "Loading trusted certificate failed\n");

	opts->trust_anchor = NULL;

out:
	return ret;
}

int main(int argc, char *argv[])
{
	struct pkcs7_generator_opts parsed_opts = { 0 };
	struct x509_checker_options *checker_opts = &parsed_opts.checker_opts;
	struct lc_verify_rules *verify_rules = &parsed_opts.verify_rules;
	PKCS7_ALLOC
	int ret = 0, opt_index = 0;

	static const char *opts_short = "ho:i:";
	static const struct option opts[] = { { "help", 0, 0, 'h' },

					      { "outfile", 1, 0, 'o' },
					      { "infile", 1, 0, 'i' },

					      { "md", 1, 0, 0 },
					      { "x509-signer", 1, 0, 0 },
					      { "signer-sk-file", 1, 0, 0 },
					      { "x509-cert", 1, 0, 0 },

					      { "print", 0, 0, 0 },
					      { "noout", 0, 0, 0 },
					      { "print-pkcs7", 1, 0, 0 },
					      { "trust-anchor", 1, 0, 0 },

					      { "expected-keyusage", 1, 0, 0 },
					      { "expected-eku", 1, 0, 0 },

					      { "check-ca", 0, 0, 0 },
					      { "check-ca-conformant", 0, 0,
						0 },
					      { "check-issuer-cn", 1, 0, 0 },
					      { "check-subject-cn", 1, 0, 0 },
					      { "check-noselfsigned", 0, 0, 0 },
					      { "check-eku", 1, 0, 0 },
					      { "check-noca", 0, 0, 0 },
					      { "check-selfsigned", 0, 0, 0 },
					      { "check-rootca", 0, 0, 0 },
					      { "check-keyusage", 1, 0, 0 },

					      { "verify-pkcs7", 1, 0, 0 },

					      { 0, 0, 0, 0 } };

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

			/* outfile */
			case 1:
				CKINT(pkcs7_check_file(optarg));
				parsed_opts.outfile = optarg;
				break;
			/* infile */
			case 2:
				parsed_opts.infile = optarg;
				break;

			/* md */
			case 3:
				if (parsed_opts.signer_set) {
					printf("The option --md must be set before the first signer to take effect\n");
					ret = -EINVAL;
					goto out;
				}
				CKINT(lc_x509_name_to_hash(optarg,
							   &parsed_opts.hash));
				break;

			/* x509-signer */
			case 4:
				parsed_opts.x509_signer_file = optarg;
				CKINT(pkcs7_collect_signer(&parsed_opts));
				break;
			/* signer-sk-file */
			case 5:
				parsed_opts.signer_sk_file = optarg;
				CKINT(pkcs7_collect_signer(&parsed_opts));
				break;

			/* x509-cert */
			case 6:
				parsed_opts.x509_file = optarg;
				CKINT(pkcs7_collect_x509(&parsed_opts));
				break;

			/* print */
			case 7:
				parsed_opts.print_pkcs7 = 1;
				break;
			/* noout */
			case 8:
				parsed_opts.noout = 1;
				break;
			/* print-pkcs7 */
			case 9:
				parsed_opts.pkcs7_msg = optarg;
				parsed_opts.print_pkcs7 = 1;
				break;
			/* trust-anchor */
			case 10:
				parsed_opts.trust_anchor = optarg;
				CKINT(pkcs7_collect_trust(&parsed_opts));
				break;

			/* expected-keyusage */
			case 11:
				CKINT(lc_x509_name_to_keyusage(
					optarg,
					&verify_rules->required_keyusage));
				parsed_opts.verify_rules_set = 1;
				break;
			/* expected-eku */
			case 12:
				CKINT(lc_x509_name_to_eku(
					optarg, &verify_rules->required_eku));
				parsed_opts.verify_rules_set = 1;
				break;

			/* check-ca */
			case 13:
				checker_opts->check_ca = 1;
				parsed_opts.checker = 1;
				break;
			/* check-ca-conformant */
			case 14:
				checker_opts->check_ca_conformant = 1;
				parsed_opts.checker = 1;
				break;
			/* check-issuer-cn */
			case 15:
				checker_opts->issuer_cn = optarg;
				parsed_opts.checker = 1;
				break;
			/* check-subject-cn */
			case 16:
				checker_opts->subject_cn = optarg;
				parsed_opts.checker = 1;
				break;
			/* check-noselfsigned */
			case 17:
				checker_opts->check_no_selfsigned = 1;
				parsed_opts.checker = 1;
				break;
			/* check-eku */
			case 18:
				checker_opts->eku =
					(unsigned int)strtoul(optarg, NULL, 10);
				parsed_opts.checker = 1;
				break;
			/* check-noca */
			case 19:
				checker_opts->check_no_ca = 1;
				parsed_opts.checker = 1;
				break;
			/* check-selfsigned */
			case 20:
				checker_opts->check_selfsigned = 1;
				parsed_opts.checker = 1;
				break;
			/* check-rootca */
			case 21:
				checker_opts->check_root_ca = 1;
				parsed_opts.checker = 1;
				break;
			/* check-keyusage */
			case 22:
				checker_opts->keyusage =
					(unsigned int)strtoul(optarg, NULL, 10);
				parsed_opts.checker = 1;
				break;
			/* verify-pkcs7 */
			case 23:
				parsed_opts.pkcs7_msg = optarg;
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
