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
#include <sys/stat.h>
#include <time.h>

#include "binhexbin.h"
#include "ret_checkers.h"
#include "lc_status.h"
#include "lc_x509_generator.h"
#include "lc_x509_generator_file_helper.h"
#include "lc_x509_generator_helper.h"
#include "lc_x509_parser.h"
#include "lc_pkcs8_parser.h"
#include "lc_pkcs8_generator.h"
#include "small_stack_support.h"
#include "x509_checker.h"
#include "x509_print.h"

#define DATASIZE 65536

struct x509_generator_opts {
	struct lc_x509_certificate cert;
	struct lc_x509_certificate signer_cert;
	struct lc_x509_key_input_data key_input_data;
	struct lc_x509_key_data key_data;
	struct lc_x509_key_input_data signer_key_input_data;
	struct lc_x509_key_data signer_key_data;
	struct x509_checker_options checker_opts;
	struct lc_pkcs8_message pkcs8;
	uint8_t *raw_skid;
	size_t raw_skid_size;
	uint8_t *raw_akid;
	size_t raw_akid_size;
	uint8_t *raw_serial;
	size_t raw_serial_size;
	const char *print_x509_cert;
	const char *outfile;
	const char *sk_file;
	const char *pk_file;
	const char *x509_signer_file;
	const char *signer_sk_file;
	const char *data_file;
	const char *x509_cert_file;

	uint8_t *signer_data;
	size_t signer_data_len;
	uint8_t *pk_data;
	size_t pk_len;
	uint8_t *sk_data;
	size_t sk_len;
	uint8_t *signer_sk_data;
	size_t signer_sk_len;
	uint8_t *data;
	size_t data_len;
	uint8_t *x509_cert_data;
	size_t x509_cert_data_len;

	enum lc_sig_types create_keypair_algo;
	enum lc_sig_types in_key_type;

	unsigned int print_x509 : 1;
	unsigned int noout : 1;
	unsigned int checker : 1;
	unsigned int cert_present : 1;
	unsigned int sk_is_pkcs8 : 1;
	unsigned int generate_sk_seed : 1;
};

static int x509_check_file(const char *file)
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

static int x509_gen_file(struct x509_generator_opts *opts,
			 const uint8_t *certdata, size_t certdata_len)
{
	FILE *f = NULL;
	size_t written;
	int ret = 0;

	if (opts->noout)
		return 0;

	CKNULL(opts->outfile, -EINVAL);

	CKINT(x509_check_file(opts->outfile));

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

static int x509_enc_dump(struct x509_generator_opts *opts,
			 const uint8_t *x509_data, size_t x509_datalen)
{
	struct workspace {
		struct lc_x509_certificate pcert;
	};
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (!opts->print_x509 && !opts->checker)
		return 0;

	CKINT_LOG(lc_x509_cert_decode(&ws->pcert, x509_data, x509_datalen),
		  "X.509 decoding failed\n");

	if (opts->checker) {
		CKINT_LOG(apply_checks_x509(&ws->pcert, &opts->checker_opts),
			  "X.509 checks failed\n");
	}

	if (opts->print_x509) {
		CKINT_LOG(print_x509_cert(&ws->pcert),
			  "X.509 certificate printing failed\n");
	}

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int x509_dump_file(struct x509_generator_opts *opts)
{
	struct workspace {
		struct lc_x509_certificate pcert;
	};
	uint8_t *x509_data = NULL;
	size_t x509_datalen = 0;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (!opts->print_x509_cert && !opts->checker)
		return 0;

	CKINT_LOG(get_data(opts->print_x509_cert, &x509_data, &x509_datalen),
		  "Loading of file %s failed\n", opts->print_x509_cert);

	CKINT_LOG(lc_x509_cert_decode(&ws->pcert, x509_data, x509_datalen),
		  "Parsing of input file %s failed\n", opts->print_x509_cert);

	if (opts->checker) {
		/* Be lenient on received certificate */
		opts->checker_opts.cert_may_be_invalid = 1;
		CKINT(apply_checks_x509(&ws->pcert, &opts->checker_opts));
		opts->checker_opts.cert_may_be_invalid = 0;
	}

	if (opts->print_x509_cert)
		CKINT(print_x509_cert(&ws->pcert));

out:
	LC_RELEASE_MEM(ws);
	release_data(x509_data, x509_datalen);
	return ret;
}

static int x509_gen_cert(struct x509_generator_opts *opts)
{
	struct workspace {
		uint8_t data[DATASIZE];
	};
	struct lc_x509_certificate *gcert = &opts->cert;
	size_t avail_datalen = DATASIZE, datalen;
	int ret;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	if (opts->cert_present)
		return 0;

	/* Check the issuer */
	CKINT(lc_x509_cert_check_issuer_ca(gcert));

	CKINT(lc_x509_cert_encode(gcert, ws->data, &avail_datalen));
	datalen = DATASIZE - avail_datalen;

	if (!opts->outfile)
		bin2print(ws->data, datalen, stdout, "X.509 Certificate");

	CKINT_LOG(x509_gen_file(opts, ws->data, datalen),
		  "Writing of X.509 certificate failed\n");

	CKINT(x509_enc_dump(opts, ws->data, datalen));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static void x509_clean_opts(struct x509_generator_opts *opts)
{
	if (!opts)
		return;

	if (opts->raw_skid)
		free(opts->raw_skid);
	if (opts->raw_akid)
		free(opts->raw_akid);
	if (opts->raw_serial)
		free(opts->raw_serial);

	lc_x509_cert_clear(&opts->cert);
	lc_x509_cert_clear(&opts->signer_cert);
	lc_pkcs8_message_clear(&opts->pkcs8);

	release_data(opts->signer_data, opts->signer_data_len);
	release_data(opts->pk_data, opts->pk_len);
	release_data(opts->sk_data, opts->sk_len);
	release_data(opts->signer_sk_data, opts->signer_sk_len);
	release_data(opts->data, opts->data_len);
	release_data(opts->x509_cert_data, opts->x509_cert_data_len);
}

static int x509_enc_eku(struct x509_generator_opts *opts,
			const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	unsigned long val;
	char *string;
	int ret;

	val = strtoul(opt_optarg, &string, 10);
	if (val == 0) {
		CKINT(lc_x509_cert_set_eku(cert, string));
	} else if (val < USHRT_MAX) {
		CKINT(lc_x509_cert_set_eku_val(cert, (uint16_t)val));
	} else {
		return -ERANGE;
	}

out:
	return ret;
}

static int x509_enc_keyusage(struct x509_generator_opts *opts,
			     const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	unsigned long val;
	char *string;
	int ret;

	val = strtoul(opt_optarg, &string, 10);
	if (val == 0) {
		CKINT(lc_x509_cert_set_keyusage(cert, string));
	} else if (val < USHRT_MAX) {
		CKINT_LOG(lc_x509_cert_set_keyusage_val(cert, (uint16_t)val),
			  "Set key usage value %u\n", (uint16_t)val);
	} else {
		return -ERANGE;
	}

out:
	return ret;
}

static int x509_enc_ca(struct x509_generator_opts *opts)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_ca(cert);
}

static int x509_enc_san_dns(struct x509_generator_opts *opts,
			    const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_san_dns(cert, opt_optarg);
}

static int x509_enc_san_ip(struct x509_generator_opts *opts, char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	uint8_t ipaddr[16];
	size_t ip_len = sizeof(ipaddr);
	int ret;

	CKINT(lc_x509_enc_san_ip(opt_optarg, ipaddr, &ip_len));

	CKINT(lc_x509_cert_set_san_ip(cert, ipaddr, ip_len));

out:
	return ret;
}

static int x509_enc_skid(struct x509_generator_opts *opts,
			 const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	int ret;

	if (!opt_optarg)
		return -EINVAL;

	CKINT(hex2bin_alloc(opt_optarg, strlen(opt_optarg), &opts->raw_skid,
			    &opts->raw_skid_size));

	CKINT(lc_x509_cert_set_skid(cert, opts->raw_skid, opts->raw_skid_size));

out:
	return ret;
}

static int x509_enc_akid(struct x509_generator_opts *opts,
			 const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	int ret;

	if (!opt_optarg)
		return -EINVAL;

	CKINT(hex2bin_alloc(opt_optarg, strlen(opt_optarg), &opts->raw_akid,
			    &opts->raw_akid_size));

	CKINT(lc_x509_cert_set_akid(cert, opts->raw_akid, opts->raw_akid_size));

out:
	return ret;
}

static int x509_enc_valid_from(struct x509_generator_opts *opts,
			       const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	unsigned long long val;

	val = strtoull(opt_optarg, NULL, 10);
	if (val == ULLONG_MAX)
		return -ERANGE;

	return lc_x509_cert_set_valid_from(cert, (time64_t)val);
}

static int x509_enc_valid_to(struct x509_generator_opts *opts,
			     const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	unsigned long long val;

	val = strtoull(opt_optarg, NULL, 10);
	if (val == ULLONG_MAX)
		return -ERANGE;

	return lc_x509_cert_set_valid_to(cert, (time64_t)val);
}

static int x509_enc_valid_days(struct x509_generator_opts *opts,
			       const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	time64_t now;
	unsigned long long val;
	int ret;

	val = strtoull(opt_optarg, NULL, 10);
	if (val == ULLONG_MAX)
		return -ERANGE;

	now = time(NULL);
	if (now == ((time_t)-1))
		return -errno;

	/* Read data is in days -> convert to seconds */
	val *= 24; /* hours */
	val *= 60; /* minutes */
	val *= 60; /* seconds */

	/* Turn val into the "valid-to" time */
	val += (unsigned long long)now;

	CKINT(lc_x509_cert_set_valid_from(cert, now));
	CKINT(lc_x509_cert_set_valid_to(cert, (time64_t)val));

out:
	return ret;
}

static int x509_enc_subject_cn(struct x509_generator_opts *opts,
			       const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_subject_cn(cert, opt_optarg,
					   strlen(opt_optarg));
}

static int x509_enc_subject_email(struct x509_generator_opts *opts,
				  const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_subject_email(cert, opt_optarg,
					      strlen(opt_optarg));
}

static int x509_enc_subject_ou(struct x509_generator_opts *opts,
			       const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_subject_ou(cert, opt_optarg,
					   strlen(opt_optarg));
}

static int x509_enc_subject_o(struct x509_generator_opts *opts,
			      const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_subject_o(cert, opt_optarg, strlen(opt_optarg));
}

static int x509_enc_subject_st(struct x509_generator_opts *opts,
			       const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_subject_st(cert, opt_optarg,
					   strlen(opt_optarg));
}

static int x509_enc_subject_c(struct x509_generator_opts *opts,
			      const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_subject_c(cert, opt_optarg, strlen(opt_optarg));
}

static int x509_enc_issuer_cn(struct x509_generator_opts *opts,
			      const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_issuer_cn(cert, opt_optarg, strlen(opt_optarg));
}

static int x509_enc_issuer_email(struct x509_generator_opts *opts,
				 const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_issuer_email(cert, opt_optarg,
					     strlen(opt_optarg));
}

static int x509_enc_issuer_ou(struct x509_generator_opts *opts,
			      const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_issuer_ou(cert, opt_optarg, strlen(opt_optarg));
}

static int x509_enc_issuer_o(struct x509_generator_opts *opts,
			     const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_issuer_o(cert, opt_optarg, strlen(opt_optarg));
}

static int x509_enc_issuer_st(struct x509_generator_opts *opts,
			      const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_issuer_st(cert, opt_optarg, strlen(opt_optarg));
}

static int x509_enc_issuer_c(struct x509_generator_opts *opts,
			     const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;

	return lc_x509_cert_set_issuer_c(cert, opt_optarg, strlen(opt_optarg));
}

static int x509_enc_serial(struct x509_generator_opts *opts,
			   const char *opt_optarg)
{
	struct lc_x509_certificate *cert = &opts->cert;
	int ret;

	if (!opt_optarg)
		return -EINVAL;

	CKINT(hex2bin_alloc(opt_optarg, strlen(opt_optarg), &opts->raw_serial,
			    &opts->raw_serial_size));

	CKINT(lc_x509_cert_set_serial(cert, opts->raw_serial,
				      opts->raw_serial_size));

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
	ret = lc_pkcs8_decode(&opts->pkcs8, data, datalen);
	if (!ret) {
		opts->sk_is_pkcs8 = 1;
		return 0;
	}

	opts->sk_is_pkcs8 = 0;
	CKINT(lc_x509_sk_decode(keys, pkey_type, data, datalen));

out:
	return ret;
}

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

static int x509_signature_gen(const struct x509_generator_opts *opts,
			      uint8_t *sig_data, size_t *siglen,
			      const struct lc_x509_key_data *keys,
			      const uint8_t *m, size_t mlen,
			      const struct lc_hash *prehash_algo)
{
	int ret;

	if (opts->sk_is_pkcs8) {
		CKINT(lc_pkcs8_signature_gen(sig_data, siglen, &opts->pkcs8, m,
					     mlen, prehash_algo));
	} else {
		CKINT(lc_x509_signature_gen(sig_data, siglen, keys, m, mlen,
					    prehash_algo));
	}

out:
	return ret;
}

static int x509_load_sk(struct x509_generator_opts *opts)
{
	struct lc_x509_key_data *signer_key_data = &opts->signer_key_data;
	struct lc_x509_key_input_data *signer_key_input_data =
		&opts->signer_key_input_data;
	enum lc_sig_types pkey_type;
	int ret;

	CKINT_LOG(get_data(opts->signer_sk_file, &opts->signer_sk_data,
			   &opts->signer_sk_len),
		  "Signer SK mmap failure\n");

	/* Get the signature type based on the signer key */
	CKINT(lc_x509_cert_get_pubkey(&opts->signer_cert, NULL, NULL,
				      &pkey_type));

	LC_X509_LINK_SK_INPUT_DATA(signer_key_data, signer_key_input_data);
	CKINT_LOG(x509_sk_decode(opts, signer_key_data, pkey_type,
				 opts->signer_sk_data, opts->signer_sk_len),
		  "Loading signer private key from file failed: %d\n", ret);

out:
	return ret;
}

static int x509_enc_set_signer(struct x509_generator_opts *opts)
{
	struct lc_x509_certificate *gcert = &opts->cert;
	struct lc_x509_key_data *signer_key_data = &opts->signer_key_data;
	struct lc_x509_key_input_data *signer_key_input_data =
		&opts->signer_key_input_data;
	int ret;

	CKNULL(opts->x509_signer_file, -EINVAL);

	CKINT_LOG(get_data(opts->x509_signer_file, &opts->signer_data,
			   &opts->signer_data_len),
		  "mmap failure\n");

	CKINT_LOG(lc_x509_cert_decode(&opts->signer_cert, opts->signer_data,
				      opts->signer_data_len),
		  "Failure to parse certificate\n");

	CKINT(lc_x509_policy_is_ca(&opts->signer_cert));
	if (ret != LC_X509_POL_TRUE)
		printf("WARNING: X.509 signer is no CA!\n");

	LC_X509_LINK_PK_INPUT_DATA(signer_key_data, signer_key_input_data);

	if (opts->signer_sk_file) {
		CKINT_LOG(x509_load_sk(opts),
			  "Loading of private key failed\n");
	}

	CKINT_LOG(lc_x509_cert_set_signer(gcert, signer_key_data,
					  &opts->signer_cert),
		  "Setting the signer of the certificate failed\n");

out:
	return ret;
}

static int x509_enc_set_key(struct x509_generator_opts *opts)
{
	struct workspace {
		uint8_t der_sk[DATASIZE];
	};
	struct lc_x509_certificate *gcert = &opts->cert;
	struct lc_x509_key_input_data *key_input_data = &opts->key_input_data;
	struct lc_x509_key_data *keys = &opts->key_data;
	size_t der_sk_len = DATASIZE;
	unsigned int self_signed = !(opts->x509_signer_file);
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	LC_X509_LINK_INPUT_DATA(keys, key_input_data);

	if (opts->create_keypair_algo) {
		keys->sk_seed_set = opts->generate_sk_seed;
		CKINT(lc_x509_keypair_gen(gcert, keys,
					  opts->create_keypair_algo));

		if (!opts->noout) {
			CKINT_LOG(x509_sk_encode(opts, keys, ws->der_sk,
						 &der_sk_len),
				  "Generation of private key file failed\n");
			CKINT(write_data(opts->sk_file, ws->der_sk,
					 DATASIZE - der_sk_len));
		}

	} else if (opts->x509_cert_file) {
		/* Caller set X.509 certificate, perhaps for signing. */

		/* Secret key must be present */
		CKNULL_LOG(opts->sk_file, -EINVAL,
			   "Secret key corresponding to certificate missing\n");

		/* Access the X.509 certificate file */
		CKINT_LOG(get_data(opts->x509_cert_file, &opts->x509_cert_data,
				   &opts->x509_cert_data_len),
			  "X.509 certificate mmap failure\n");
		/* Parse the X.509 certificate */
		CKINT_LOG(lc_x509_cert_decode(gcert, opts->x509_cert_data,
					      opts->x509_cert_data_len),
			  "Loading of X.509 certificate failed\n");

		/* Access the X.509 certificate file */
		CKINT_LOG(get_data(opts->sk_file, &opts->sk_data,
				   &opts->sk_len),
			  "Secret key mmap failure\n");
		/* Parse the X.509 secret key */
		CKINT_LOG(x509_sk_decode(opts, keys, gcert->pub.pkey_algo,
					 opts->sk_data, opts->sk_len),
			  "Parsing of secret key failed\n");

		opts->cert_present = 1;
	} else {
		CKNULL_LOG(!opts->in_key_type, -EINVAL,
			   "Input key files must be specified with key type\n");

		CKINT_LOG(get_data(opts->pk_file, &opts->pk_data,
				   &opts->pk_len),
			  "PK mmap failure\n");
		CKINT_LOG(lc_x509_pk_decode(keys, opts->in_key_type,
					    opts->pk_data, opts->pk_len),
			  "Decoding of public key failed\n");
		if (self_signed) {
			CKINT_LOG(get_data(opts->sk_file, &opts->sk_data,
					   &opts->sk_len),
				  "SK mmap failure\n");
			CKINT_LOG(x509_sk_decode(opts, keys, opts->in_key_type,
						 opts->sk_data, opts->sk_len),
				  "Decoding of private key failed\n");
		}

		CKINT_LOG(lc_x509_keypair_load(gcert, keys),
			  "Loading of keypair failed\n");
	}

out:
	LC_RELEASE_MEM(ws);
	return ret;
}

static int x509_enc_crypto_algo(struct x509_generator_opts *opts)
{
	int ret;

	if (!opts->noout && !opts->sk_file) {
		printf("A secret key file for the generation the signature is missing!\n");
		return -EINVAL;
	}

	if (!opts->x509_cert_file && !opts->create_keypair_algo &&
	    !opts->pk_file) {
		printf("A public key file for the generation the X.509 certificate is missing as no key pair shall be generated!\n");
		return -EINVAL;
	}

	/*
	 * Set the public key
	 */
	CKINT_LOG(x509_enc_set_key(opts),
		  "Setting X.509 public key / secret key failed\n");

	/*
	 * Set the signer information
	 */
	if (opts->x509_signer_file) {
		CKINT_LOG(x509_enc_set_signer(opts),
			  "Setting the signer X.509 key data failed\n");
	}

out:
	return ret;
}

static int x509_sign_data(struct x509_generator_opts *opts)
{
	const struct lc_x509_key_data *key_data = &opts->key_data;
	size_t siglen;
	uint8_t *sigptr = NULL;
	int ret;

	if (!opts->data_file)
		return 0;

	CKINT(lc_x509_get_signature_size_from_sk(&siglen, key_data));

	CKINT(lc_alloc_aligned((void **)&sigptr, 8, siglen));

	CKINT_LOG(get_data(opts->data_file, &opts->data, &opts->data_len),
		  "Failure of getting data to be signed\n");

	CKINT(x509_signature_gen(opts, sigptr, &siglen, key_data, opts->data,
				 opts->data_len, NULL));

#if 0
	const struct lc_x509_certificate *cert = &opts->cert;
	CKINT_LOG(lc_x509_verify_signature(sigptr, siglen, cert, opts->data,
					   opts->data_len, NULL),
		  "Verification of data failed\n");
#endif

	if (opts->outfile) {
		CKINT(write_data(opts->outfile, sigptr, siglen));
	} else {
		bin2print(sigptr, siglen, stdout, "Signature");
	}

out:
	lc_free(sigptr);
	return ret;
}

static int x509_check_data(struct x509_generator_opts *opts)
{
	struct lc_x509_certificate *cert = &opts->cert;
	int ret = 0;

	if (!opts->raw_serial) {
#define LC_X509_RANDOM_SERIAL_SIZE 8
		opts->raw_serial = calloc(1, LC_X509_RANDOM_SERIAL_SIZE);
		CKNULL(opts->raw_serial, -ENOMEM);
		opts->raw_serial_size = LC_X509_RANDOM_SERIAL_SIZE;
		CKINT(lc_rng_generate(lc_seeded_rng, NULL, 0, opts->raw_serial,
				      opts->raw_serial_size));
		CKINT(lc_x509_cert_set_serial(cert, opts->raw_serial,
					      opts->raw_serial_size));
	}

out:
	return ret;
}

static void x509_generator_usage(void)
{
	fprintf(stderr, "\nLeancrypto X.509 Certificate Generator\n");

	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t[OPTION]\n");

	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr,
		"\t-o --outfile <FILE>\t\tFile to write certificate to\n");

	fprintf(stderr, "\n\tOptions for X.509 cryptographic aspects:\n");
	fprintf(stderr,
		"\t   --sk-file <FILE>\t\tFile with secret key used for signature\n");
	fprintf(stderr, "\t\t\t\t\tInput when key is available (MUST be\n"),
		fprintf(stderr, "\t\t\t\t\tDER),\n");
	fprintf(stderr, "\t\t\t\t\toutput with --create-keypair\n");
	fprintf(stderr,
		"\t   --pk-file <FILE>\t\tFile with public key used for signature\n");
	fprintf(stderr, "\t\t\t\t\tInput when key is available to generate\n"),
		fprintf(stderr, "\t\t\t\t\tcert (MUST be DER),\n");
	fprintf(stderr, "\t\t\t\t\toutput with --create-keypair\n");
	fprintf(stderr,
		"\t   --key-type <TYPE>\t\tInput keys are of given type\n");
	fprintf(stderr, "\t\t\t\t\tQuery available types with \"?\"\n");
	fprintf(stderr,
		"\t   --create-keypair <TYPE>\tCreate key pair of given type\n");
	fprintf(stderr, "\t\t\t\t\tNOTE: generated keys are written to file\n");
	fprintf(stderr,
		"\t   --create-keypair-pkcs8 <TYPE>\tCreate key pair of given\n");
	fprintf(stderr, "\t\t\t\t\ttype where private key is PKCS#8 blob\n");
	fprintf(stderr, "\t\t\t\t\tNOTE: generated keys are written to file\n");
	fprintf(stderr,
		"\t   --create-keypair-pkcs8-seed <TYPE>\tCreate key pair of given\n");
	fprintf(stderr, "\t\t\t\t\ttype where private key is PKCS#8 blob\n");
	fprintf(stderr, "\t\t\t\t\tNOTE: If possible, generate seed key\n");
	fprintf(stderr, "\t\t\t\t\t      following RFC 9881 chapter 6.\n");
	fprintf(stderr, "\t\t\t\t\tNOTE: generated keys are written to file\n");
	fprintf(stderr,
		"\t   --x509-signer <FILE>\t\tX.509 certificate of signer\n");
	fprintf(stderr, "\t\t\t\t\tIf not set, create a self-signed\n");
	fprintf(stderr, "\t\t\t\t\tcertificate\n");
	fprintf(stderr,
		"\t   --signer-sk-file <FILE>\tFile with signer secret\n");
	fprintf(stderr, "\t   --x509-cert <FILE>\t\tCertificate for signing\n");

	fprintf(stderr, "\n\tOptions for X.509 meta data:\n");
	fprintf(stderr, "\t   --eku <FLAG>\t\t\tSet Extended Key Usage flag\n");
	fprintf(stderr, "\t\t\t\t\tQuery available flags with \"?\"\n");

	fprintf(stderr, "\t   --keyusage <FLAG>\t\tSet Key Usage flag\n");
	fprintf(stderr, "\t\t\t\t\tQuery available flags with \"?\"\n");

	fprintf(stderr,
		"\t   --ca\t\t\t\tSet CA basic constraint with criticality\n");
	fprintf(stderr, "\t   --san-dns <NAME> \t\tSet SAN DNS name\n");
	fprintf(stderr,
		"\t   --san-ip <IP> \t\tSet SAN IP address (IPv4 or IPv6)\n");
	fprintf(stderr, "\t   --skid\t\t\tSet SKID (in hex form)\n");
	fprintf(stderr, "\t   --akid\t\t\tSet AKID (in hex form)\n");
	fprintf(stderr, "\t\t\t\t\tAKID only used without X.509 signer\n");
	fprintf(stderr, "\t\t\t\t\tbeing specified\n");
	fprintf(stderr, "\t   --valid-from\t\t\tSet start time\n");
	fprintf(stderr, "\t   --valid-to\t\t\tSet end time\n");
	fprintf(stderr,
		"\t   --valid-days\t\t\tSet validity time in days from\n");
	fprintf(stderr, "\t\t\t\t\tfrom today\n");
	fprintf(stderr,
		"\t   --serial <VALUE>\t\tSet serial numer (in hex form)\n");

	fprintf(stderr, "\n\t   --subject-cn <VALUE>\t\tSet subject CN\n");
	fprintf(stderr, "\t   --subject-email <VALUE>\tSet subject Email\n");
	fprintf(stderr, "\t   --subject-ou <VALUE>\t\tSet subject OU\n");
	fprintf(stderr, "\t   --subject-o <VALUE>\t\tSet subject O\n");
	fprintf(stderr, "\t   --subject-st <VALUE>\t\tSet subject ST\n");
	fprintf(stderr, "\t   --subject-c <VALUE>\t\tSet subject C\n");

	fprintf(stderr,
		"\n\tThe following issuer options are only relevant if no X.509\n");
	fprintf(stderr, "\tsigner is present - they are unused otherwise\n");
	fprintf(stderr, "\t   --issuer-cn <VALUE>\t\tSet issuer CN\n");
	fprintf(stderr, "\t   --issuer-email <VALUE>\tSet issuer Email\n");
	fprintf(stderr, "\t   --issuer-ou <VALUE>\t\tSet issuer OU\n");
	fprintf(stderr, "\t   --issuer-o <VALUE>\t\tSet issuer O\n");
	fprintf(stderr, "\t   --issuer-st <VALUE>\t\tSet issuer ST\n");
	fprintf(stderr, "\t   --issuer-c <VALUE>\t\tSet issuer C\n");

	fprintf(stderr,
		"\n\tOptions for analyzing generated / loaded X.509 certificate:\n");
	fprintf(stderr,
		"\t   --print\t\t\tParse the generated X.509 and print its\n");
	fprintf(stderr, "\t\t\t\t\tcontents\n");
	fprintf(stderr,
		"\t   --print-x509 <FILE>\t\tParse the X.509 certificate and\n");
	fprintf(stderr, "\t\t\t\t\tprint its contents\n");
	fprintf(stderr, "\t   --noout\t\t\tNo generation of output files\n");

	fprintf(stderr,
		"\n\tOptions for checking generated / loaded X.509 certificate:\n");
	fprintf(stderr, "\t   --check-ca\t\t\tcheck presence of CA\n");
	fprintf(stderr, "\t   --check-rootca\t\tcheck if root CA\n");
	fprintf(stderr, "\t   --check-noca\t\t\tcheck absence of CA\n");
	fprintf(stderr,
		"\t   --check-ca-conformant\tcheck presence of RFC5280 conformant CA\n");
	fprintf(stderr, "\t\t\t\t\tdefinition\n");
	fprintf(stderr,
		"\t   --check-time\t\t\tcheck time-validity of the certificate\n");
	fprintf(stderr, "\t   --check-issuer-cn\t\tcheck issuer CN\n");
	fprintf(stderr, "\t   --check-subject-cn\t\tcheck subject CN\n");
	fprintf(stderr,
		"\t   --check-selfsigned\t\tcheck that cert is self-signed\n");
	fprintf(stderr,
		"\t   --check-noselfsigned\t\tcheck that cert is not self-signed\n");
	fprintf(stderr,
		"\t   --check-valid-from <EPOCH time>\tcheck validity of time\n");
	fprintf(stderr,
		"\t   --check-valid-to <EPOCH time>\tcheck validity of time\n");
	fprintf(stderr,
		"\t   --check-eku <EKU>\t\tmatch extended key usage (use KEY_EKU_*\n");
	fprintf(stderr, "\t\t\t\t\tflags)\n");
	fprintf(stderr,
		"\t   --check-keyusage <EKU>\tmatch key usage (use KEY_USAGE_* flags)\n");
	fprintf(stderr, "\t   --check-san-dns <NAME>\tmatch SAN DNS\n");
	fprintf(stderr, "\t   --check-san-ip <IP-Hex>\tmatch SAN IP\n");
	fprintf(stderr, "\t   --check-skid <HEX>\t\tmatch subject key ID\n");
	fprintf(stderr, "\t   --check-akid <HEX>\t\tmatch authority key ID\n");

	fprintf(stderr, "\t   --data-file <FILE>\t\tFile with data to sign\n");

	fprintf(stderr, "\n\t-h --help\t\t\tPrint this help text\n");
	fprintf(stderr,
		"\n\t-v --version\t\t\tPrint version and acceleration support\n");
}

static void x509_generator_version(void)
{
	char version[500];

	memset(version, 0, sizeof(version));
	lc_status(version, sizeof(version));

	fprintf(stderr, "Leancrypto X.509 Certificate Generator\n");
	fprintf(stderr, "%s", version);
}

int main(int argc, char *argv[])
{
	struct workspace {
		struct x509_generator_opts parsed_opts;
	};
	struct x509_checker_options *checker_opts;
	int ret = 0, opt_index = 0;

	static const char *opts_short = "ho:v";
	static const struct option opts[] = {
		{ "help", 0, 0, 'h' },
		{ "version", 0, 0, 'v' },

		{ "outfile", 1, 0, 'o' },
		{ "sk-file", 1, 0, 0 },
		{ "pk-file", 1, 0, 0 },
		{ "key-type", 1, 0, 0 },
		{ "create-keypair", 1, 0, 0 },

		{ "x509-signer", 1, 0, 0 },
		{ "signer-sk-file", 1, 0, 0 },

		{ "eku", 1, 0, 0 },
		{ "keyusage", 1, 0, 0 },

		{ "ca", 0, 0, 0 },
		{ "san-dns", 1, 0, 0 },
		{ "san-ip", 1, 0, 0 },
		{ "skid", 1, 0, 0 },
		{ "akid", 1, 0, 0 },
		{ "valid-from", 1, 0, 0 },
		{ "valid-to", 1, 0, 0 },
		{ "valid-days", 1, 0, 0 },
		{ "serial", 1, 0, 0 },

		{ "subject-cn", 1, 0, 0 },
		{ "subject-email", 1, 0, 0 },
		{ "subject-ou", 1, 0, 0 },
		{ "subject-o", 1, 0, 0 },
		{ "subject-st", 1, 0, 0 },
		{ "subject-c", 1, 0, 0 },

		{ "issuer-cn", 1, 0, 0 },
		{ "issuer-email", 1, 0, 0 },
		{ "issuer-ou", 1, 0, 0 },
		{ "issuer-o", 1, 0, 0 },
		{ "issuer-st", 1, 0, 0 },
		{ "issuer-c", 1, 0, 0 },

		{ "print", 0, 0, 0 },
		{ "noout", 0, 0, 0 },
		{ "print-x509", 1, 0, 0 },

		{ "check-ca", 0, 0, 0 },
		{ "check-ca-conformant", 0, 0, 0 },
		{ "check-time", 0, 0, 0 },
		{ "check-issuer-cn", 1, 0, 0 },
		{ "check-subject-cn", 1, 0, 0 },
		{ "check-noselfsigned", 0, 0, 0 },
		{ "check-valid-from", 1, 0, 0 },
		{ "check-valid-to", 1, 0, 0 },
		{ "check-eku", 1, 0, 0 },
		{ "check-san-dns", 1, 0, 0 },
		{ "check-san-ip", 1, 0, 0 },
		{ "check-skid", 1, 0, 0 },
		{ "check-akid", 1, 0, 0 },
		{ "check-noca", 0, 0, 0 },
		{ "check-selfsigned", 0, 0, 0 },
		{ "check-rootca", 0, 0, 0 },
		{ "check-keyusage", 1, 0, 0 },

		{ "data-file", 1, 0, 0 },
		{ "x509-cert", 1, 0, 0 },

		{ "create-keypair-pkcs8-seed", 1, 0, 0 },
		{ "create-keypair-pkcs8", 1, 0, 0 },

		{ 0, 0, 0, 0 }
	};

	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	checker_opts = &ws->parsed_opts.checker_opts;

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
			/* version */
			case 1:
				x509_generator_version();
				goto out;

			/* outfile */
			case 2:
				CKINT_LOG(x509_check_file(optarg),
					  "Output file check failure\n");
				ws->parsed_opts.outfile = optarg;
				break;
			/* sk-file */
			case 3:
				ws->parsed_opts.sk_file = optarg;
				break;
			/* pk-file */
			case 4:
				ws->parsed_opts.pk_file = optarg;
				break;
			/* key-type */
			case 5:
				CKINT_LOG(lc_x509_pkey_name_to_algorithm(
						  optarg,
						  &ws->parsed_opts.in_key_type),
					  "Key type unknown\n");
				break;
			/* create-keypair */
			case 6:
				CKINT_LOG(
					lc_x509_pkey_name_to_algorithm(
						optarg,
						&ws->parsed_opts
							 .create_keypair_algo),
					"Key type for key creation parsing failure\n");
				break;
			/* x509-signer */
			case 7:
				ws->parsed_opts.x509_signer_file = optarg;
				break;
			/* signer-sk-file */
			case 8:
				ws->parsed_opts.signer_sk_file = optarg;
				break;

			/* eku */
			case 9:
				CKINT_LOG(x509_enc_eku(&ws->parsed_opts,
						       optarg),
					  "EKU unknown\n");
				break;
			/* keyusage */
			case 10:
				CKINT_LOG(x509_enc_keyusage(&ws->parsed_opts,
							    optarg),
					  "Key usage unknown\n");
				break;
			/* ca */
			case 11:
				CKINT_LOG(x509_enc_ca(&ws->parsed_opts),
					  "Set CA\n");
				break;
			/* san-dns */
			case 12:
				CKINT_LOG(x509_enc_san_dns(&ws->parsed_opts,
							   optarg),
					  "Set SAN DNS\n");
				break;
			/* san-ip */
			case 13:
				CKINT_LOG(x509_enc_san_ip(&ws->parsed_opts,
							  optarg),
					  "Set SAN IP\n");
				break;

			/* skid */
			case 14:
				CKINT_LOG(x509_enc_skid(&ws->parsed_opts,
							optarg),
					  "Set SKID\n");
				break;
			/* akid */
			case 15:
				CKINT_LOG(x509_enc_akid(&ws->parsed_opts,
							optarg),
					  "Set AKID\n");
				break;
			/* valid-from */
			case 16:
				CKINT_LOG(x509_enc_valid_from(&ws->parsed_opts,
							      optarg),
					  "Set valid from\n");
				break;
			/* valid-to */
			case 17:
				CKINT_LOG(x509_enc_valid_to(&ws->parsed_opts,
							    optarg),
					  "Set valid to\n");
				break;
			/* valid-days */
			case 18:
				/*
				 * There is deliberately no control whether the
				 * caller used valid-from/to and valid-days at
				 * the same time - it is his fault if he uses
				 * conflicting information. Whatever comes last
				 * is used to set the time.
				 */
				CKINT_LOG(x509_enc_valid_days(&ws->parsed_opts,
							      optarg),
					  "Set valid days\n");
				break;
			/* serial */
			case 19:
				CKINT_LOG(x509_enc_serial(&ws->parsed_opts,
							  optarg),
					  "Set serial\n");
				break;

			/* subject-cn */
			case 20:
				CKINT_LOG(x509_enc_subject_cn(&ws->parsed_opts,
							      optarg),
					  "Subject CN parsing error\n");
				break;
			/* subject-email */
			case 21:
				CKINT_LOG(x509_enc_subject_email(
						  &ws->parsed_opts, optarg),
					  "Subject email parsing error\n");
				break;
			/* subject-ou */
			case 22:
				CKINT_LOG(x509_enc_subject_ou(&ws->parsed_opts,
							      optarg),
					  "Subject OU parsing error\n");
				break;
			/* subject-o */
			case 23:
				CKINT_LOG(x509_enc_subject_o(&ws->parsed_opts,
							     optarg),
					  "Subject O parsing error\n");
				break;
			/* subject-st */
			case 24:
				CKINT(x509_enc_subject_st(&ws->parsed_opts,
							  optarg));
				break;
			/* subject-c */
			case 25:
				CKINT(x509_enc_subject_c(&ws->parsed_opts,
							 optarg));
				break;

			/* issuer-cn */
			case 26:
				CKINT(x509_enc_issuer_cn(&ws->parsed_opts,
							 optarg));
				break;
			/* issuer-email */
			case 27:
				CKINT(x509_enc_issuer_email(&ws->parsed_opts,
							    optarg));
				break;
			/* issuer-ou */
			case 28:
				CKINT(x509_enc_issuer_ou(&ws->parsed_opts,
							 optarg));
				break;
			/* issuer-o */
			case 29:
				CKINT(x509_enc_issuer_o(&ws->parsed_opts,
							optarg));
				break;
			/* issuer-st */
			case 30:
				CKINT(x509_enc_issuer_st(&ws->parsed_opts,
							 optarg));
				break;
			/* issuer-c */
			case 31:
				CKINT(x509_enc_issuer_c(&ws->parsed_opts,
							optarg));
				break;

			/* print */
			case 32:
				ws->parsed_opts.print_x509 = 1;
				break;
			/* noout */
			case 33:
				ws->parsed_opts.noout = 1;
				break;
			/* print-x509 */
			case 34:
				ws->parsed_opts.print_x509_cert = optarg;
				break;

			/* check-ca */
			case 35:
				checker_opts->check_ca = 1;
				ws->parsed_opts.checker = 1;
				break;
			/* check-ca-conformant */
			case 36:
				checker_opts->check_ca_conformant = 1;
				ws->parsed_opts.checker = 1;
				break;
			/* check-time */
			case 37:
				checker_opts->check_time = 1;
				ws->parsed_opts.checker = 1;
				break;
			/* check-issuer-cn */
			case 38:
				checker_opts->issuer_cn = optarg;
				ws->parsed_opts.checker = 1;
				break;
			/* check-subject-cn */
			case 39:
				checker_opts->subject_cn = optarg;
				ws->parsed_opts.checker = 1;
				break;
			/* check-noselfsigned */
			case 40:
				checker_opts->check_no_selfsigned = 1;
				ws->parsed_opts.checker = 1;
				break;
			/* check-valid-from */
			case 41:
				checker_opts->valid_from =
					strtoull(optarg, NULL, 10);
				ws->parsed_opts.checker = 1;
				break;
			/* check-valid-to */
			case 42:
				checker_opts->valid_to =
					strtoull(optarg, NULL, 10);
				ws->parsed_opts.checker = 1;
				break;
			/* check-eku */
			case 43:
				checker_opts->eku =
					(unsigned int)strtoul(optarg, NULL, 10);
				ws->parsed_opts.checker = 1;
				break;
			/* check-san-dns */
			case 44:
				checker_opts->san_dns = optarg;
				ws->parsed_opts.checker = 1;
				break;
			/* check-san-ip */
			case 45:
				checker_opts->san_ip = optarg;
				ws->parsed_opts.checker = 1;
				break;
			/* check-skid */
			case 46:
				checker_opts->skid = optarg;
				ws->parsed_opts.checker = 1;
				break;
			/* check-akid */
			case 47:
				checker_opts->akid = optarg;
				ws->parsed_opts.checker = 1;
				break;
			/* check-noca */
			case 48:
				checker_opts->check_no_ca = 1;
				ws->parsed_opts.checker = 1;
				break;
			/* check-selfsigned */
			case 49:
				checker_opts->check_selfsigned = 1;
				ws->parsed_opts.checker = 1;
				break;
			/* check-rootca */
			case 50:
				checker_opts->check_root_ca = 1;
				ws->parsed_opts.checker = 1;
				break;
			/* check-keyusage */
			case 51:
				checker_opts->keyusage =
					(unsigned int)strtoul(optarg, NULL, 10);
				ws->parsed_opts.checker = 1;
				break;

			/* data-file */
			case 52:
				ws->parsed_opts.data_file = optarg;
				break;
			/* x509-cert */
			case 53:
				ws->parsed_opts.x509_cert_file = optarg;
				break;

			/* create-keypair-pkcs8-seed */
			case 54:
				ws->parsed_opts.generate_sk_seed = 1;
				fallthrough;
			/* create-keypair-pkcs8 */
			case 55:
				CKINT_LOG(
					lc_x509_pkey_name_to_algorithm(
						optarg,
						&ws->parsed_opts
							 .create_keypair_algo),
					"Key type for key creation parsing failure\n");
				ws->parsed_opts.sk_is_pkcs8 = 1;
				break;
			}

			break;

		case 'o':
			CKINT_LOG(x509_check_file(optarg),
				  "Output file check failure\n");
			ws->parsed_opts.outfile = optarg;
			break;
		case 'h':
			x509_generator_usage();
			goto out;
		case 'v':
			x509_generator_version();
			goto out;

		default:
			x509_generator_usage();
			ret = -1;
			goto out;
		}
	}

	CKINT(x509_check_data(&ws->parsed_opts));

	if (ws->parsed_opts.print_x509_cert) {
		if (ws->parsed_opts.x509_signer_file)
			CKINT(x509_enc_set_signer(&ws->parsed_opts));

		CKINT(x509_dump_file(&ws->parsed_opts));
		goto out;
	}

	CKINT(x509_enc_crypto_algo(&ws->parsed_opts));

	CKINT(x509_gen_cert(&ws->parsed_opts));

	CKINT(x509_sign_data(&ws->parsed_opts));

out:
	x509_clean_opts(&ws->parsed_opts);
	LC_RELEASE_MEM(ws);
	return -ret;
}
