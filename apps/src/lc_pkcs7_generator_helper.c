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

#include <sys/stat.h>

#include "asn1.h"
#include "binhexbin.h"
#include "lc_pkcs7_generator_helper.h"
#include "lc_pkcs7_parser.h"
#include "lc_x509_generator.h"
#include "lc_x509_generator_file_helper.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "x509_print.h"

void pkcs7_clean_opts(struct pkcs7_generator_opts *opts)
{
	struct pkcs7_x509 *x509;

	if (!opts)
		return;

	lc_pkcs7_trust_store_clear(&opts->trust_store);

	x509 = opts->x509;
	while (x509) {
		struct pkcs7_x509 *tmp_x509 = x509->next;

		release_data(x509->x509_data, x509->x509_data_len,
			     lc_pem_flag_certificate);
		release_data(x509->signer_sk_data, x509->signer_sk_data_len,
			     lc_pem_flag_priv_key);
		release_data(x509->signer_data, x509->signer_data_len,
			     lc_pem_flag_certificate);

		lc_x509_cert_clear(x509->x509);
		lc_free(x509->x509);

		lc_free(x509);

		x509 = tmp_x509;
	}

	opts->x509 = NULL;

	release_data(opts->data, opts->datalen, lc_pem_flag_nopem);

	lc_pkcs7_message_clear(opts->pkcs7);
	lc_pkcs8_message_clear(&opts->pkcs8);
	lc_memset_secure(opts, 0, sizeof(*opts));
}

int pkcs7_check_file(const char *file)
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
	int ret = 0;

	if (opts->noout)
		return 0;

	CKNULL(opts->outfile, -EINVAL);

	CKINT(pkcs7_check_file(opts->outfile));

	CKINT(write_data(opts->outfile, certdata, certdata_len,
			 opts->pem_format_output ? lc_pem_flag_cms :
						   lc_pem_flag_nopem));

out:
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

int pkcs7_dump_file(struct pkcs7_generator_opts *opts)
{
	const uint8_t *avail_data;
	uint8_t *pkcs7_data = NULL;
	size_t pkcs7_datalen = 0, avail_datalen;
	PKCS7_ALLOC
	int ret;

	if (!opts->pkcs7_msg && !opts->checker)
		return 0;

	CKINT_LOG(get_data(opts->pkcs7_msg, &pkcs7_data, &pkcs7_datalen,
			   lc_pem_flag_cms),
		  "Loading of file %s failed\n", opts->pkcs7_msg);

	CKINT_LOG(lc_pkcs7_decode(pkcs7_msg, pkcs7_data, pkcs7_datalen),
		  "Parsing of input file %s failed\n", opts->pkcs7_msg);

	/*
	 * If caller provided data, set it - if data is found in the CMS
	 * structure, the following call will error out.
	 */
	if (opts->data) {
		CKINT(lc_pkcs7_set_data(pkcs7_msg, opts->data, opts->datalen,
					0));
	}

	/*
	 * Now, if we have data with the PKCS7 message, attempt to verify it
	 * (i.e. perform a signature verification).
	 */
	ret = lc_pkcs7_get_content_data(pkcs7_msg, &avail_data, &avail_datalen);
	if (!ret && !opts->skip_signature_verification) {
		CKINT_LOG(lc_pkcs7_verify(
				  pkcs7_msg,
				  opts->use_trust_store ? &opts->trust_store :
							  NULL,
				  opts->verify_rules_set ? &opts->verify_rules :
							   NULL),
			  "Verification of PKCS#7 message failed\n");
	} else {
		printf("Verification of PKCS#7 message skipped\n");
	}

	if (opts->checker)
		CKINT(apply_checks_pkcs7(pkcs7_msg, &opts->checker_opts));

	if (opts->print_pkcs7)
		CKINT(print_pkcs7_data(pkcs7_msg));

out:
	lc_pkcs7_message_clear(pkcs7_msg);
	release_data(pkcs7_data, pkcs7_datalen, lc_pem_flag_cms);
	PKCS7_FREE
	return ret;
}

int pkcs7_gen_message(struct pkcs7_generator_opts *opts)
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


	if (!opts->outfile) {
		bin2print(ws->data, datalen, stdout, "PKCS7 Message");
	} else {
		CKINT_LOG(pkcs7_gen_file(opts, ws->data, datalen),
			  "Writing of X.509 certificate failed\n");
	}

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

static int pkcs7_sk_decode(struct pkcs7_generator_opts *opts,
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
		struct lc_pkcs8_message *pkcs8 = &opts->pkcs8;
		struct lc_x509_key_data *pkcs8_keys = &pkcs8->privkey;

		/*
		 * After successful parsing of the private key into the
		 * PKCS#8 structure, refer to this private key.
		 */
		keys->sk.dilithium_sk = pkcs8_keys->sk.dilithium_sk;
		return 0;
	}

	CKINT(lc_x509_sk_decode(keys, pkey_type, data, datalen));

out:
	return ret;
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
			   &x509->signer_data_len, lc_pem_flag_certificate),
		  "mmap failure\n");

	CKINT_LOG(get_data(opts->signer_sk_file, &x509->signer_sk_data,
			   &x509->signer_sk_data_len, lc_pem_flag_priv_key),
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
	CKINT_LOG(
		pkcs7_sk_decode(opts, signer_key_data, pkey_type,
				x509->signer_sk_data, x509->signer_sk_data_len),
		"Loading X.509 signer private key from file failed: %d\n", ret);
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

	CKINT(get_data(opts->x509_file, &x509->x509_data, &x509->x509_data_len,
		       lc_pem_flag_certificate));

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
			   &x509->x509_data_len, lc_pem_flag_certificate),
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

int pkcs7_set_data(struct pkcs7_generator_opts *opts)
{
	struct lc_pkcs7_message *pkcs7 = opts->pkcs7;
	int ret;

	CKNULL_LOG(opts->infile, -EINVAL,
		   "Data file to be protected missing\n");

	CKINT_LOG(get_data(opts->infile, &opts->data, &opts->datalen,
			   lc_pem_flag_nopem),
		  "Loading of file %s failed\n", opts->infile);

	CKINT(lc_pkcs7_set_data(pkcs7, opts->data, opts->datalen,
				opts->infile_flags));

out:
	return ret;
}

int pkcs7_collect_signer(struct pkcs7_generator_opts *opts)
{
	int ret;

	if (!opts->x509_signer_file)
		return 0;
	if (!opts->signer_sk_file)
		return 0;

	CKINT_LOG(pkcs7_load_signer(opts),
		  "Loading signer key/certificate failed\n");

	opts->x509_signer_file = NULL;
	opts->signer_sk_file = NULL;

out:
	return ret;
}

int pkcs7_collect_x509(struct pkcs7_generator_opts *opts)
{
	int ret;

	CKNULL(opts->x509_file, 0);

	CKINT_LOG(pkcs7_load_cert(opts), "Loading certificate failed\n");

	opts->x509_file = NULL;

out:
	return ret;
}

int pkcs7_collect_trust(struct pkcs7_generator_opts *opts)
{
	int ret;

	CKNULL(opts->trust_anchor, 0);

	CKINT_LOG(pkcs7_load_trust(opts),
		  "Loading trusted certificate failed\n");

	opts->trust_anchor = NULL;

out:
	return ret;
}
