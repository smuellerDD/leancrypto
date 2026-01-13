/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#ifndef LC_PKCS7_GENERATOR_HELPER_H
#define LC_PKCS7_GENERATOR_HELPER_H

#include "lc_pkcs7_generator.h"
#include "lc_pkcs8_parser.h"
#include "lc_x509_generator_helper.h"
#include "x509_checker.h"

#ifdef __cplusplus
extern "C" {
#endif

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
	struct lc_pkcs8_message pkcs8;
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

	enum lc_pkcs7_set_data_flags infile_flags;

	uint8_t *data;
	size_t datalen;

	struct lc_pkcs7_trust_store trust_store;

	unsigned int print_pkcs7 : 1;
	unsigned int noout : 1;
	unsigned int checker : 1;
	unsigned int use_trust_store : 1;
	unsigned int signer_set : 1;
	unsigned int verify_rules_set : 1;
	unsigned int pem_format_output : 1;
	unsigned int skip_signature_verification : 1;

	struct pkcs7_x509 *x509;

	void *aux_data;
	size_t aux_datalen;
};

int pkcs7_check_file(const char *file);
int pkcs7_collect_signer(struct pkcs7_generator_opts *opts);
int pkcs7_collect_x509(struct pkcs7_generator_opts *opts);
int pkcs7_collect_trust(struct pkcs7_generator_opts *opts);
int pkcs7_set_data(struct pkcs7_generator_opts *opts);
int pkcs7_dump_file(struct pkcs7_generator_opts *opts);
int pkcs7_gen_message(struct pkcs7_generator_opts *opts);
void pkcs7_clean_opts(struct pkcs7_generator_opts *opts);

#ifdef __cplusplus
}
#endif

#endif /* LC_PKCS7_GENERATOR_HELPER_H */
