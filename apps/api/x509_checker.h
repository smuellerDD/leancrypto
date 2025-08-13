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

#ifndef X509_CHECKER_H
#define X509_CHECKER_H

#include "ext_headers_internal.h"
#include "lc_pkcs7_parser.h"
#include "lc_x509_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

enum asn1_test_type {
	asn1_type_undefined,
	asn1_type_pkcs7,
	asn1_type_x509,
	asn1_type_verify,
};

struct x509_checker_options {
	const char *file;
	const char *verified_file;
	enum asn1_test_type asn1_type;

	unsigned int check_ca : 1;
	unsigned int check_ca_conformant : 1;
	unsigned int check_root_ca : 1;
	unsigned int check_time : 1;
	unsigned int check_no_ca : 1;
	unsigned int check_selfsigned : 1;
	unsigned int check_no_selfsigned : 1;
	unsigned int unsupported_sig : 1;
	unsigned int print_cert_details : 1;
	unsigned int cert_may_be_invalid : 1;
	unsigned int eku;
	unsigned int keyusage;
	const char *issuer_cn;
	const char *subject_cn;
	const char *san_dns;
	const char *san_ip;
	const char *skid;
	const char *akid;
	uint64_t valid_from;
	uint64_t valid_to;
};

int apply_checks_x509(const struct lc_x509_certificate *x509,
		      const struct x509_checker_options *parsed_opts);

int apply_checks_pkcs7(const struct lc_pkcs7_message *pkcs7_msg,
		       const struct x509_checker_options *parsed_opts);

#ifdef __cplusplus
}
#endif

#endif /* X509_CHECKER_H */
