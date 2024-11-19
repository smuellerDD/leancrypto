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

#ifndef PKCS7_INTERNAL_H
#define PKCS7_INTERNAL_H

#include "lc_pkcs7_parser.h"
#include "ret_checkers.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pkcs7_parse_context {
	struct lc_pkcs7_message *msg; /* Message being constructed */
	struct lc_pkcs7_signed_info *sinfo; /* SignedInfo being constructed */
	struct lc_pkcs7_signed_info **ppsinfo; /* linked list of signer info */
	struct lc_x509_certificate *certs; /* Certificate cache */
	struct lc_x509_certificate **ppcerts; /* linked list of certs */
	const uint8_t *data; /* Start of data */
	enum OID last_oid; /* Last OID encountered */
	unsigned int x509_index;
	unsigned int sinfo_index;
	size_t raw_serial_size;
	size_t raw_issuer_size;
	size_t raw_skid_size;
	const uint8_t *raw_serial;
	const uint8_t *raw_issuer;
	const uint8_t *raw_skid;
	unsigned int expect_skid : 1; /* Subject key ID */
};

int pkcs7_verify_sig_chain(struct lc_x509_certificate *certificate_chain,
			   const struct lc_pkcs7_trust_store *trust_store,
			   struct lc_x509_certificate *x509,
			   struct lc_pkcs7_signed_info *sinfo);

int
pkcs7_find_asymmetric_key(struct lc_x509_certificate **anchor_cert,
			  const struct lc_pkcs7_trust_store *trust_store,
			  const struct lc_asymmetric_key_id *auth0,
			  const struct lc_asymmetric_key_id *auth1);

#ifdef __cplusplus
}
#endif

#endif /* PKCS7_INTERNAL_H */
