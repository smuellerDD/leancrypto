/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING ANY WAY OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */
/*
 * This code is derived in parts from the Linux kernel
 * License: SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
/*
 * Red Hat granted the following additional license to the leancrypto project:
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "asn1_debug.h"
#include "asym_key.h"
#include "asymmetric_type.h"
#include "lc_pkcs7_parser.h"
#include "pkcs7_internal.h"
#include "ret_checkers.h"
#include "visibility.h"

int lc_pkcs7_find_asymmetric_key(const struct lc_x509_certificate **anchor_cert,
				 const struct lc_pkcs7_trust_store *trust_store,
				 const struct lc_asymmetric_key_id *auth0,
				 const struct lc_asymmetric_key_id *auth1)
{
	const struct lc_x509_certificate *p;

	if (!trust_store)
		return -ENOKEY;

	/*
	 * Look through the X.509 certificates in the PKCS#7 message's
	 * list to see if the next one is there.
	 */
	if (auth0 && auth0->len) {
		bin2print_debug(auth0->data, auth0->len, stdout, "- want");
		for (p = trust_store->anchor_cert; p; p = p->next) {
			printf_debug("- cmp [%u] ", p->index);
			bin2print_debug(p->id.data, p->id.len, stdout, "");

			if (lc_asymmetric_key_id_same(&p->id, auth0))
				goto found_issuer_check_skid;
		}
	} else if (auth1 && auth1->len) {
		bin2print_debug(auth1->data, auth1->len, stdout, "- want");
		for (p = trust_store->anchor_cert; p; p = p->next) {
			if (!p->skid.len)
				continue;
			printf_debug("- cmp [%u] ", p->index);
			bin2print_debug(p->skid.data, p->skid.len, stdout, "");
			if (lc_asymmetric_key_id_same(&p->skid, auth1))
				goto found_issuer;
		}
	}

	/* We didn't find a match */
	printf_debug("- no certificate found in the trust store\n");
	return -ENOKEY;

found_issuer_check_skid:
	/*
	 * We matched issuer + serialNumber, but if there's an authKeyId.keyId,
	 * that must match the CA subjKeyId also.
	 */
	if (auth1 && auth1->len &&
	    !lc_asymmetric_key_id_same(&p->skid, auth1)) {
		bin2print_debug(auth1->data, auth1->len, stdout,
				"Mismatch: AuthKeyID wanted");
		bin2print_debug(p->id.data, p->id.len, stdout,
				"Mismatch: CA SubjectKeyID found");
		return -EKEYREJECTED;
	}
found_issuer:
	printf_debug("- subject %s\n", p->subject_segments.cn.value);

	*anchor_cert = p;

	/* Just prune the certificate chain at this point if we lack some
	 * crypto module to go further.  Note, however, we don't want to set
	 * sinfo->unsupported_crypto as the signed info block may still be
	 * validatable against an X.509 cert lower in the chain that we have a
	 * trusted copy of.
	 */
	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_trust_store_add,
		      struct lc_pkcs7_trust_store *trust_store,
		      struct lc_x509_certificate *x509)
{
	struct lc_x509_certificate *anchor_cert;
	int ret;

	CKNULL(x509, -EINVAL);
	CKNULL(trust_store, -EINVAL);

	CKINT(lc_x509_policy_is_root_ca(x509));
	if (ret != LC_X509_POL_TRUE) {
		printf_debug(
			"Certificate is no root CA, checking certificate chain in trust store\n");

		CKINT(lc_x509_policy_is_ca(x509));

		if (ret != LC_X509_POL_TRUE) {
			printf_debug("Certificate is no CA\n");
			ret = -EKEYREJECTED;
			goto out;
		}

		CKINT(lc_pkcs7_verify_sig_chain(trust_store->anchor_cert, NULL,
						x509, NULL));
	}

	x509->next = NULL;
	ret = 0;

	/*
	 * Try to atomically swap the trust anchor in the list head.
	 */
	if (__sync_val_compare_and_swap(&trust_store->anchor_cert, NULL,
					x509) == NULL)
		goto out;

	/*
	 * Swap did not succeed, which means we must have a head.
	 */
	for (anchor_cert = trust_store->anchor_cert; anchor_cert;
	     anchor_cert = anchor_cert->next) {
		if (__sync_val_compare_and_swap(&anchor_cert->next, NULL,
						x509) == NULL)
			goto out;
	}

out:
	return ret;
}

LC_INTERFACE_FUNCTION(void, lc_pkcs7_trust_store_clear,
		      struct lc_pkcs7_trust_store *trust_store)
{
	struct lc_x509_certificate *anchor_cert, *tmp;

	if (!trust_store) {
		/* Trust store is empty, nothing to do */
		return;
	}

	anchor_cert = trust_store->anchor_cert;

	while (anchor_cert) {
		tmp = anchor_cert;
		anchor_cert = anchor_cert->next;
		lc_x509_cert_clear(tmp);
	}
}
