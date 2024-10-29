/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "asn1_debug.h"
#include "asymmetric_type.h"
#include "lc_pkcs7.h"
#include "pkcs7_internal.h"
#include "public_key.h"
#include "ret_checkers.h"
#include "visibility.h"

static int pkcs7_find_asymmetric_key(
	struct x509_certificate **anchor_cert,
	const struct pkcs7_trust_store *trust_store,
	const struct asymmetric_key_id *auth0,
	const struct asymmetric_key_id *auth1)
{
	struct x509_certificate *p;

	/* Look through the X.509 certificates in the PKCS#7 message's
		* list to see if the next one is there.
		*/
	if (auth0 && auth0->len) {
		bin2print_debug(auth0->data, auth0->len, stdout, "- want");
		for (p = trust_store->anchor_cert; p; p = p->next) {
			printf_debug("- cmp [%u] ", p->index);
			bin2print_debug(p->id.data, p->id.len, stdout,
					"");

			if (asymmetric_key_id_same(&p->id, auth0))
				goto found_issuer_check_skid;
		}
	} else if (auth1 && auth1->len) {
		bin2print_debug(auth1->data, auth1->len, stdout, "- want");
		for (p = trust_store->anchor_cert; p; p = p->next) {
			if (!p->skid.len)
				continue;
			printf_debug("- cmp [%u] ", p->index);
			bin2print_debug(p->skid.data, p->skid.len,
					stdout, "");
			if (asymmetric_key_id_same(&p->skid, auth1))
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
	if (auth1 && auth1->len && !asymmetric_key_id_same(&p->skid, auth1)) {
		bin2print_debug(auth1->data, auth1->len, stdout,
				"Mismatch: AuthKeyID wanted");
		bin2print_debug(p->id.data, p->id.len, stdout,
				"Mismatch: CA SubjectKeyID found");
		return -EKEYREJECTED;
	}
found_issuer:
	printf_debug("- subject %s\n", p->subject);

	*anchor_cert = p;

	/* Just prune the certificate chain at this point if we lack some
	 * crypto module to go further.  Note, however, we don't want to set
	 * sinfo->unsupported_crypto as the signed info block may still be
	 * validatable against an X.509 cert lower in the chain that we have a
	 * trusted copy of.
	 */
	return 0;
}

/*
 * Check the trust on one PKCS#7 SignedInfo block.
 */
static int pkcs7_validate_trust_one(struct pkcs7_signed_info *sinfo,
				    struct pkcs7_trust_store *trust_store)
{
	struct public_key_signature *sig = &sinfo->sig;
	struct x509_certificate *x509, *last = NULL, *p, *anchor_cert;
	int ret;

	printf_debug("Validating signer at index %u\n", sinfo->index);

	if (sinfo->unsupported_crypto) {
		printf_debug(" = -ENOPKG [cached]");
		return -ENOPKG;
	}

	for (x509 = sinfo->signer; x509; x509 = x509->signer) {
		if (x509->seen) {
			if (x509->verified)
				goto verified;
			printf_debug(" = -ENOKEY [cached]");
			return -ENOKEY;
		}
		x509->seen = 1;

		/*
		 * Look to see if this certificate is present in the trusted
		 * keys.
		 */
		ret = pkcs7_find_asymmetric_key(&anchor_cert, trust_store,
						&x509->id, &x509->skid);
		if (!ret) {
			/*
			 * One of the X.509 certificates in the PKCS#7 message
			 * is apparently the same as one we already trust.
			 * Verify that the trusted variant can also validate
			 * the signature on the descendant.
			 */
			printf_debug("sinfo %u: Cert %u identity match\n",
				     sinfo->index, x509->index);
			goto matched;
		}
		if (ret != -ENOKEY)
			return ret;

		 /*
		  * Self-signed certificates form roots of their own, and if we
		  * don't know them, then we can't accept them.
		  */
		if (x509->signer == x509) {
			printf_debug(" = -ENOKEY [unknown self-signed]");
			return -ENOKEY;
		}

		last = x509;
		sig = &last->sig;
	}

	/*
	 * No match - see if the root certificate has a signer amongst the
	 * trusted keys.
	 */
	if (last && (last->sig.auth_ids[0].len || last->sig.auth_ids[1].len)) {
		ret = pkcs7_find_asymmetric_key(&anchor_cert, trust_store,
						&last->sig.auth_ids[0],
						&last->sig.auth_ids[1]);
		if (!ret) {
			x509 = last;
			printf_debug("sinfo %u: Root cert %u signer is key ",
				     sinfo->index, x509->index);
			bin2print_debug(anchor_cert->id.data,
					anchor_cert->id.len, stdout, "");
			goto matched;
		}
		if (ret != -ENOKEY)
			return ret;
	}

	/*
	 * As a last resort, see if we have a trusted public key that matches
	 * the signed info directly.
	 */
	ret = pkcs7_find_asymmetric_key(&anchor_cert, trust_store,
					&sinfo->sig.auth_ids[0], NULL);
	if (!ret) {
		printf_debug("sinfo %u: Root cert %u signer is key ",
			     sinfo->index, x509 ? x509->index : 0);
		bin2print_debug(anchor_cert->id.data, anchor_cert->id.len,
				stdout, "");
		x509 = NULL;
		sig = &sinfo->sig;
		goto matched;
	}
	if (ret != -ENOKEY)
		return ret;

	printf_debug(" = -ENOKEY [no backref]");
	return -ENOKEY;

matched:
	CKINT_SIGCHECK(public_key_verify_signature(&anchor_cert->pub, sig));

verified:
	if (x509) {
		x509->verified = 1;
		for (p = sinfo->signer; p != x509; p = p->signer)
			p->verified = 1;
	}
	printf_debug(" = 0");
	return 0;

out:
	printf_debug(" = -EKEYREJECTED [verify %d]", ret);
	return -EKEYREJECTED;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_trust_validate, struct pkcs7_message *pkcs7,
		      struct pkcs7_trust_store *trust_store)
{
	struct pkcs7_signed_info *sinfo;
	struct x509_certificate *p;
	int cached_ret = -ENOKEY;
	int ret;

	if (!pkcs7)
		return -EINVAL;
	if (!trust_store)
		return -ENOKEY;

	for (p = pkcs7->certs; p; p = p->next)
		p->seen = 0;

	for (sinfo = pkcs7->signed_infos; sinfo; sinfo = sinfo->next) {
		ret = pkcs7_validate_trust_one(sinfo, trust_store);
		switch (ret) {
		case -ENOKEY:
			continue;
		case -ENOPKG:
			if (cached_ret == -ENOKEY)
				cached_ret = -ENOPKG;
			continue;
		case 0:
			cached_ret = 0;
			continue;
		default:
			return ret;
		}
	}

	return cached_ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_trust_store_add,
		      struct pkcs7_trust_store *trust_store,
		      struct x509_certificate *x509)
{
	struct x509_certificate *anchor_cert;
	int ret;

	CKNULL(x509, -EINVAL);
	CKNULL(trust_store, -EINVAL);

	CKINT(lc_x509_policy_is_root_ca(x509));
	if (ret != LC_X509_POL_TRUE) {
		printf_debug("Certificate is no root CA, checking certificate chain in trust store\n");

		CKINT(lc_x509_policy_is_ca(x509));

		if (ret != LC_X509_POL_TRUE) {
			printf_debug("Certificate is no CA\n");
			ret = -EKEYREJECTED;
			goto out;
		}

		CKINT(pkcs7_verify_sig_chain(trust_store->anchor_cert, x509,
					     NULL));
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
		if (__sync_val_compare_and_swap(
			&anchor_cert->next, NULL, x509) == NULL)
			goto out;
	}

out:
	return ret;
}

LC_INTERFACE_FUNCTION(void, lc_pkcs7_trust_store_clear,
		      struct pkcs7_trust_store *trust_store)
{
	struct x509_certificate *anchor_cert;

	if (!trust_store) {
		/* Trust store is empty, nothing to do */
		return;
	}

	anchor_cert = trust_store->anchor_cert;

	while (anchor_cert) {
		lc_x509_certificate_clear(anchor_cert);

		anchor_cert = anchor_cert->next;
	}
}
