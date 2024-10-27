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

#include "asn1.h"
#include "asn1_debug.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "lc_pkcs7.h"
#include "lc_x509.h"
#include "public_key.h"
#include "ret_checkers.h"
#include "visibility.h"

#ifdef LC_PKCS7_DEBUG
#warning                                                                       \
	"LC_PKCS7_DEBUG enabled - code MUST ONLY BE USED FOR TESTING - NEVER IN PRODUCTION!"
#define CKINT_SIGCHECK(x)                                                      \
	{                                                                      \
		ret = x;                                                       \
		if (ret == -ENOPKG) {                                          \
			printf("WARNING: NO SIGNATURE CHECK\n");               \
			ret = 0;                                               \
		}                                                              \
		if (ret < 0)                                                   \
			goto out;                                              \
	}
#else
#define CKINT_SIGCHECK CKINT
#endif

/*
 * Digest the relevant parts of the PKCS#7 data
 */
static int pkcs7_digest(struct pkcs7_message *pkcs7,
			struct pkcs7_signed_info *sinfo)
{
	struct public_key_signature *sig = &sinfo->sig;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, sig->hash_algo);

	printf_debug("==> %s(), %u\n", __func__, sinfo->index);

	/* The digest was calculated already. */
	if (sig->digest_size)
		return 0;

	if (!sig->hash_algo)
		return -ENOPKG;

	/* Digest the message [RFC5652 5.4] */
	lc_hash_init(hash_ctx);
	sig->digest_size = lc_hash_digestsize(hash_ctx);
	if (sig->digest_size > sizeof(sig->digest)) {
		ret = -ENOMEM;
		goto out;
	}

	lc_hash_update(hash_ctx, pkcs7->data, pkcs7->data_len);
	lc_hash_final(hash_ctx, sig->digest);
	lc_hash_zero(hash_ctx);

	bin2print_debug(sig->digest, sig->digest_size, stdout, "messageDigest");

	/*
	 * However, if there are authenticated attributes, there must be a
	 * message digest attribute amongst them which corresponds to the
	 * digest we just calculated.
	 */
	if (sinfo->authattrs) {
		uint8_t tag;

		if (!sinfo->msgdigest) {
			printf_debug("Sig %u: No messageDigest\n",
				     sinfo->index);
			ret = -EKEYREJECTED;
			goto out;
		}

		if (sinfo->msgdigest_len != sig->digest_size) {
			printf_debug("Sig %u: Invalid digest size (%zu)\n",
				     sinfo->index, sinfo->msgdigest_len);
			ret = -EBADMSG;
			goto out;
		}

		if (memcmp(sig->digest, sinfo->msgdigest,
			   sinfo->msgdigest_len) != 0) {
			printf_debug("Sig %u: Message digest doesn't match\n",
				     sinfo->index);
			bin2print_debug(sinfo->msgdigest, sinfo->msgdigest_len,
					stdout, "signerInfos messageDigest");
			ret = -EKEYREJECTED;
			goto out;
		}

		/*
		 * We then calculate anew, using the authenticated attributes
		 * as the contents of the digest instead.  Note that we need to
		 * convert the attributes from a CONT.0 into a SET before we
		 * hash it.
		 */
		memset(sig->digest, 0, sig->digest_size);
		lc_hash_init(hash_ctx);
		tag = ASN1_CONS_BIT | ASN1_SET;
		lc_hash_update(hash_ctx, &tag, 1);
		lc_hash_update(hash_ctx, sinfo->authattrs,
			       sinfo->authattrs_len);
		lc_hash_final(hash_ctx, sig->digest);
		lc_hash_zero(hash_ctx);

		bin2print_debug(sinfo->msgdigest, sinfo->msgdigest_len, stdout,
				"signerInfos AADigest");
	}

out:
	printf_debug("<== %s(),  = %d\n", __func__, ret);
	return ret;
}

/*
 * Find the key (X.509 certificate) to use to verify a PKCS#7 message.  PKCS#7
 * uses the issuer's name and the issuing certificate serial number for
 * matching purposes.  These must match the certificate issuer's name (not
 * subject's name) and the certificate serial number [RFC 2315 6.7].
 */
static int pkcs7_find_key(struct pkcs7_message *pkcs7,
			  struct pkcs7_signed_info *sinfo)
{
	struct x509_certificate *x509;
	struct public_key_signature *sig = &sinfo->sig;
	struct asymmetric_key_id *sig_auth_id = &sig->auth_ids[0];
	struct asymmetric_key_id *cert_auth_id;

	unsigned int certix = 1;

	printf_debug("==> %s(), %u\n", __func__, sinfo->index);

	for (x509 = pkcs7->certs; x509; x509 = x509->next, certix++) {
		cert_auth_id = &x509->id;

		/* I'm _assuming_ that the generator of the PKCS#7 message will
		 * encode the fields from the X.509 cert in the same way in the
		 * PKCS#7 message - but I can't be 100% sure of that.  It's
		 * possible this will need element-by-element comparison.
		 */
		if (!asymmetric_key_id_same(cert_auth_id, sig_auth_id))
			continue;
		printf_debug("Sig %u: Found cert serial match X.509[%u]\n",
			     sinfo->index, certix);

		sinfo->signer = x509;
		return 0;
	}

	/* The relevant X.509 cert isn't found here, but it might be found in
	 * the trust keyring.
	 */
	printf_debug("Sig %u: Issuing X.509 cert not found (#%*phN)\n",
		     sinfo->index, sig_auth_id->len, sig_auth_id->data);
	return 0;
}

/*
 * Verify the internal certificate chain as best we can.
 */
static int pkcs7_verify_sig_chain(struct pkcs7_message *pkcs7,
				  struct pkcs7_signed_info *sinfo)
{
	struct public_key_signature *sig;
	struct x509_certificate *x509 = sinfo->signer, *p;
	struct asymmetric_key_id *auth0, *auth1;
	int ret = 0;

	printf_debug("==> %s()\n", __func__);

	for (p = pkcs7->certs; p; p = p->next)
		p->seen = 0;

	for (;;) {
		bin2print_debug(x509->raw_serial, x509->raw_serial_size, stdout,
				"verify");
		x509->seen = 1;

		if (x509->blacklisted) {
			/* If this cert is blacklisted, then mark everything
			 * that depends on this as blacklisted too.
			 */
			sinfo->blacklisted = 1;
			for (p = sinfo->signer; p != x509; p = p->signer)
				p->blacklisted = 1;
			printf_debug("- blacklisted\n");
			return 0;
		}

		printf_debug("- issuer %s\n", x509->issuer);
		sig = &x509->sig;
		auth0 = &sig->auth_ids[0];
		auth1 = &sig->auth_ids[1];
		if (auth0->len) {
			bin2print_debug(auth0->data, auth0->len, stdout,
					"- authkeyid.id");
		}
		if (auth1->len) {
			bin2print_debug(auth1->data, auth1->len, stdout,
					"- authkeyid.skid");
		}

		if (x509->self_signed) {
			/* If there's no authority certificate specified, then
			 * the certificate must be self-signed and is the root
			 * of the chain.  Likewise if the cert is its own
			 * authority.
			 */
			if (x509->unsupported_sig)
				goto unsupported_sig_in_x509;
			x509->signer = x509;
			printf_debug("- self-signed\n");
			return 0;
		}

		/* Look through the X.509 certificates in the PKCS#7 message's
		 * list to see if the next one is there.
		 */
		if (auth0->len) {
			bin2print_debug(auth0->data, auth0->len, stdout,
					"- want");
			for (p = pkcs7->certs; p; p = p->next) {
				printf_debug("- cmp [%u] ", p->index);
				bin2print_debug(p->id.data, p->id.len, stdout,
						"");

				if (asymmetric_key_id_same(&p->id, auth0))
					goto found_issuer_check_skid;
			}
		} else if (auth1->len) {
			bin2print_debug(auth1->data, auth1->len, stdout,
					"- want");
			for (p = pkcs7->certs; p; p = p->next) {
				if (!p->skid.len)
					continue;
				printf_debug("- cmp [%u] ", p->index);
				bin2print_debug(p->skid.data, p->skid.len,
						stdout, "");
				if (asymmetric_key_id_same(&p->skid, auth1))
					goto found_issuer;
			}
		}

		/* We didn't find the root of this chain */
		printf_debug("- top\n");
		return 0;

	found_issuer_check_skid:
		/* We matched issuer + serialNumber, but if there's an
		 * authKeyId.keyId, that must match the CA subjKeyId also.
		 */
		if (auth1->len && !asymmetric_key_id_same(&p->skid, auth1)) {
			printf_debug(
				"Sig %u: X.509 chain contains auth-skid nonmatch (%u->%u)\n",
				sinfo->index, x509->index, p->index);
			return -EKEYREJECTED;
		}
	found_issuer:
		printf_debug("- subject %s\n", p->subject);
		if (p->seen) {
			printf_debug("Sig %u: X.509 chain contains loop\n",
				     sinfo->index);
#ifdef LC_PKCS7_DEBUG
			/*
			 * The root CA detection below will not work in debug
			 * mode.
			 */
			return 0;
#else
			return -EKEYREJECTED;
#endif
		}
		CKINT_SIGCHECK(
			public_key_verify_signature(&p->pub, &x509->sig));
		x509->signer = p;
		CKINT(lc_x509_policy_is_root_ca(p));
		if (ret == LC_X509_POL_TRUE) {
			printf_debug("- root CA\n");
			return 0;
		}

		x509 = p;
	}

unsupported_sig_in_x509:
out:
	/* Just prune the certificate chain at this point if we lack some
	 * crypto module to go further.  Note, however, we don't want to set
	 * sinfo->unsupported_crypto as the signed info block may still be
	 * validatable against an X.509 cert lower in the chain that we have a
	 * trusted copy of.
	 */
	return ret;
}

/*
 * Verify one signed information block from a PKCS#7 message.
 */
static int pkcs7_verify_one(struct pkcs7_message *pkcs7,
			    struct pkcs7_signed_info *sinfo)
{
	int ret;

	printf_debug("==> %s(), %u\n", __func__, sinfo->index);

	/* First of all, digest the data in the PKCS#7 message and the
	 * signed information block
	 */
	CKINT(pkcs7_digest(pkcs7, sinfo));

	/* Find the key for the signature if there is one */
	CKINT(pkcs7_find_key(pkcs7, sinfo));

	CKNULL(sinfo->signer, 0);

	printf_debug("Using X.509[%u] for sig %u\n", sinfo->signer->index,
		     sinfo->index);

	/* Check that the PKCS#7 signing time is valid according to the X.509
	 * certificate.  We can't, however, check against the system clock
	 * since that may not have been set yet and may be wrong.
	 */
	if (sinfo->aa_set & sinfo_has_signing_time) {
		if (sinfo->signing_time < sinfo->signer->valid_from ||
		    sinfo->signing_time > sinfo->signer->valid_to) {
			printf_debug(
				"Message signed outside of X.509 validity window\n");
			return -EKEYREJECTED;
		}
	}

	/* Verify the PKCS#7 binary against the key */
	CKINT_SIGCHECK(
		public_key_verify_signature(&sinfo->signer->pub, &sinfo->sig));

	printf_debug("Verified signature %u\n", sinfo->index);

	/* Verify the internal certificate chain */
	CKINT(pkcs7_verify_sig_chain(pkcs7, sinfo));

out:
	return ret;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_pkcs7_get_digest, struct pkcs7_message *pkcs7,
		      const uint8_t **message_digest,
		      size_t *message_digest_len,
		      const struct lc_hash **hash_algo)
{
	struct pkcs7_signed_info *sinfo = pkcs7->signed_infos;
	int ret;

	CKNULL(message_digest, -EBADMSG);
	CKNULL(message_digest_len, -EBADMSG);

	/*
	 * This function doesn't support messages with more than one signature.
	 */
	CKNULL(sinfo, -EBADMSG);
	if (sinfo->next != NULL)
		return -EBADMSG;

	CKINT(pkcs7_digest(pkcs7, sinfo));

	*message_digest = sinfo->sig.digest;
	*message_digest_len = sinfo->sig.digest_size;

	if (hash_algo)
		*hash_algo = sinfo->sig.hash_algo;

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_verify, struct pkcs7_message *pkcs7)
{
	struct pkcs7_signed_info *sinfo;
	int actual_ret = -ENOPKG;
	int ret;

	if (!pkcs7)
		return -EINVAL;

	printf_debug("==> %s(), ", __func__);

	if (pkcs7->data_type != OID_data) {
		printf_debug("Invalid sig (not pkcs7-data)\n");
		return -EKEYREJECTED;
	}

	if (!pkcs7->data) {
		printf_debug("EncapsulatedContent missing\n");
		return -ENODATA;
	}

	for (sinfo = pkcs7->signed_infos; sinfo; sinfo = sinfo->next) {
		ret = pkcs7_verify_one(pkcs7, sinfo);
		if (sinfo->blacklisted) {
			if (actual_ret == -ENOPKG)
				actual_ret = -EKEYREJECTED;
			continue;
		}
		if (ret < 0) {
			if (ret == -ENOPKG) {
				sinfo->unsupported_crypto = 1;
				continue;
			}
			printf_debug("<== %s() = %d\n", __func__, ret);
			return ret;
		}
		actual_ret = 0;
	}

	printf_debug("<== %s() = %d\n", __func__, actual_ret);
	return actual_ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_supply_detached_data,
		      struct pkcs7_message *pkcs7, const uint8_t *data,
		      size_t datalen)
{
	if (!pkcs7)
		return -EINVAL;

	if (pkcs7->data) {
		printf_debug("Data already supplied\n");
		return -EEXIST;
	}

	pkcs7->data = data;
	pkcs7->data_len = datalen;

	return 0;
}