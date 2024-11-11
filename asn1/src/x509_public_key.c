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
#include "lc_memcmp_secure.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "x509_algorithm_mapper.h"
#include "x509_cert_parser.h"

/*
 * Set up the signature parameters in an X.509 certificate.  This involves
 * digesting the signed data and extracting the signature.
 */
static int _x509_get_sig_params(struct lc_x509_certificate *cert,
				const struct lc_hash *hash_algo)
{
	struct lc_public_key_signature *sig = &cert->sig;
	int ret = 0;
	LC_HASH_CTX_ON_STACK(hash_ctx, hash_algo);

	printf_debug("==>%s()\n", __func__);

	lc_hash_init(hash_ctx);
	sig->digest_size = lc_hash_digestsize(hash_ctx);
	if (sig->digest_size > sizeof(sig->digest)) {
		ret = -ENOMEM;
		goto out;
	}
	printf_debug("Digest size %zu\n", sig->digest_size);

	lc_hash_update(hash_ctx, cert->tbs, cert->tbs_size);
	lc_hash_final(hash_ctx, sig->digest);
	lc_hash_zero(hash_ctx);

out:
	printf_debug("<==%s() = %d\n", __func__, 0);
	return ret;
}

int x509_get_sig_params(struct lc_x509_certificate *cert)
{
	struct lc_public_key_signature *sig = &cert->sig;
	const struct lc_hash *hash_algo;
	int ret = 0;

	sig->s = cert->raw_sig;
	sig->s_size = cert->raw_sig_size;

	CKINT(lc_x509_sig_type_to_hash(sig->pkey_algo, &hash_algo));

	/*
	 * If a hash algo was set, apply it to the main data, otherwise
	 * register the main data for later processing directly as part of the
	 * signature operation.
	 */
	if (hash_algo) {
		CKINT(_x509_get_sig_params(cert, hash_algo));
	} else {
		sig->raw_data = cert->tbs;
		sig->raw_data_len = cert->tbs_size;
	}

out:
	return ret;
}

/*
 * Check for self-signedness in an X.509 cert and if found, check the signature
 * immediately if we can.
 */
int x509_check_for_self_signed(struct lc_x509_certificate *cert)
{
	struct lc_public_key_signature *sig = &cert->sig;
	struct lc_asymmetric_key_id *auth_id_0 = &sig->auth_ids[0];
	struct lc_asymmetric_key_id *auth_id_1 = &sig->auth_ids[1];

	int ret = 0;

	printf_debug("==>%s()\n", __func__);

	if (lc_memcmp_secure(cert->raw_subject, cert->raw_subject_size,
			     cert->raw_issuer, cert->raw_issuer_size))
		goto not_self_signed;

	if (auth_id_0->len || auth_id_1->len) {
		/*
		 * If the AKID is present it may have one or two parts.  If
		 * both are supplied, both must match.
		 */
		int a = asymmetric_key_id_same(&cert->skid, auth_id_1);
		int b = asymmetric_key_id_same(&cert->id, auth_id_0);

		if (!a && !b)
			goto not_self_signed;

		if (((a && !b) || (b && !a)) && auth_id_0->len &&
		    auth_id_1->len) {
			ret = -EKEYREJECTED;
			goto out;
		}
	}

	if (cert->unsupported_sig) {
		ret = 0;
		goto out;
	}

	ret = public_key_verify_signature(&cert->pub, &cert->sig);
	if (ret < 0) {
		if (ret == -ENOPKG) {
			cert->unsupported_sig = 1;
			ret = 0;
#ifdef LC_PKCS7_DEBUG
			cert->self_signed = 1;
#endif
		}
		goto out;
	}

	cert->self_signed = 1;

out:
	printf_debug("<==%s() = %d [self-signed]\n", __func__, ret);
	return ret;

not_self_signed:
	printf_debug("<==%s() = %d [not self-signed]\n", __func__, ret);
	return ret;
}
