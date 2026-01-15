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

#include "asn1_debug.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "lc_pkcs7_generator.h"
#include "lc_x509_parser.h"
#include "pkcs7_internal.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "x509_algorithm_mapper.h"

static int pkcs7_add_cert(struct lc_pkcs7_message *pkcs7,
			  struct lc_x509_certificate *x509)
{
	struct lc_x509_certificate *tmpcert;

	if (!pkcs7->certs) {
		pkcs7->certs = x509;
	} else {
		for (tmpcert = pkcs7->certs; tmpcert; tmpcert = tmpcert->next) {
			if (!tmpcert->next) {
				tmpcert->next = x509;
				break;
			}
		}
	}

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_set_certificate,
		      struct lc_pkcs7_message *pkcs7,
		      struct lc_x509_certificate *x509)
{
	int ret;

	CKNULL(pkcs7, -EINVAL);
	CKNULL(x509, -EINVAL);

	/* Check that keys were set */
	CKNULL(x509->raw_cert, -EINVAL);
	CKNULL(x509->raw_cert_size, -EINVAL);

	CKINT(pkcs7_add_cert(pkcs7, x509));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_set_signer, struct lc_pkcs7_message *pkcs7,
		      struct lc_x509_certificate *x509_with_sk,
		      const struct lc_hash *signing_hash,
		      unsigned long auth_attribute)
{
	const struct lc_x509_key_data *sig_gen_data;
	struct lc_pkcs7_signed_info *sinfo = NULL;
	int ret;

	CKNULL(pkcs7, -EINVAL);
	CKNULL(x509_with_sk, -EINVAL);

	sig_gen_data = &x509_with_sk->sig_gen_data;

	/* Check that keys were set */
	CKNULL(sig_gen_data->sig_type, -EINVAL);
	CKNULL(sig_gen_data->pk.dilithium_pk, -EINVAL);
	CKNULL(sig_gen_data->sk.dilithium_sk, -EINVAL);

	CKINT(lc_pkcs7_sinfo_get(&sinfo, pkcs7));

	/* Also set the certificate as signer */
	sinfo->signer = x509_with_sk;

	/*
	 * Safety measure: If authenticated attributes are created, a message
	 * digest of the actual data must be created according to
	 * RFC5652 section 5.3. This is a safety measure, because
	 * lc_pkcs7_external_aa_enc forces the creation of a digest in any
	 * case.
	 *
	 * Also, at a minimum, the  content type must be set if authenticated
	 * attributes are set.
	 */
	if (auth_attribute) {
		auth_attribute |=
			sinfo_has_message_digest | sinfo_has_content_type;
	}

	/* Set the authenticated attributes to be generated */
	sinfo->aa_set = auth_attribute;

	if (!signing_hash) {
		CKINT(lc_x509_sig_type_to_hash(sig_gen_data->sig_type,
					       &sinfo->sig.hash_algo));
	} else {
		CKINT(lc_x509_sig_check_hash(sig_gen_data->sig_type,
					     signing_hash));
		sinfo->sig.hash_algo = signing_hash;
	}

	/*
	 * Add the certificate to the PKCS#7 structure for being added to the
	 * PKCS#7 message to be generated.
	 */
	CKINT(pkcs7_add_cert(pkcs7, sinfo->signer));

	/* Now add the filled signed info to the PKCS7 */
	CKINT(lc_pkcs7_sinfo_add(pkcs7));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_set_data_with_type,
		      struct lc_pkcs7_message *pkcs7, const uint8_t *data,
		      size_t data_len, enum lc_pkcs7_set_data_flags flags,
		      enum OID data_type)
{
	int ret = 0;

	CKNULL(pkcs7, -EINVAL);
	CKNULL(data, -EINVAL);

	if (pkcs7->data)
		return -EAGAIN;

	pkcs7->data = data;
	pkcs7->data_len = data_len;
	pkcs7->data_type = data_type;

	switch (flags) {
	case lc_pkcs7_set_data_embed:
		pkcs7->embed_data = 1;
		break;
	case lc_pkcs7_set_data_noflag:
	default:
		/* Do nothing */
		break;
	}

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_set_data, struct lc_pkcs7_message *pkcs7,
		      const uint8_t *data, size_t data_len,
		      enum lc_pkcs7_set_data_flags flags)
{
	return lc_pkcs7_set_data_with_type(pkcs7, data, data_len, flags,
					   OID_data);
}
