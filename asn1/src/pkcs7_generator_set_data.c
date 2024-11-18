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

#include "lc_sha3.h"
#include "lc_memory_support.h"
#include "lc_pkcs7_generator.h"
#include "lc_x509_parser.h"
#include "ret_checkers.h"
#include "visibility.h"

static int pkcs7_add_cert(struct pkcs7_message *pkcs7,
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

static int pkcs7_add_signer(struct pkcs7_message *pkcs7,
			    struct pkcs7_signed_info *sinfo)
{
	struct pkcs7_signed_info *tmpsinfo;

	if (!pkcs7->signed_infos) {
		pkcs7->signed_infos = sinfo;
	} else {
		for (tmpsinfo = pkcs7->signed_infos; tmpsinfo;
		     tmpsinfo = tmpsinfo->next) {
			if (!tmpsinfo->next) {
				tmpsinfo->next = sinfo;
				break;
			}
		}
	}

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_set_certificate,
		      struct pkcs7_message *pkcs7,
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

LC_INTERFACE_FUNCTION(int, lc_pkcs7_set_signer, struct pkcs7_message *pkcs7,
		      struct lc_x509_certificate *x509_with_sk)
{
	struct pkcs7_signed_info *sinfo = NULL;
	int ret;

	CKNULL(pkcs7, -EINVAL);
	CKNULL(x509_with_sk, -EINVAL);

	/* Check that we have an X.509 key */
	CKNULL(x509_with_sk, -EINVAL);

	/* Check that keys were set */
	CKNULL(x509_with_sk->sig_gen_data.sig_type, -EINVAL);
	CKNULL(x509_with_sk->sig_gen_data.pk.dilithium_pk, -EINVAL);
	CKNULL(x509_with_sk->sig_gen_data.sk.dilithium_sk, -EINVAL);

	CKINT(lc_alloc_aligned((void **)&sinfo, 8,
			       sizeof(struct pkcs7_signed_info)));

	/* Also set the certificate as signer */
	sinfo->signer = x509_with_sk;

	/* Set the authenticated attributes to be generated */
	sinfo->aa_set = sinfo_has_content_type | sinfo_has_signing_time |
			sinfo_has_message_digest;

	/* Set the hash algorithm to be used */
	sinfo->sig.hash_algo = lc_sha3_512;

	/*
	 * Add the certificate to the PKCS#7 structure for being added to the
	 * PKCS#7 message to be generated.
	 */
	CKINT(pkcs7_add_cert(pkcs7, sinfo->signer));

	/* Add the signer information to the PKCS#7 message */
	CKINT(pkcs7_add_signer(pkcs7, sinfo));

	sinfo = NULL;

out:
	lc_free(sinfo);
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs7_set_data, struct pkcs7_message *pkcs7,
		      const uint8_t *data, size_t data_len)
{
	int ret = 0;

	CKNULL(pkcs7, -EINVAL);
	CKNULL(data, -EINVAL);

	pkcs7->data = data;
	pkcs7->data_len = data_len;
	pkcs7->data_type = OID_data;

out:
	return ret;
}
