/* PKCS#8 Generator following RFC5958
 *
 * Copyright (C) 2025, Stephan Mueller <smueller@chronox.de>
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
 * This code is derived in parts from the PKCS7 parser pkcs7_generator.c and
 * x509_cert_generator.c.
 */

#include "asn1_debug.h"
#include "asym_key.h"
#include "ext_headers_internal.h"
#include "lc_pkcs8_common.h"
#include "lc_pkcs8_generator.h"
#include "lc_x509_generator.h"
#include "oid_registry.h"
#include "pkcs8_asn1.h"
#include "pkcs8_internal.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "x509_algorithm_mapper.h"

struct pkcs8_generate_context {
	/*
	  * Message being converted into PKCS#8 blob
	  */
	const struct lc_pkcs8_message *pkcs8;
};

/******************************************************************************
 * Generator helper functions
 ******************************************************************************/

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int lc_pkcs8_note_OID_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	const struct pkcs8_generate_context *ctx = context;
	const struct lc_pkcs8_message *pkcs8 = ctx->pkcs8;
	const struct lc_x509_key_data *privkey = pkcs8->privkey_ptr;
	const uint8_t *oid_data = NULL;
	size_t oid_datalen = 0;
	enum OID oid;
	int ret;

	(void)tag;

	CKINT(lc_x509_sig_type_to_oid(privkey->sig_type, &oid));

	CKINT(lc_OID_to_data(oid, &oid_data, &oid_datalen));
	bin2print_debug(oid_data, oid_datalen, stdout,
			"OID signed pkey algorithm");

	if (oid_datalen) {
		CKINT(lc_x509_sufficient_size(avail_datalen, oid_datalen));

		memcpy(data, oid_data, oid_datalen);
		*avail_datalen -= oid_datalen;
	}

out:
	return ret;
}

int lc_pkcs8_note_version_enc(void *context, uint8_t *data,
			      size_t *avail_datalen, uint8_t *tag)
{
	/*
	 * This implementation only supports version 1 which according
	 * to RFC5958 chapter 2 complies with the following statement:
	 * "When v1, PrivateKeyInfo is the same as it was in [RFC5208]".
	 */
	static const uint8_t pkcs8_version = 0;
	int ret;

	(void)context;
	(void)tag;

	CKINT(lc_x509_sufficient_size(avail_datalen, sizeof(pkcs8_version)));

	data[0] = pkcs8_version;
	*avail_datalen -= sizeof(pkcs8_version);
	printf_debug("Set PKCS#8 version %u\n", pkcs8_version);

out:
	return ret;
}

int lc_pkcs8_note_algo_enc(void *context, uint8_t *data, size_t *avail_datalen,
			   uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;

	return 0;
}

/*
 * Obtain the private key data and parse it into the leancrypto key structure.
 */
int lc_pkcs8_note_key_enc(void *context, uint8_t *data, size_t *avail_datalen,
			  uint8_t *tag)
{
	const struct pkcs8_generate_context *ctx = context;
	const struct lc_pkcs8_message *pkcs8 = ctx->pkcs8;
	struct x509_generate_privkey_context privkey_ctx;
	int ret;

	(void)tag;

	privkey_ctx.keys = pkcs8->privkey_ptr;

	CKINT(lc_privkey_key_encode(&privkey_ctx, data, avail_datalen));

	printf_debug("Setting private key type %u\n", pkcs8->privkey.sig_type);

out:
	return ret;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_pkcs8_set_privkey, struct lc_pkcs8_message *pkcs8,
		      const struct lc_x509_key_data *privkey)
{
	int ret = 0;

	CKNULL(pkcs8, -EINVAL);
	CKNULL(privkey, -EINVAL);

	pkcs8->privkey_ptr = privkey;

out:
	return ret;
}

/*
 * Parse a PKCS#8 private key blob.
 */
LC_INTERFACE_FUNCTION(int, lc_pkcs8_encode,
		      const struct lc_pkcs8_message *pkcs8, uint8_t *data,
		      size_t *avail_datalen)
{
	struct pkcs8_generate_context ctx = { 0 };
	int ret;

	CKNULL(pkcs8, -EINVAL);
	CKNULL(data, -EINVAL);
	CKNULL(avail_datalen, -EINVAL);

	ctx.pkcs8 = pkcs8;

	/* Attempt to decode the signature */
	CKINT(lc_asn1_ber_encoder(&lc_pkcs8_encoder, &ctx, data,
				  avail_datalen));

out:
	return ret;
}
