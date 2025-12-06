/* PKCS#8 Parser following RFC5958
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
 * This code is derived in parts from the PKCS7 parser pkcs7_parser.c and
 * x509_cert_parser.c.
 */

#include "asn1_debug.h"
#include "asym_key.h"
#include "ext_headers_internal.h"
#include "lc_pkcs8_common.h"
#include "lc_pkcs8_parser.h"
#include "lc_x509_generator.h"
#include "oid_registry.h"
#include "pkcs8_asn1.h"
#include "pkcs8_internal.h"
#include "ret_checkers.h"
#include "visibility.h"
#include "x509_algorithm_mapper.h"

/******************************************************************************
 * Parser helper functions
 ******************************************************************************/

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int lc_pkcs8_note_OID(void *context, size_t hdrlen, unsigned char tag,
		      const uint8_t *value, size_t vlen)
{
	struct pkcs8_parse_context *ctx = context;

	(void)hdrlen;
	(void)tag;

	ctx->last_oid = lc_look_up_OID(value, vlen);

	if (ctx->last_oid == OID__NR) {
		char buffer[50];

		lc_sprint_oid(value, vlen, buffer, sizeof(buffer));
		printf_debug("PKCS7: Unknown OID: [%lu] %s\n",
			     value - ctx->data, buffer);
	}
	return 0;
}

int lc_pkcs8_note_version(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	(void)context;
	(void)hdrlen;
	(void)tag;

	if (vlen != 1) {
		printf_debug("Missing PKCS#8 version\n");
		return -EBADMSG;
	}

	switch (((const uint8_t *)value)[0]) {
	case 0:
		/*
		 * This implementation only supports version 1 which according
		 * to RFC5958 chapter 2 complies with the following statement:
		 * "When v1, PrivateKeyInfo is the same as it was in [RFC5208]".
		 */
		break;
	case 1:
		/*
		 * This implementation as of now does not cover the inclusion
		 * of the public key with the OneAsymmetricKey definition.
		 */
		fallthrough;
	default:
		printf_debug("Unsupported PKCS#8 version\n");
		return -EBADMSG;
	}

	return 0;
}

/*
 * Record the algorithm of the private key and convert it to the internal
 * representation.
 */
int lc_pkcs8_note_algo(void *context, size_t hdrlen, unsigned char tag,
		       const uint8_t *value, size_t vlen)
{
	struct pkcs8_parse_context *ctx = context;
	struct lc_x509_key_data *keypair = ctx->privkey;
	int ret;

	(void)hdrlen;
	(void)tag;
	(void)value;
	(void)vlen;

	CKINT(lc_x509_oid_to_sig_type(ctx->last_oid, &keypair->sig_type));

out:
	return ret;
}

/*
 * Obtain the private key data and parse it into the leancrypto key structure.
 */
int lc_pkcs8_note_key(void *context, size_t hdrlen, unsigned char tag,
		      const uint8_t *value, size_t vlen)
{
	struct pkcs8_parse_context *ctx = context;
	struct lc_x509_key_data *privkey = ctx->privkey;
	int ret;

	(void)hdrlen;
	(void)tag;

	CKINT(lc_privkey_key_decode(privkey, value, vlen));

	printf_debug("Public Key type %u\n", privkey->sig_type);

out:
	return ret;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(void, lc_pkcs8_message_clear,
		      struct lc_pkcs8_message *pkcs8)
{
	if (pkcs8)
		lc_memset_secure(pkcs8, 0, sizeof(struct lc_pkcs8_message));
}

/*
 * Parse a PKCS#8 private key blob.
 */
LC_INTERFACE_FUNCTION(int, lc_pkcs8_decode, struct lc_pkcs8_message *pkcs8,
		      const uint8_t *data, size_t datalen)
{
	struct pkcs8_parse_context ctx = { 0 };
	struct lc_x509_key_data *privkey = &pkcs8->privkey;
	struct lc_x509_priv_key_data *privkey_data = &pkcs8->privkey_data;
	int ret;

	CKNULL(pkcs8, -EINVAL);
	CKNULL(data, -EINVAL);

	ctx.data = data;
	ctx.privkey = privkey;

	/*
	 * Link the common key structure of privkey to the buffer that may hold
	 * the privkey. Also, set the pubkey to NULL.
	 */
	LC_PKCS8_LINK_PRIVKEY_DATA(privkey, privkey_data);
	pkcs8->privkey_ptr = privkey;

	/* Attempt to decode the PKCS#8 blob */
	CKINT_LOG(
		lc_asn1_ber_decoder(&lc_pkcs8_decoder, &ctx, data, datalen),
		"Parsing of data as PKCS#8 failed - perhaps it is a raw secret key?\n");

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_pkcs8_signature_gen, uint8_t *sig_data,
		      size_t *siglen, const struct lc_pkcs8_message *pkcs8,
		      const uint8_t *m, size_t mlen,
		      const struct lc_hash *prehash_algo)
{
#ifdef LC_X509_GENERATOR
	int ret;

	CKNULL(pkcs8, -EINVAL);

	CKINT(lc_x509_signature_gen(sig_data, siglen, &pkcs8->privkey, m, mlen,
				    prehash_algo));

out:
	return ret;
#else
	(void)sig_data;
	(void)siglen;
	(void)pkcs8;
	(void)m;
	(void)mlen;
	(void)prehash_algo;
	return -EOPNOTSUPP;
#endif
}
