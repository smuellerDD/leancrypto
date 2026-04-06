/*
 * Copyright (C) 2026, Stephan Mueller <smueller@chronox.de>
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

#include "lc_x509_csr_parser.h"
#include "x509_cert_parser.h"
#include "x509_csr_asn1.h"
#include "ret_checkers.h"
#include "visibility.h"

int lc_x509_note_csr_info(void *context, size_t hdrlen, unsigned char tag,
			  const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)tag;

	printf_debug("x509_note_tbs_certificate(%zu,%02x,%ld,%zu)!\n", hdrlen,
		     tag, value - ctx->data, vlen);

	/*
	 * Although we are having a CSR, the signature is calculated over the
	 * entire CertificationRequestInfo block which is the conceptual
	 * same data as the TBS certificate for X.509.
	 */
	cert->tbs = value - hdrlen;
	cert->tbs_size = vlen + hdrlen;
	return 0;
}

int lc_x509_csr_version(void *context, size_t hdrlen, unsigned char tag,
			const uint8_t *value, size_t vlen)
{
	struct x509_parse_context *ctx = context;
	struct lc_x509_certificate *cert = ctx->cert;

	(void)hdrlen;
	(void)tag;

	if (vlen != 1)
		return -EBADMSG;

	cert->x509_version = value[0];

	/* CSR versions start with zero as version 1 */
	cert->x509_version++;

	switch (cert->x509_version) {
	case 1:
		/* RFC2986 section 4.1 mandates version 0 */
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_x509_csr_decode,
		      struct lc_x509_certificate *x509, const uint8_t *data,
		      size_t datalen)
{
	struct x509_parse_context ctx = { 0 };
	struct lc_x509_key_data *gendata;
	const uint8_t *pk_ptr;
	size_t pk_len;
	int ret;

	CKNULL(x509, -EINVAL);
	CKNULL(data, -EINVAL);

	ctx.cert = x509;
	ctx.data = data;

	x509->raw_cert = data;
	x509->raw_cert_size = datalen;

	/* This certificate is to be handled as a CSR */
	x509->is_csr = 1;

	/* Attempt to decode the certificate */
	CKINT(lc_asn1_ber_decoder(&lc_x509_csr_decoder, &ctx, data, datalen));

	x509->pub.key = ctx.key;
	x509->pub.keylen = ctx.key_size;

	x509->pub.params = ctx.params;
	x509->pub.paramlen = ctx.params_size;

	x509->pub.algo = ctx.key_algo;

	/* Grab the signature bits */
	CKINT(lc_x509_get_sig_params(x509));

	/* Verify the entity's signature */
	CKINT(lc_public_key_verify_signature(&x509->pub, &x509->sig));

	/* Calculate the digest of the pub key */
	CKINT(lc_x509_cert_get_pubkey(x509, &pk_ptr, &pk_len, NULL));
	gendata = &x509->pub_gen_data;
	CKINT(lc_hash(LC_X509_SKID_DEFAULT_HASH, pk_ptr, pk_len,
		      gendata->pk_digest));

	x509->is_csr = 1;

out:
	if (ret)
		lc_x509_cert_clear(x509);
	return ret;
}
