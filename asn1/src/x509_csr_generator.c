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

#include "lc_x509_generator.h"
#include "lc_x509_csr_generator.h"
#include "x509_csr_asn1.h"
#include "x509_cert_generator.h"
#include "x509_cert_parser.h"
#include "ret_checkers.h"
#include "small_stack_support.h"
#include "visibility.h"

int lc_x509_note_csr_info_enc(void *context, uint8_t *data,
				size_t *avail_datalen, uint8_t *tag)
{
	(void)context;
	(void)data;
	(void)avail_datalen;
	(void)tag;

	return 0;
}

int lc_x509_csr_version_enc(void *context, uint8_t *data, size_t *avail_datalen,
			    uint8_t *tag)
{
	/*
	 * Version  ::=  INTEGER  {  v1(0)  }
	 *
	 * We set the version hard-coded to version 1.
	 */
	static const uint8_t x509_csr_version = 0x00;
	int ret;

	(void)context;
	(void)tag;

	CKINT(lc_x509_sufficient_size(avail_datalen, sizeof(x509_csr_version)));
	data[0] = x509_csr_version;
	*avail_datalen -= sizeof(x509_csr_version);
	printf_debug("Set X.509 version to %u\n", x509_csr_version);

out:
	return ret;
}

/******************************************************************************
 * API functions
 ******************************************************************************/

LC_INTERFACE_FUNCTION(int, lc_x509_csr_encode,
		      const struct lc_x509_certificate *x509, uint8_t *data,
		      size_t *avail_datalen)
{
	struct workspace {
		struct x509_generate_context gctx;
		struct x509_parse_context pctx;
		struct lc_x509_certificate parsed_x509;
	};
	size_t datalen = *avail_datalen;
	uint8_t *sigdstptr;
	int ret = 0;
	LC_DECLARE_MEM(ws, struct workspace, sizeof(uint64_t));

	CKNULL(x509, -EINVAL);
	CKNULL(data, -EINVAL);

	ws->gctx.cert = x509;

	/* Issuer is irrelevant to be set, thus only process subject */
	ws->gctx.subject_attribute_processing = 1;
	ws->gctx.issuer_attribute_processing = 0;

	/*
	 * Attempt to encode the certificate
	 */
	CKINT(lc_asn1_ber_encoder(&lc_x509_csr_encoder, &ws->gctx, data,
				  avail_datalen));

	datalen -= *avail_datalen;

	/*
	 * Parse the encoded signature to detect the CertificationRequestInfo
	 */
	ws->pctx.cert = &ws->parsed_x509;
	ws->pctx.data = data;
	/* This certificate is to be handled as a CSR */
	ws->parsed_x509.is_csr = 1;
	CKINT(lc_asn1_ber_decoder(&lc_x509_csr_decoder, &ws->pctx, data,
				  datalen));

	/*
	 * Grab the signature bits
	 */
	CKINT(lc_x509_get_sig_params(&ws->parsed_x509));

	/*
	 * Copy the signature to its destination
	 * We can unconstify the raw_sig pointer here, because we know the
	 * data buffer is in the just parsed data.
	 */
	sigdstptr = (uint8_t *)ws->parsed_x509.raw_sig;

	/*
	 * Generate the signature over the TBSCertificate and place it
	 * into the signature location of the certificate.
	 */
	CKINT(lc_public_key_generate_signature(&x509->sig_gen_data,
					       &ws->parsed_x509.sig, sigdstptr,
					       &ws->parsed_x509.raw_sig_size));

out:
	LC_RELEASE_MEM(ws);
	return ret;
}
