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

#ifndef LC_X509_CSR_PARSER_H
#define LC_X509_CSR_PARSER_H

#include "ext_headers.h"
#include "lc_x509_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup X509
 * @brief Parse the certificate signing request (CSR)
 *
 * This function performs the following steps as mandated by RFC2986:
 *
 * 1. Parsing the certificate into the internal data structure of
 *    \p lc_x509_certificate.
 *
 * 2. Authenticating the requesting entity and verify the entity's signature.
 *
 * With the filled \p lc_x509_certificate the caller then is expected to
 * fullfill the remaining parts of RFC2986 by constructing an X.509 certificate:
 *
 * 1. Using the DN and the public key from the CSR to validate the origin
 *    and the appropriateness of the data (e.g. proper DN content, proper
 *    key type).
 *
 * 2. add the issuer by using \p lc_x509_cert_set_signer. Note, this call
 *    enables the CSR to be used as a certificate.
 *
 * 3. add the CA (issuer's) choice of serial number, validity period and
 *    signature algorithm by using \p lc_x509_cert_set_serial (optional
 *    as by default the SHA3-256 hash of the public key of the CSR is used
 *    as the serial), \p lc_x509_cert_set_valid_from and
 *    \p lc_x509_cert_set_valid_to. The signature algorithm is defined with
 *    \p lc_x509_cert_set_signer called in the previous step.
 *
 * 4. If the certification request contains any PKCS #9 attributes, the
 *    certification authority may also use the values in these attributes as
 *    well as other information known to the certification authority to
 *    construct X.509 certificate extensions. This can be done by using
 *    \p lc_x509_cert_set_eku or \p lc_x509_cert_set_keyusage.
 *
 * @param [in,out] x509 Certificate structure to be filled
 * @param [in] data Data blob with CSR data to be parsed
 * @param [in] datalen length of the CSR data blob
 *
 * @return 0 on success; < 0 on error
 */
int lc_x509_csr_decode(struct lc_x509_certificate *x509, const uint8_t *data,
		       size_t datalen);

#ifdef __cplusplus
}
#endif

#endif /* LC_X509_CSR_PARSER_H */
