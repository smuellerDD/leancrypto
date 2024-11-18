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

#ifndef LC_PKCS7_GENERATOR_H
#define LC_PKCS7_GENERATOR_H

#include "lc_pkcs7_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int lc_pkcs7_generate(const struct pkcs7_message *pkcs7, uint8_t *data,
		      size_t *avail_datalen);

/**
 * @brief Set an X.509 certificate to be added to a PKCS#7 message
 *
 * @param [out] pkcs7 PKCS#7 structure that shall receive the signer
 * @param [in] x509 X.509 certificate
 *
 * @return 0 on success, < 0 on error
 */
int lc_pkcs7_set_certificate(struct pkcs7_message *pkcs7,
			     struct lc_x509_certificate *x509);

/**
 * @brief Set an X.509 certificate as signer for a PKCS#7 message
 *
 * The certificate MUST have a public and secret key set to be added.
 *
 * @param [out] pkcs7 PKCS#7 structure that shall receive the signer
 * @param [in] x509_with_sk X.509 certificate with secret key to be used as
 *			    signer
 *
 * @return 0 on success, < 0 on error
 */
int lc_pkcs7_set_signer(struct pkcs7_message *pkcs7,
			struct lc_x509_certificate *x509_with_sk);

/**
 * @brief Set the data to be signed with PKCS#7
 *
 * @param [in] pkcs7 PKCS#7 data structure to be filled
 * @param [in] data Pointer to the data to be signed
 * @param [in] data_len Size of the data buffer
 *
 * @return 0 on success, < 0 on error
 */
int lc_pkcs7_set_data(struct pkcs7_message *pkcs7, const uint8_t *data,
		      size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* LC_PKCS7_GENERATOR_H */
