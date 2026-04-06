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

#ifndef LC_X509_CSR_GENERATOR_H
#define LC_X509_CSR_GENERATOR_H

#include "lc_x509_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup X509Gen
 * @brief Encode an X.509 CSR
 *
 * The function generates an X.509 CSR data blob from the filled X.509 data
 * structure.
 *
 * This function also performs the signature generation to sign the X.509
 * CSR data with the provided signer which ought to be its own private key.
 *
 * To generate a CSR, have the following information set:
 *
 * 1. Proper subject with the different APIs of `lc_x509_cert_set_subject_*`
 *
 * 2. Public/private key where the keys are set with `lc_x509_keypair_load`.
 *    Note, both the public and private key are used where the public key is
 *    encapsulated into the CSR and the private key is used to sign the CSR.
 *
 * @param [in] x509 The data structure that is filled by the caller before this
 *		    invocation using the various setter functions.
 * @param [in,out] data Raw X.509 data blob in DER / BER format - the caller
 *			must provide the memory
 * @param [in,out] avail_datalen Length of the raw X.509 certificate buffer that
 *				 is free (the input value must be equal to the
 * 				 \p data buffer size, the output refers to how
 *				 many bytes are unused)
 *
 * @return 0 on success or < 0 on error
 */
int lc_x509_csr_encode(const struct lc_x509_certificate *x509, uint8_t *data,
		       size_t *avail_datalen);

#ifdef __cplusplus
}
#endif

#endif /* LC_X509_CSR_GENERATOR_H */
