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

#ifndef LC_X509_GENERATOR_HELPER_H
#define LC_X509_GENERATOR_HELPER_H

#include "lc_dilithium.h"
#include "lc_sphincs.h"
#include "lc_x509_common.h"

#ifdef __cplusplus
extern "C" {
#endif

struct lc_x509_key_input_data {
	struct lc_x509_key_input_data *next;
	enum lc_sig_types sig_type;
	union {
		struct lc_dilithium_pk dilithium_pk;
		struct lc_dilithium_ed25519_pk dilithium_ed25519_pk;
		struct lc_sphincs_pk sphincs_pk;
	} pk;
	union {
		struct lc_dilithium_sk dilithium_sk;
		struct lc_dilithium_ed25519_sk dilithium_ed25519_sk;
		struct lc_sphincs_sk sphincs_sk;
	} sk;
};

int lc_x509_cert_set_signer(struct lc_x509_certificate *signed_x509,
			    struct lc_x509_key_input_data *signer_key_input_data,
			    struct lc_x509_certificate *signer_x509,
			    const uint8_t *sk_data, size_t sk_data_len);

#ifdef __cplusplus
}
#endif

#endif /* LC_X509_GENERATOR_HELPER_H */
