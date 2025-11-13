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

#ifndef ASYM_KEY_DILITHIUM_ED448_H
#define ASYM_KEY_DILITHIUM_ED448_H

#include "asym_key.h"
#include "x509_cert_generator.h"
#include "x509_cert_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

int public_key_encode_dilithium_ed448(uint8_t *data, size_t *avail_datalen,
				      struct x509_generate_context *ctx);
int private_key_encode_dilithium_ed448(
	uint8_t *data, size_t *avail_datalen,
	struct x509_generate_privkey_context *ctx);
int private_key_decode_dilithium_ed448(struct lc_x509_key_data *keys,
				       const uint8_t *data, size_t datalen);

int public_key_verify_signature_dilithium_ed448(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig);

int public_key_generate_signature_dilithium_ed448(
	const struct lc_x509_key_data *gen_data,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len);

int asym_set_dilithium_ed448_keypair(struct lc_x509_key_data *gen_data,
				     struct lc_dilithium_ed448_pk *pk,
				     struct lc_dilithium_ed448_sk *sk);
int asym_keypair_gen_dilithium_ed448(struct lc_x509_certificate *cert,
				     struct lc_x509_key_data *keys,
				     enum lc_dilithium_type dilithium_key_type);

#ifdef LC_DILITHIUM_ED448
int public_key_signature_size_dilithium_ed448(
	enum lc_dilithium_type dilithium_type, size_t *size);
int public_key_decode_dilithium_ed448(
	struct lc_dilithium_ed448_pk *dilithium_ed448_pk, const uint8_t *data,
	size_t datalen);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ASYM_KEY_DILITHIUM_ED448_H */
