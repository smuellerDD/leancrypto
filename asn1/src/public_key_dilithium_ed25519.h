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

#ifndef PUBLIC_KEY_DILITHIUM_ED25519_H
#define PUBLIC_KEY_DILITHIUM_ED25519_H

#include "public_key.h"
#include "x509_cert_generator.h"
#include "x509_cert_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

int public_key_encode_dilithium_ed25519(uint8_t *data, size_t *avail_datalen,
					struct x509_generate_context *ctx);
int private_key_encode_dilithium_ed25519(
	uint8_t *data, size_t *avail_datalen,
	struct x509_generate_privkey_context *ctx);
int private_key_decode_dilithium_ed25519(
	struct lc_x509_key_input_data *key_input_data, const uint8_t *data,
	size_t datalen);

int public_key_verify_signature_dilithium_ed25519(
	const struct lc_public_key *pkey,
	const struct lc_public_key_signature *sig);

int public_key_generate_signature_dilithium_ed25519(
	const struct lc_x509_generate_data *gen_data,
	const struct lc_public_key_signature *sig, uint8_t *sig_data,
	size_t *available_len);

int public_key_signature_size_dilithium_ed25519(
	enum lc_dilithium_type dilithium_type, size_t *size);

#ifdef __cplusplus
}
#endif

#endif /* PUBLIC_KEY_DILITHIUM_ED25519_H */
