/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#ifndef ASYM_KEY_H
#define ASYM_KEY_H

#include "asymmetric_type.h"
#include "lc_x509_parser.h"
#include "lc_sha256.h"
#include "lc_sha512.h"
#include "lc_sha3.h"
#include "oid_registry.h"
#include "x509_cert_generator.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LC_PKCS7_DEBUG
#warning                                                                       \
	"LC_PKCS7_DEBUG enabled - code MUST ONLY BE USED FOR TESTING - NEVER IN PRODUCTION!"
#define CKINT_SIGCHECK(x)                                                      \
	{                                                                      \
		ret = x;                                                       \
		if (ret == -ENOPKG) {                                          \
			printf("WARNING: NO SIGNATURE CHECK\n");               \
			ret = 0;                                               \
		}                                                              \
		if (ret < 0)                                                   \
			goto out;                                              \
	}
#else
#define CKINT_SIGCHECK CKINT
#endif

void lc_public_key_clear(struct lc_public_key *key);

void lc_public_key_signature_clear(struct lc_public_key_signature *sig);

int lc_public_key_verify_signature(const struct lc_public_key *pkey,
				   const struct lc_public_key_signature *sig);

int lc_public_key_generate_signature(const struct lc_x509_key_data *gen_data,
				     const struct lc_public_key_signature *sig,
				     uint8_t *sig_data, size_t *available_len);
int lc_public_key_extract(struct x509_generate_context *ctx, uint8_t *dst_data,
			  size_t *available_len);
int lc_public_key_signature_size(size_t *siglen, enum lc_sig_types sig_type);
int lc_privkey_key_encode(struct x509_generate_privkey_context *ctx,
			  uint8_t *dst_data, size_t *available_len);
int lc_privkey_key_decode(struct lc_x509_key_data *keys, const uint8_t *data,
			  size_t datalen);
int lc_pubkey_key_decode(struct lc_x509_key_data *keys, const uint8_t *data,
			 size_t datalen);
int lc_asym_set_signer(struct lc_x509_certificate *signed_x509,
		       const struct lc_x509_key_data *signer_key_data,
		       const struct lc_x509_certificate *signer_x509);
int lc_asym_keypair_gen(struct lc_x509_certificate *cert,
			struct lc_x509_key_data *keys,
			enum lc_sig_types create_keypair_algo);
int lc_asym_keypair_load(struct lc_x509_certificate *cert,
			 const struct lc_x509_key_data *keys);
int lc_asym_keypair_gen_seed(struct lc_x509_key_data *keys,
			     const char *addtl_input, size_t addtl_input_len);

#ifdef __cplusplus
}
#endif

#endif /* ASYM_KEY_H */
