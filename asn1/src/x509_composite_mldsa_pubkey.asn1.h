/*
 * Automatically generated by asn1_compiler.  Do not edit
 *
 * ASN.1 parser for x509_composite_mldsa_pubkey
 */
#pragma once
#include "asn1_encoder.h"
#include "asn1_decoder.h"

// clang-format off
extern const struct asn1_encoder x509_composite_mldsa_pubkey_encoder;
extern const struct asn1_decoder x509_composite_mldsa_pubkey_decoder;

extern int x509_ed25519_public_key_enc(void *, uint8_t *, size_t *, uint8_t *);
extern int x509_ed25519_public_key(void *, size_t, unsigned char, const uint8_t *, size_t);
extern int x509_mldsa_public_key_enc(void *, uint8_t *, size_t *, uint8_t *);
extern int x509_mldsa_public_key(void *, size_t, unsigned char, const uint8_t *, size_t);
// clang-format on
