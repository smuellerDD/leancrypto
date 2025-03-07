/*
 * Automatically generated by asn1_compiler.  Do not edit
 *
 * ASN.1 parser for x509_composite_mldsa_signature
 */
#pragma once
#include "asn1_encoder.h"
#include "asn1_decoder.h"

// clang-format off
extern const struct asn1_encoder x509_composite_mldsa_signature_encoder;
extern const struct asn1_decoder x509_composite_mldsa_signature_decoder;

extern int x509_ed25519_signature_enc(void *, uint8_t *, size_t *, uint8_t *);
extern int x509_ed25519_signature(void *, size_t, unsigned char, const uint8_t *, size_t);
extern int x509_mldsa_signature_enc(void *, uint8_t *, size_t *, uint8_t *);
extern int x509_mldsa_signature(void *, size_t, unsigned char, const uint8_t *, size_t);
// clang-format on
