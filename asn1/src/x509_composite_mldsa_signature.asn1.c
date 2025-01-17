
/*
 * Automatically generated by asn1_compiler.  Do not edit
 *
 * ASN.1 parser for x509_composite_mldsa_signature
 */
#include "asn1_ber_bytecode.h"
#include "x509_composite_mldsa_signature.asn1.h"

// clang-format off

enum x509_composite_mldsa_signature_actions {
	ACT_x509_ed25519_signature = 0,
	ACT_x509_mldsa_signature = 1,
	NR__x509_composite_mldsa_signature_actions = 2
};

static const asn1_action_t x509_composite_mldsa_signature_action_table[NR__x509_composite_mldsa_signature_actions] = {
	[   0] = x509_ed25519_signature,
	[   1] = x509_mldsa_signature,
};

static const asn1_action_enc_t x509_composite_mldsa_signature_action_table_enc[NR__x509_composite_mldsa_signature_actions] = {
	[   0] = x509_ed25519_signature_enc,
	[   1] = x509_mldsa_signature_enc,
};

static const unsigned char x509_composite_mldsa_signature_machine[] = {
	// CompositeSignatureValue
	[   0] = ASN1_OP_MATCH,
	[   1] = _tag(UNIV, CONS, SEQ),
	[   2] =  ASN1_OP_MATCH_ACT,		// firstSignature
	[   3] =  _tag(UNIV, PRIM, BTS),
	[   4] =  _action(ACT_x509_mldsa_signature),
	[   5] =  ASN1_OP_MATCH_ACT,		// secondSignature
	[   6] =  _tag(UNIV, PRIM, BTS),
	[   7] =  _action(ACT_x509_ed25519_signature),
	[   8] = ASN1_OP_END_SEQ,
	[   9] = ASN1_OP_COMPLETE,
};

const struct asn1_decoder x509_composite_mldsa_signature_decoder = {
	.machine = x509_composite_mldsa_signature_machine,
	.machlen = sizeof(x509_composite_mldsa_signature_machine),
	.actions = x509_composite_mldsa_signature_action_table,
};

const struct asn1_encoder x509_composite_mldsa_signature_encoder = {
	.machine = x509_composite_mldsa_signature_machine,
	.machlen = sizeof(x509_composite_mldsa_signature_machine),
	.actions = x509_composite_mldsa_signature_action_table_enc,
};

// clang-format on
