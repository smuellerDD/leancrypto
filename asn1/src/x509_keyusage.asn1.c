/*
 * Automatically generated by asn1_compiler.  Do not edit
 *
 * ASN.1 parser for x509_keyusage
 */
#include "asn1_ber_bytecode.h"
#include "x509_keyusage.asn1.h"

enum x509_keyusage_actions {
	ACT_x509_key_usage = 0,
	NR__x509_keyusage_actions = 1
};

static const asn1_action_t
	x509_keyusage_action_table[NR__x509_keyusage_actions] = {
		[0] = x509_key_usage,
	};

static const unsigned char x509_keyusage_machine[] = {
	// KeyUsage
	[0] = ASN1_OP_MATCH_ACT,
	[1] = _tag(UNIV, PRIM, BTS),
	[2] = _action(ACT_x509_key_usage),
	[3] = ASN1_OP_COMPLETE,
};

const struct asn1_decoder x509_keyusage_decoder = {
	.machine = x509_keyusage_machine,
	.machlen = sizeof(x509_keyusage_machine),
	.actions = x509_keyusage_action_table,
};