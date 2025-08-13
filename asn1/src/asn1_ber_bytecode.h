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
/*
 * This code is derived in parts from the Linux kernel
 * License: SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#ifndef ASN1_BER_BYTECODE_H
#define ASN1_BER_BYTECODE_H

#include "asn1.h"
#include "ext_headers_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*asn1_action_t)(void *context,
			     size_t hdrlen, /* In case of ANY type */
			     unsigned char tag, /* In case of ANY type */
			     const uint8_t *value, size_t vlen);

typedef int (*asn1_action_enc_t)(void *context,
				 uint8_t *data, /* Data buffer to fill */
				 size_t *avail_datalen, /* Available data
							   length - upon
							   return, reduce by
							   generated data */
				 uint8_t *tag);

struct asn1_encoder {
	const unsigned char *machine;
	size_t machlen;
	const asn1_action_enc_t *actions;
};

struct asn1_decoder {
	const unsigned char *machine;
	size_t machlen;
	const asn1_action_t *actions;
};

enum asn1_opcode {
/*
	 * The tag-matching ops come first and the odd-numbered slots
	 * are for OR_SKIP ops.
	 */
#define ASN1_OP_MATCH__SKIP 0x01
#define ASN1_OP_MATCH__ACT 0x02
#define ASN1_OP_MATCH__JUMP 0x04
#define ASN1_OP_MATCH__ANY 0x08
#define ASN1_OP_MATCH__COND 0x10

	ASN1_OP_MATCH = 0x00,
	ASN1_OP_MATCH_OR_SKIP = 0x01,
	ASN1_OP_MATCH_ACT = 0x02,
	ASN1_OP_MATCH_ACT_OR_SKIP = 0x03,
	ASN1_OP_MATCH_JUMP = 0x04,
	ASN1_OP_MATCH_JUMP_OR_SKIP = 0x05,
	ASN1_OP_MATCH_ANY = 0x08,
	ASN1_OP_MATCH_ANY_OR_SKIP = 0x09,
	ASN1_OP_MATCH_ANY_ACT = 0x0a,
	ASN1_OP_MATCH_ANY_ACT_OR_SKIP = 0x0b,
	/* Everything before here matches unconditionally */

	ASN1_OP_COND_MATCH_OR_SKIP = 0x11,
	ASN1_OP_COND_MATCH_ACT_OR_SKIP = 0x13,
	ASN1_OP_COND_MATCH_JUMP_OR_SKIP = 0x15,
	ASN1_OP_COND_MATCH_ANY = 0x18,
	ASN1_OP_COND_MATCH_ANY_OR_SKIP = 0x19,
	ASN1_OP_COND_MATCH_ANY_ACT = 0x1a,
	ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP = 0x1b,

/* Everything before here will want a tag from the data */
#define ASN1_OP__MATCHES_TAG ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP

	/* These are here to help fill up space */
	ASN1_OP_COND_FAIL = 0x1c,
	ASN1_OP_COMPLETE = 0x1d,
	ASN1_OP_ACT = 0x1e,
	ASN1_OP_MAYBE_ACT = 0x1f,

	/* The following eight have bit 0 -> SET, 1 -> OF, 2 -> ACT */
	ASN1_OP_END_SEQ = 0x20,
	ASN1_OP_END_SET = 0x21,
	ASN1_OP_END_SEQ_OF = 0x22,
	ASN1_OP_END_SET_OF = 0x23,
	ASN1_OP_END_SEQ_ACT = 0x24,
	ASN1_OP_END_SET_ACT = 0x25,
	ASN1_OP_END_SEQ_OF_ACT = 0x26,
	ASN1_OP_END_SET_OF_ACT = 0x27,
#define ASN1_OP_END__SET 0x01
#define ASN1_OP_END__OF 0x02
#define ASN1_OP_END__ACT 0x04

	ASN1_OP_RETURN = 0x28,

	ASN1_OP__NR
};

#define _tag(CLASS, CP, TAG)                                                   \
	((ASN1_##CLASS << 6) | (ASN1_##CP << 5) | ASN1_##TAG)
#define _tagn(CLASS, CP, TAG) ((ASN1_##CLASS << 6) | (ASN1_##CP << 5) | TAG)
#define _jump_target(N) (N)
#define _action(N) (N)

extern const unsigned char asn1_op_lengths[ASN1_OP__NR];

#ifdef __cplusplus
}
#endif

#endif /* ASN1_BER_BYTECODE_H */
