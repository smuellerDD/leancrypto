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
/*
 * This code is derived in parts from the Linux kernel
 * License: SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */
/*
 * Red Hat granted the following additional license to the leancrypto project:
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "asn1_ber_bytecode.h"

// clang-format off
const unsigned char asn1_op_lengths[ASN1_OP__NR] = {
	/*					OPC TAG JMP ACT */
	[ASN1_OP_MATCH]				= 1 + 1,
	[ASN1_OP_MATCH_OR_SKIP]			= 1 + 1,
	[ASN1_OP_MATCH_ACT]			= 1 + 1     + 1,
	[ASN1_OP_MATCH_ACT_OR_SKIP]		= 1 + 1     + 1,
	[ASN1_OP_MATCH_JUMP]			= 1 + 1 + 1,
	[ASN1_OP_MATCH_JUMP_OR_SKIP]		= 1 + 1 + 1,
	[ASN1_OP_MATCH_ANY]			= 1,
	[ASN1_OP_MATCH_ANY_OR_SKIP]		= 1,
	[ASN1_OP_MATCH_ANY_ACT]			= 1         + 1,
	[ASN1_OP_MATCH_ANY_ACT_OR_SKIP]		= 1         + 1,
	[ASN1_OP_COND_MATCH_OR_SKIP]		= 1 + 1,
	[ASN1_OP_COND_MATCH_ACT_OR_SKIP]	= 1 + 1     + 1,
	[ASN1_OP_COND_MATCH_JUMP_OR_SKIP]	= 1 + 1 + 1,
	[ASN1_OP_COND_MATCH_ANY]		= 1,
	[ASN1_OP_COND_MATCH_ANY_OR_SKIP]	= 1,
	[ASN1_OP_COND_MATCH_ANY_ACT]		= 1         + 1,
	[ASN1_OP_COND_MATCH_ANY_ACT_OR_SKIP]	= 1         + 1,
	[ASN1_OP_COND_FAIL]			= 1,
	[ASN1_OP_COMPLETE]			= 1,
	[ASN1_OP_ACT]				= 1         + 1,
	[ASN1_OP_MAYBE_ACT]			= 1         + 1,
	[ASN1_OP_RETURN]			= 1,
	[ASN1_OP_END_SEQ]			= 1,
	[ASN1_OP_END_SEQ_OF]			= 1     + 1,
	[ASN1_OP_END_SET]			= 1,
	[ASN1_OP_END_SET_OF]			= 1     + 1,
	[ASN1_OP_END_SEQ_ACT]			= 1         + 1,
	[ASN1_OP_END_SEQ_OF_ACT]		= 1     + 1 + 1,
	[ASN1_OP_END_SET_ACT]			= 1         + 1,
	[ASN1_OP_END_SET_OF_ACT]		= 1     + 1 + 1,
};
// clang-format on
