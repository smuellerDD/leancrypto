/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "asymmetric_type.h"
#include "build_bug_on.h"
#include "ext_headers.h"
#include "lc_memcmp_secure.h"
#include "lc_memory_support.h"
#include "ret_checkers.h"

/**
 * asymmetric_key_generate_id: Construct an asymmetric key ID
 * @val_1: First binary blob
 * @len_1: Length of first binary blob
 * @val_2: Second binary blob
 * @len_2: Length of second binary blob
 *
 * Construct an asymmetric key ID from a pair of binary blobs.
 */
int asymmetric_key_generate_id(struct lc_asymmetric_key_id *kid,
			       const uint8_t *val_1, size_t len_1,
			       const uint8_t *val_2, size_t len_2)
{
	size_t len = len_1 + len_2;

	BUILD_BUG_ON(sizeof(kid->data) > (1 << (sizeof(kid->len) << 3)));

	if (len > sizeof(kid->data))
		return -EOVERFLOW;

	kid->len = (uint8_t)len;

	if (val_1)
		memcpy(kid->data, val_1, len_1);
	if (val_2)
		memcpy(kid->data + len_1, val_2, len_2);

	return 0;
}

/**
 * asymmetric_key_id_same - Return true if two asymmetric keys IDs are the same.
 * @kid1: The key ID to compare
 * @kid2: The key ID to compare
 */
int asymmetric_key_id_same(const struct lc_asymmetric_key_id *kid1,
			   const struct lc_asymmetric_key_id *kid2)
{
	if (!kid1 || !kid2)
		return 0;
	return lc_memcmp_secure(kid1->data, kid2->len, kid2->data,
				kid2->len) == 0;
}

/**
 * asymmetric_key_id_partial - Return true if two asymmetric keys IDs
 * partially match
 * @kid1: The key ID to compare
 * @kid2: The key ID to compare
 */
int asymmetric_key_id_partial(const struct lc_asymmetric_key_id *kid1,
			      const struct lc_asymmetric_key_id *kid2)
{
	if (!kid1 || !kid2)
		return 0;
	if (kid1->len < kid2->len)
		return 0;
	return lc_memcmp_secure(kid1->data + (kid1->len - kid2->len), kid2->len,
				kid2->data, kid2->len) == 0;
}
