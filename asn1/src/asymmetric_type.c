/*
 * Copyright (C) 2024 - 2026, Stephan Mueller <smueller@chronox.de>
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
/*
 * Red Hat granted the following additional license to the leancrypto project:
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "asymmetric_type.h"
#include "build_bug_on.h"
#include "ext_headers_internal.h"
#include "lc_memcmp_secure.h"
#include "lc_memory_support.h"
#include "ret_checkers.h"

/**
 * asymmetric_key_generate_id: Construct an asymmetric key ID
 * @val_1: First binary blob
 * @len_1: Length of first binary blob
 *
 * Construct an asymmetric key ID from a pair of binary blobs.
 */
int lc_asymmetric_key_generate_id(struct lc_asymmetric_key_id *kid,
				  const uint8_t *val, size_t len)
{
	BUILD_BUG_ON(sizeof(kid->data) > (1 << (sizeof(kid->len) << 3)));

	if (!val || !len)
		return -EINVAL;

	if (len > sizeof(kid->data))
		return -EOVERFLOW;

	kid->len = (uint8_t)len;
	memcpy(kid->data, val, len);

	return 0;
}

/**
 * asymmetric_key_id_same - Return true if two asymmetric keys IDs are the same.
 * @kid1: The key ID to compare
 * @kid2: The key ID to compare
 */
int lc_asymmetric_key_id_same(const struct lc_asymmetric_key_id *kid1,
			      const struct lc_asymmetric_key_id *kid2)
{
	if (!kid1 || !kid2)
		return 0;
	return lc_memcmp_secure(kid1->data, kid1->len, kid2->data, kid2->len) ==
	       0;
}
