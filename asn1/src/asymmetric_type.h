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

#ifndef ASYMMETRIC_TYPE_H
#define ASYMMETRIC_TYPE_H

#include "ext_headers.h"
#include "lc_x509_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

extern struct key_type key_type_asymmetric;

/*
 * The key payload is four words.  The asymmetric-type key uses them as
 * follows:
 */
enum asymmetric_payload_bits {
	asym_crypto, /* The data representing the key */
	asym_subtype, /* Pointer to an asymmetric_key_subtype struct */
	asym_key_ids, /* Pointer to an asymmetric_key_ids struct */
	asym_auth /* The key's authorisation (signature, parent key ID) */
};

struct asymmetric_key_ids {
	void *id[3];
};

extern int asymmetric_key_id_same(const struct lc_asymmetric_key_id *kid1,
				  const struct lc_asymmetric_key_id *kid2);

extern int asymmetric_key_id_partial(const struct lc_asymmetric_key_id *kid1,
				     const struct lc_asymmetric_key_id *kid2);

extern int asymmetric_key_generate_id(struct lc_asymmetric_key_id *,
				      const uint8_t *val_1, size_t len_1,
				      const uint8_t *val_2, size_t len_2);
// static inline
// const struct asymmetric_key_ids *asymmetric_key_ids(const struct key *key)
// {
// 	return key->payload.data[asym_key_ids];
// }
//
// static inline
// const struct public_key *asymmetric_key_public_key(const struct key *key)
// {
// 	return key->payload.data[asym_crypto];
// }

extern struct key *find_asymmetric_key(struct key *keyring,
				       const struct lc_asymmetric_key_id *id_0,
				       const struct lc_asymmetric_key_id *id_1,
				       const struct lc_asymmetric_key_id *id_2,
				       unsigned int partial);

int x509_load_certificate_list(const uint8_t cert_list[],
			       const unsigned long list_size,
			       const struct key *keyring);

/*
 * The payload is at the discretion of the subtype.
 */

#ifdef __cplusplus
}
#endif

#endif /* ASYMMETRIC_TYPE_H */
