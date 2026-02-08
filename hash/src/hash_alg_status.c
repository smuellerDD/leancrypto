// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Hash heap memory management
 *
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
 */

#include "hash_common.h"
#include "lc_ascon_hash.h"
#include "lc_hash.h"
#include "lc_sha256.h"
#include "lc_sha3.h"
#include "lc_sha512.h"
#include "status_algorithms.h"
#include "visibility.h"

uint64_t lc_hash_is_fips_eligible(const struct lc_hash *hash)
{
	/*
	 * Only the regular interfaces are considered to have a type to be
	 * resolvable as FIPS algorithm.
	 */
	if (hash == lc_sha3_224 || hash == lc_sha3_256 || hash == lc_sha3_384 ||
	    hash == lc_sha3_512 || hash == lc_shake128 || hash == lc_shake256 ||
	    hash == lc_cshake128 || hash == lc_cshake256 ||
	    hash == lc_shake128 || hash == lc_sha256 || hash == lc_sha384 ||
	    hash == lc_sha512 || hash == lc_ascon_256 || hash == lc_ascon_xof)
		return LC_ALG_STATUS_FIPS;
	return 0;
}

LC_INTERFACE_FUNCTION(enum lc_alg_status_val, lc_hash_alg_status,
		      const struct lc_hash *hash)
{
	if (!hash)
		return lc_alg_status_unknown;

	return lc_alg_status(hash->algorithm_type |
			     lc_hash_is_fips_eligible(hash));
}

LC_INTERFACE_FUNCTION(enum lc_alg_status_val, lc_hash_ctx_alg_status,
		      const struct lc_hash_ctx *ctx)
{
	if (!ctx)
		return lc_alg_status_unknown;

	return lc_hash_alg_status(ctx->hash);
}
