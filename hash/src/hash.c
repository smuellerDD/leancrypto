// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Hash heap memory management
 *
 * Copyright (C) 2022 - 2024, Stephan Mueller <smueller@chronox.de>
 */

#include "lc_hash.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_hash_alloc, const struct lc_hash *hash,
		      struct lc_hash_ctx **hash_ctx)
{
	struct lc_hash_ctx *out_ctx = NULL;
	int ret;

	if (!hash_ctx)
		return -EINVAL;

	ret = lc_alloc_aligned((void **)&out_ctx, LC_HASH_COMMON_ALIGNMENT,
			       LC_HASH_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_HASH_SET_CTX(out_ctx, hash);

	*hash_ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(void, lc_hash_zero_free, struct lc_hash_ctx *hash_ctx)
{
	if (!hash_ctx)
		return;

	lc_hash_zero(hash_ctx);
	lc_free(hash_ctx);
}

LC_INTERFACE_FUNCTION(void, lc_hash, const struct lc_hash *hash,
		      const uint8_t *in, size_t inlen, uint8_t *digest)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, hash);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, in, inlen);
	lc_hash_final(hash_ctx, digest);

	lc_hash_zero(hash_ctx);
}

LC_INTERFACE_FUNCTION(void, lc_xof, const struct lc_hash *xof,
		      const uint8_t *in, size_t inlen, uint8_t *digest,
		      size_t digestlen)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, xof);

	lc_hash_init(hash_ctx);
	lc_hash_update(hash_ctx, in, inlen);
	lc_hash_set_digestsize(hash_ctx, digestlen);
	lc_hash_final(hash_ctx, digest);

	lc_hash_zero(hash_ctx);
}
