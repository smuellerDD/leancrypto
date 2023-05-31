// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Hash heap memory management
 *
 * Copyright (C) 2022 - 2023, Stephan Mueller <smueller@chronox.de>
 */

#include "lc_hash.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(
int, lc_hash_alloc, const struct lc_hash *hash, struct lc_hash_ctx **hash_ctx)
{
	struct lc_hash_ctx *out_ctx = NULL;
	int ret;

	if (!hash_ctx)
		return -EINVAL;

	ret = lc_alloc_aligned((void **)&out_ctx, LC_MEM_COMMON_ALIGNMENT,
			       LC_HASH_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_HASH_SET_CTX(out_ctx, hash);

	*hash_ctx = out_ctx;

	return 0;
}

LC_INTERFACE_FUNCTION(
void, lc_hash_zero_free, struct lc_hash_ctx *hash_ctx)
{
	if (!hash_ctx)
		return;

	lc_hash_zero(hash_ctx);
	lc_free(hash_ctx);
}
