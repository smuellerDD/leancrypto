// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Hash heap memory management
 *
 * Copyright (C) 2022, Stephan Mueller <smueller@chronox.de>
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "lc_hash.h"
#include "visibility.h"

DSO_PUBLIC
int lc_hash_alloc(const struct lc_hash *hash, struct lc_hash_ctx **hash_ctx)
{
	struct lc_hash_ctx *out_ctx;
	int ret = posix_memalign((void *)&out_ctx, sizeof(uint64_t),
				 LC_HASH_CTX_SIZE(hash));

	if (ret)
		return -ret;

	LC_HASH_SET_CTX(out_ctx, hash);

	*hash_ctx = out_ctx;

	return 0;
}

DSO_PUBLIC
void lc_hash_zero_free(struct lc_hash_ctx *hash_ctx)
{
	if (!hash_ctx)
		return;

	lc_hash_zero(hash_ctx);
	free(hash_ctx);
}
