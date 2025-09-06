// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Hash heap memory management
 *
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
 */

#include "ext_headers_internal.h"
#include "hash_common.h"
#include "lc_hash.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(int, lc_hash_init, struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return -EINVAL;

	hash = hash_ctx->hash;
	return hash->init(hash_ctx->hash_state);
}

LC_INTERFACE_FUNCTION(void, lc_hash_update, struct lc_hash_ctx *hash_ctx,
		      const uint8_t *in, size_t inlen)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return;

	hash = hash_ctx->hash;
	hash->update(hash_ctx->hash_state, in, inlen);
}

LC_INTERFACE_FUNCTION(void, lc_hash_final, struct lc_hash_ctx *hash_ctx,
		      uint8_t *digest)
{
	const struct lc_hash *hash;

	if (!hash_ctx || !digest)
		return;

	hash = hash_ctx->hash;
	hash->final(hash_ctx->hash_state, digest);
}

LC_INTERFACE_FUNCTION(void, lc_hash_set_digestsize,
		      struct lc_hash_ctx *hash_ctx, size_t digestsize)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return;

	hash = hash_ctx->hash;
	if (hash->set_digestsize)
		hash->set_digestsize(hash_ctx->hash_state, digestsize);
}

LC_INTERFACE_FUNCTION(size_t, lc_hash_digestsize, struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return 0;

	hash = hash_ctx->hash;
	return hash->get_digestsize(hash_ctx->hash_state);
}

LC_INTERFACE_FUNCTION(unsigned int, lc_hash_blocksize,
		      struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return 0;

	hash = hash_ctx->hash;
	return hash->sponge_rate;
}

LC_INTERFACE_FUNCTION(unsigned int, lc_hash_ctxsize,
		      struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return 0;

	hash = hash_ctx->hash;
	return hash->statesize;
}

LC_INTERFACE_FUNCTION(void, lc_hash_zero, struct lc_hash_ctx *hash_ctx)
{
	const struct lc_hash *hash;

	if (!hash_ctx)
		return;

	hash = hash_ctx->hash;
	lc_memset_secure(hash_ctx->hash_state, 0, hash->statesize);
}

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

LC_INTERFACE_FUNCTION(int, lc_hash, const struct lc_hash *hash,
		      const uint8_t *in, size_t inlen, uint8_t *digest)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, hash);
	int ret = lc_hash_init(hash_ctx);

	if (ret)
		return ret;
	lc_hash_update(hash_ctx, in, inlen);
	lc_hash_final(hash_ctx, digest);

	lc_hash_zero(hash_ctx);

	return 0;
}

void lc_hash_nocheck(const struct lc_hash *hash, const uint8_t *in,
		     size_t inlen, uint8_t *digest)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, hash);

	hash->init_nocheck(hash_ctx->hash_state);
	lc_hash_update(hash_ctx, in, inlen);
	lc_hash_final(hash_ctx, digest);

	lc_hash_zero(hash_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_xof, const struct lc_hash *xof,
		      const uint8_t *in, size_t inlen, uint8_t *digest,
		      size_t digestlen)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, xof);
	int ret = lc_hash_init(hash_ctx);

	if (ret)
		return ret;

	lc_hash_update(hash_ctx, in, inlen);
	lc_hash_set_digestsize(hash_ctx, digestlen);
	if (lc_hash_digestsize(hash_ctx) != digestlen) {
		memset(digest, 0, digestlen);
		return 0;
	}
	lc_hash_final(hash_ctx, digest);

	lc_hash_zero(hash_ctx);

	return 0;
}

void lc_xof_nocheck(const struct lc_hash *xof, const uint8_t *in, size_t inlen,
		    uint8_t *digest, size_t digestlen)
{
	LC_HASH_CTX_ON_STACK(hash_ctx, xof);

	xof->init_nocheck(hash_ctx->hash_state);
	lc_hash_update(hash_ctx, in, inlen);
	lc_hash_set_digestsize(hash_ctx, digestlen);
	if (lc_hash_digestsize(hash_ctx) != digestlen) {
		memset(digest, 0, digestlen);
		return;
	}
	lc_hash_final(hash_ctx, digest);

	lc_hash_zero(hash_ctx);
}

LC_INTERFACE_FUNCTION(int, lc_sponge, const struct lc_hash *hash, void *state,
		      unsigned int rounds)
{
	if (!state || !hash || !hash->sponge_permutation)
		return -EOPNOTSUPP;

	hash->sponge_permutation(state, rounds);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_sponge_add_bytes, const struct lc_hash *hash,
		      void *state, const uint8_t *data, size_t offset,
		      size_t length)
{
	if (!state || !hash || !hash->sponge_add_bytes)
		return -EOPNOTSUPP;

	hash->sponge_add_bytes(state, data, offset, length);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_sponge_extract_bytes, const struct lc_hash *hash,
		      const void *state, uint8_t *data, size_t offset,
		      size_t length)
{
	if (!state || !hash || !hash->sponge_extract_bytes)
		return -EOPNOTSUPP;

	hash->sponge_extract_bytes(state, data, offset, length);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_sponge_newstate, const struct lc_hash *hash,
		      void *state, const uint8_t *data, size_t offset,
		      size_t length)
{
	if (!state || !hash || !hash->sponge_newstate)
		return -EOPNOTSUPP;

	hash->sponge_newstate(state, data, offset, length);

	return 0;
}
