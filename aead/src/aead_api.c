/*
 * Copyright (C) 2022 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "ext_headers_internal.h"
#include "lc_aead.h"
#include "lc_memory_support.h"
#include "status_algorithms.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(void, lc_aead_zero, struct lc_aead_ctx *ctx)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return;

	aead->zero(aead_state);
}

LC_INTERFACE_FUNCTION(void, lc_aead_zero_free, struct lc_aead_ctx *ctx)
{
	if (!ctx)
		return;

	lc_aead_zero(ctx);
	lc_free(ctx);
}

LC_INTERFACE_FUNCTION(int, lc_aead_setkey, struct lc_aead_ctx *ctx,
		      const uint8_t *key, const size_t keylen,
		      const uint8_t *iv, size_t ivlen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return -EINVAL;

	return aead->setkey(aead_state, key, keylen, iv, ivlen);
}

LC_INTERFACE_FUNCTION(int, lc_aead_encrypt, struct lc_aead_ctx *ctx,
		      const uint8_t *plaintext, uint8_t *ciphertext,
		      size_t datalen, const uint8_t *aad, size_t aadlen,
		      uint8_t *tag, size_t taglen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state || !aead->encrypt)
		return -EOPNOTSUPP;

	aead->encrypt(aead_state, plaintext, ciphertext, datalen, aad, aadlen,
		      tag, taglen);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_aead_enc_init, struct lc_aead_ctx *ctx,
		      const uint8_t *aad, size_t aadlen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state || !aead->enc_init)
		return -EOPNOTSUPP;

	aead->enc_init(aead_state, aad, aadlen);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_aead_enc_update, struct lc_aead_ctx *ctx,
		      const uint8_t *plaintext, uint8_t *ciphertext,
		      size_t datalen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state || !aead->enc_update)
		return -EOPNOTSUPP;

	aead->enc_update(aead_state, plaintext, ciphertext, datalen);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_aead_enc_final, struct lc_aead_ctx *ctx,
		      uint8_t *tag, size_t taglen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state || !aead->enc_final)
		return -EOPNOTSUPP;

	aead->enc_final(aead_state, tag, taglen);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_aead_decrypt, struct lc_aead_ctx *ctx,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen, const uint8_t *aad, size_t aadlen,
		      const uint8_t *tag, size_t taglen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state || !aead->decrypt)
		return -EOPNOTSUPP;

	return aead->decrypt(aead_state, ciphertext, plaintext, datalen, aad,
			     aadlen, tag, taglen);
}

LC_INTERFACE_FUNCTION(int, lc_aead_dec_init, struct lc_aead_ctx *ctx,
		      const uint8_t *aad, size_t aadlen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state || !aead->dec_init)
		return -EOPNOTSUPP;

	aead->dec_init(aead_state, aad, aadlen);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_aead_dec_update, struct lc_aead_ctx *ctx,
		      const uint8_t *ciphertext, uint8_t *plaintext,
		      size_t datalen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state || !aead->dec_update)
		return -EOPNOTSUPP;

	aead->dec_update(aead_state, ciphertext, plaintext, datalen);

	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_aead_dec_final, struct lc_aead_ctx *ctx,
		      const uint8_t *tag, size_t taglen)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return -EINVAL;

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state || !aead->dec_final)
		return -EOPNOTSUPP;

	return aead->dec_final(aead_state, tag, taglen);
}

LC_INTERFACE_FUNCTION(enum lc_alg_status_val, lc_aead_alg_status,
		      const struct lc_aead *aead)
{
	if (!aead)
		return lc_alg_status_unknown;

	/* No algorithm is ruled out a-priori for FIPS compliance */
	return lc_alg_status(aead->algorithm_type | LC_ALG_STATUS_FIPS);
}

LC_INTERFACE_FUNCTION(enum lc_alg_status_val, lc_aead_ctx_alg_status,
		      const struct lc_aead_ctx *ctx)
{
	if (!ctx)
		return lc_alg_status_unknown;

	return lc_aead_alg_status(ctx->aead);
}
