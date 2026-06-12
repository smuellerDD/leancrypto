/*
 * Copyright (C) 2022 - 2026, Stephan Mueller <smueller@chronox.de>
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

#include "build_bug_on.h"
#include "ext_headers_internal.h"
#include "lc_aead.h"
#include "lc_memory_support.h"
#include "ret_checkers.h"
#include "status_algorithms.h"
#include "visibility.h"

LC_INTERFACE_FUNCTION(void, lc_aead_zero, struct lc_aead_ctx *ctx)
{
	const struct lc_aead *aead;
	void *aead_state;

	if (!ctx)
		return;

	lc_memset_secure(ctx->key, 0, ctx->keylen);
	ctx->keylen = 0;
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

static inline int lc_aead_load_key(struct lc_aead_ctx *ctx,
				   const uint8_t *key, size_t keylen)
{
	if (!ctx)
		return -EINVAL;
	if (keylen > LC_AEAD_MAX_KEYSIZE)
		return -EOVERFLOW;

	memcpy(ctx->key, key, keylen);

	BUILD_BUG_ON(LC_AEAD_MAX_KEYSIZE > (1 << (sizeof(uint8_t) << 3)));
	ctx->keylen = (uint8_t)keylen;
	return 0;
}

LC_INTERFACE_FUNCTION(int, lc_aead_setkey, struct lc_aead_ctx *ctx,
		      const uint8_t *key, const size_t keylen,
		      const uint8_t *iv, size_t ivlen)
{
	const struct lc_aead *aead;
	const uint8_t *act_key = NULL;
	size_t act_keylen = 0;
	void *aead_state;
	int ret = 0;

	CKNULL(ctx, -EINVAL);

	if (keylen) {
		if (ivlen) {
			/* Key and IV: use them */
			act_key = key;
			act_keylen = keylen;
		} else {
			/* Key, but no IV: store key for later use */
			CKINT(lc_aead_load_key(ctx, key, keylen));

			/*
			 * If there is no state of the actual algorithm (e.g.
			 * LC_AEAD_CTX_NO_STATE is used to initialize the
			 * struct lc_aead_ctx), then we are done.
			 */
			if (!ctx->aead_state)
				return 0;

			/*
			 * A cipher algorithm state is present, initialize the
			 * current context and its state.
			 */
			act_key = key;
			act_keylen = keylen;
		}
	} else {
		if (ivlen) {
			/* No key, but IV: use stored key and provided IV */
			CKRET(!ctx->keylen, -ENOKEY);
			act_key = ctx->key;
			act_keylen = ctx->keylen;
		} else {
			/* No key and no IV: invalid */
			return -EINVAL;
		}
	}
	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return -EINVAL;

	CKINT(aead->setkey(aead_state, act_key, act_keylen, iv, ivlen));

out:
	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_aead_setkey_from_ctx, struct lc_aead_ctx *ctx,
		      const struct lc_aead_ctx *key_ctx,
		      const uint8_t *iv, size_t ivlen)
{
	const struct lc_aead *aead;
	void *aead_state;
	int ret = 0;

	CKNULL(ctx, -EINVAL);
	CKNULL(key_ctx, -EINVAL);
	CKRET(!key_ctx->keylen, -ENOKEY);
	/* It is only permissible to use the key with the same algorithm */
	CKRET(ctx->aead != key_ctx->aead, -ENOPKG);

	aead = ctx->aead;
	aead_state = ctx->aead_state;

	if (!aead || !aead_state)
		return -EINVAL;

	CKINT(aead->setkey(aead_state, key_ctx->key, key_ctx->keylen, iv,
			   ivlen));

out:
	return ret;
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

	/*
	 * In case of an in-place operation, allow the caller to provide a
	 * NULL plaintext buffer.
	 */
	if (!plaintext)
		plaintext = ciphertext;

	return aead->encrypt(aead_state, plaintext, ciphertext, datalen, aad,
			     aadlen, tag, taglen);
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

	return aead->enc_init(aead_state, aad, aadlen);
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

	/*
	 * In case of an in-place operation, allow the caller to provide a
	 * NULL plaintext buffer.
	 */
	if (!plaintext)
		plaintext = ciphertext;

	return aead->enc_update(aead_state, plaintext, ciphertext, datalen);
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

	return aead->enc_final(aead_state, tag, taglen);
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

	/*
	 * In case of an in-place operation, allow the caller to provide a
	 * NULL ciphertext buffer.
	 */
	if (!ciphertext)
		ciphertext = plaintext;

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

	return aead->dec_init(aead_state, aad, aadlen);
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

	/*
	 * In case of an in-place operation, allow the caller to provide a
	 * NULL ciphertext buffer.
	 */
	if (!ciphertext)
		ciphertext = plaintext;

	return aead->dec_update(aead_state, ciphertext, plaintext, datalen);
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
