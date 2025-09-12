/*
 * Copyright (C) 2024 - 2025, Stephan Mueller <smueller@chronox.de>
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

#include "alignment.h"
#include "ascon_internal.h"
#include "bitshift.h"
#include "build_bug_on.h"
#include "lc_ascon_aead.h"
#include "lc_memcmp_secure.h"
#include "math_helper.h"
#include "ret_checkers.h"
#include "timecop.h"
#include "visibility.h"
#include "xor.h"

static void lc_ascon_zero_ex_key(struct lc_ascon_cryptor *ascon)
{
	uint64_t *state_mem = ascon->state;

	lc_memset_secure((uint8_t *)state_mem, 0, ascon->statesize);
	ascon->rate_offset = 0;
	ascon->roundb = 0;

	/* Do not touch ascon->statesize! */
	/* Do not touch ascon->taglen! */
}

static void lc_ascon_zero(struct lc_ascon_cryptor *ascon)
{
	lc_memset_secure((uint8_t *)ascon->key, 0, sizeof(ascon->key));
	ascon->keylen = 0;

	lc_ascon_zero_ex_key(ascon);
}

/**
 * @brief Set the key for the encryption or decryption operation
 *
 * @param [in] state Ascon crypt cipher handle
 * @param [in] key Buffer with key
 * @param [in] keylen Length of key buffer
 * @param [in] nonce Nonce vector to be used
 * @param [in] noncelen Length of nonce vector
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption. Yet, checks specific
 * to the used sponge limit the key size.
 */
int lc_ascon_setkey_int(void *state, const uint8_t *key, size_t keylen,
			const uint8_t *nonce, size_t noncelen, int nocheck)
{
	struct lc_ascon_cryptor *ascon = state;
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
	int ret;

	poison(key, keylen);

	/*
	 * The different lc_sponge* APIs return error indicators which are
	 * important to observe, because those APIs refuse to operate when
	 * there is no Sponge implementation provided by the selected hash
	 * instance. As the entire AEAD code does not check for these errors,
	 * it could lead to the case that plaintext is leaked if (a) an
	 * encryption in place is performed, and (b) the used hash
	 * implementation does not have a Sponge implementation. This issue is
	 * alleviated by this check.
	 */
	if (!hash->sponge_add_bytes || !hash->sponge_extract_bytes ||
	    !hash->sponge_newstate || !hash->sponge_permutation ||
	    !hash->sponge_rate)
		return -EOPNOTSUPP;

	/*
	 * If we receive a NULL key, assume it was loaded before with
	 * lc_ascon_load_key.
	 */
	if (!key) {
		lc_ascon_zero_ex_key(ascon);
		key = ascon->key;
		keylen = ascon->keylen;
	} else {
		lc_ascon_zero(ascon);
	}

	if (noncelen < 16 || noncelen > keylen)
		return -EINVAL;

	/*
	 * Add (IV || key || Nonce) to rate section and first part of capacity
	 * section of state.
	 */

	/* Insert the IV into the first 64-bit word */
	ret = lc_ak_setiv(ascon, keylen, nocheck);
	if (ret < 0)
		return ret;

	/* lc_ak_setiv did not identify the key */
	if (!ret) {
		ret = lc_ascon_setiv(ascon, keylen, nocheck);
		if (ret < 0)
			return ret;
	}

	/* lc_ascon_ascon_setiv also did not take the data */
	if (!ret)
		return -EINVAL;

	/* Allow this function being called with the ascon->key */
	if (key != ascon->key)
		memcpy(ascon->key, key, keylen);

	/* Insert key past the IV. */
	lc_sponge_add_bytes(hash, state_mem, key, sizeof(uint64_t), keylen);

	/* Insert nonce past the key. */
	lc_sponge_add_bytes(hash, state_mem, nonce, sizeof(uint64_t) + keylen,
			    noncelen);

	/* Sponge permutation */
	lc_sponge(hash, state_mem, 12);

	/* XOR key to last part of capacity */
	lc_sponge_add_bytes(hash, state_mem, key, ascon->statesize - keylen,
			    keylen);

	return 0;
}

static int lc_ascon_setkey(void *state, const uint8_t *key, size_t keylen,
			   const uint8_t *nonce, size_t noncelen)
{
	return lc_ascon_setkey_int(state, key, keylen, nonce, noncelen, 0);
}

/* Insert the AAD into the sponge state. */
static void lc_ascon_aad(struct lc_ascon_cryptor *ascon, const uint8_t *aad,
			 size_t aadlen)
{
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
	/* Rationale for pad byte: see ascon_squeeze_common */
	static const uint8_t pad_trail = 0x80;

	if (!aadlen)
		return;

	/* Authenticated Data - Insert into rate section of the state */
	while (aadlen >= hash->sponge_rate) {
		lc_sponge_add_bytes(hash, state_mem, aad, 0, hash->sponge_rate);

		aadlen -= hash->sponge_rate;
		aad += hash->sponge_rate;

		lc_sponge(hash, state_mem, ascon->roundb);
	}

	lc_sponge_add_bytes(hash, state_mem, aad, 0, aadlen);
	lc_ascon_add_padbyte(ascon, aadlen);

	lc_sponge(hash, state_mem, ascon->roundb);

	/* Add pad_trail bit */
	lc_sponge_add_bytes(hash, state_mem, &pad_trail, ascon->statesize - 1,
			    sizeof(pad_trail));
}

/* Handle the finalization phase of the Ascon algorithm. */
static void lc_ascon_finalization(struct lc_ascon_cryptor *ascon, uint8_t *tag,
				  size_t taglen)
{
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
	uint8_t tag_offset = ascon->statesize - (uint8_t)taglen;

	/* Finalization - Insert key into capacity */
	lc_sponge_add_bytes(hash, state_mem, ascon->key, hash->sponge_rate,
			    ascon->keylen);

	/* Sponge permutation */
	lc_sponge(hash, state_mem, 12);

	/* Finalization - Insert key into capacity */
	lc_sponge_add_bytes(hash, state_mem, ascon->key, tag_offset, taglen);

	/* Finalization - Extract tag from capacity */
	lc_sponge_extract_bytes(hash, state_mem, tag, tag_offset, taglen);

	/* Timecop: Tag is not sensitive. */
	unpoison(tag, taglen);
}

/* Plaintext - Insert into sponge state and extract the ciphertext */
static void lc_ascon_enc_update(struct lc_ascon_cryptor *ascon,
				const uint8_t *plaintext, uint8_t *ciphertext,
				size_t datalen)
{
	const struct lc_hash *hash = ascon->hash;
	uint64_t *state_mem = ascon->state;
	size_t todo = 0;

	while (datalen) {
		todo = min_size(datalen,
				hash->sponge_rate - ascon->rate_offset);

		lc_sponge_add_bytes(hash, state_mem, plaintext,
				    ascon->rate_offset, todo);

		lc_sponge_extract_bytes(hash, state_mem, ciphertext,
					ascon->rate_offset, todo);

		/* Timecop: Ciphertext is not sensitive. */
		unpoison(ciphertext, todo);

		datalen -= todo;

		/* Apply Sponge for all rounds other than the last one */
		if (datalen) {
			plaintext += todo;
			ciphertext += todo;
			ascon->rate_offset = 0;
			lc_sponge(hash, state_mem, ascon->roundb);
		} else {
			ascon->rate_offset += (uint8_t)todo;
		}
	}
}

static void lc_ascon_enc_final(struct lc_ascon_cryptor *ascon, uint8_t *tag,
			       size_t taglen)
{
	const struct lc_hash *hash = ascon->hash;

	/*
	 * The _update function will not perform the final sponge call as
	 * it does not know whether its invocation was the last one. When the
	 * _final function is called, we know that no more data is sent and
	 * we can unconditionally call the last sponge operation closing the
	 * plaintext injection.
	 */
	if (ascon->rate_offset == hash->sponge_rate)
		lc_sponge(hash, ascon->state, ascon->roundb);

	/* Enforce the tag size */
	if (taglen != ascon->taglen)
		return;

	lc_ascon_add_padbyte(ascon, ascon->rate_offset);

	/* Finalization */
	lc_ascon_finalization(ascon, tag, taglen);
}

/* Complete one-shot encryption */
static void lc_ascon_encrypt(void *state, const uint8_t *plaintext,
			     uint8_t *ciphertext, size_t datalen,
			     const uint8_t *aad, size_t aadlen, uint8_t *tag,
			     size_t taglen)
{
	struct lc_ascon_cryptor *ascon = state;

	/* Authenticated Data */
	lc_ascon_aad(ascon, aad, aadlen);

	/* Plaintext - Insert into rate */
	lc_ascon_enc_update(ascon, plaintext, ciphertext, datalen);

	/* Finalize operation and get authentication tag */
	lc_ascon_enc_final(ascon, tag, taglen);
}

/* Ciphertext - Insert into sponge state and extract the plaintext */
static void lc_ascon_dec_update(struct lc_ascon_cryptor *ascon,
				const uint8_t *ciphertext, uint8_t *plaintext,
				size_t datalen)
{
	const struct lc_hash *hash = ascon->hash;
	uint8_t tmp_pt[136] __align(sizeof(uint64_t)) = { 0 };
	uint64_t *state_mem = ascon->state;
	uint8_t *pt_p = plaintext;
	size_t todo = 0;
	int zero_tmp = 0;

	/* If we have an in-place cipher operation, we need a tmp-buffer */
	if (plaintext == ciphertext) {
		pt_p = tmp_pt;
		zero_tmp = 1;
	}

	/* Timecop: Plaintext is no sensitive data regarding side-channels. */
	while (datalen) {
		todo = min_size(datalen,
				hash->sponge_rate - ascon->rate_offset);
		lc_sponge_extract_bytes(hash, state_mem, pt_p,
					ascon->rate_offset, todo);

		datalen -= todo;

		/*
		 * Replace state with ciphertext and apply Sponge for all
		 * rounds other than the last one.
		 */
		if (datalen) {
			lc_sponge_newstate(hash, state_mem, ciphertext,
					   ascon->rate_offset, todo);
			lc_sponge(hash, ascon->state, ascon->roundb);

			/*
			 * Perform XOR operation here to ensure decryption in
			 * place.
			 */
			if (!zero_tmp) {
				xor_64(pt_p, ciphertext, todo);
				unpoison(pt_p, todo);
				pt_p += todo;
			} else {
				xor_64_3(plaintext, pt_p, ciphertext, todo);
				unpoison(plaintext, todo);
				plaintext += todo;
			}

			ciphertext += todo;
			ascon->rate_offset = 0;
		} else {
			if (!zero_tmp) {
				xor_64(pt_p, ciphertext, todo);
				unpoison(pt_p, todo);
				lc_sponge_add_bytes(hash, state_mem, pt_p,
						    ascon->rate_offset, todo);
			} else {
				xor_64_3(plaintext, pt_p, ciphertext, todo);
				unpoison(plaintext, todo);
				lc_sponge_add_bytes(hash, state_mem, plaintext,
						    ascon->rate_offset, todo);
			}
			ascon->rate_offset += (uint8_t)todo;
		}
	}

	if (zero_tmp)
		lc_memset_secure(tmp_pt, 0, sizeof(tmp_pt));
}

/* Perform the authentication as the last step of the decryption operation */
static int lc_ascon_dec_final(struct lc_ascon_cryptor *ascon,
			      const uint8_t *tag, size_t taglen)
{
	const struct lc_hash *hash = ascon->hash;
	uint8_t calctag[64] __align(sizeof(uint64_t));
	int ret;

	BUILD_BUG_ON(sizeof(calctag) != sizeof(ascon->key));

	/* Tag length must match the initially configured tag length */
	if (taglen != ascon->taglen)
		return -EINVAL;

	/* See enc_final for a rationale why this sponge call is here. */
	if (ascon->rate_offset == hash->sponge_rate)
		lc_sponge(hash, ascon->state, ascon->roundb);

	lc_ascon_add_padbyte(ascon, ascon->rate_offset);

	/* Finalization */
	lc_ascon_finalization(ascon, calctag, taglen);

	ret = (lc_memcmp_secure(calctag, taglen, tag, taglen) ? -EBADMSG : 0);
	lc_memset_secure(calctag, 0, taglen);

	return ret;
}

/* Complete one-shot decryption */
static int lc_ascon_decrypt(void *state, const uint8_t *ciphertext,
			    uint8_t *plaintext, size_t datalen,
			    const uint8_t *aad, size_t aadlen,
			    const uint8_t *tag, size_t taglen)
{
	struct lc_ascon_cryptor *ascon = state;

	/* Authenticated Data - Insert into rate */
	lc_ascon_aad(ascon, aad, aadlen);

	/* Ciphertext - Insert into rate */
	lc_ascon_dec_update(ascon, ciphertext, plaintext, datalen);

	/* Finalize operation and authenticate operation */
	return lc_ascon_dec_final(ascon, tag, taglen);
}

static void lc_ascon_aad_interface(void *state, const uint8_t *aad,
				   size_t aadlen)
{
	struct lc_ascon_cryptor *ascon = state;

	lc_ascon_aad(ascon, aad, aadlen);
}

static void lc_ascon_enc_update_interface(void *state, const uint8_t *plaintext,
					  uint8_t *ciphertext, size_t datalen)
{
	struct lc_ascon_cryptor *ascon = state;

	lc_ascon_enc_update(ascon, plaintext, ciphertext, datalen);
}

static void lc_ascon_enc_final_interface(void *state, uint8_t *tag,
					 size_t taglen)
{
	struct lc_ascon_cryptor *ascon = state;

	lc_ascon_enc_final(ascon, tag, taglen);
}

static void lc_ascon_dec_update_interface(void *state,
					  const uint8_t *ciphertext,
					  uint8_t *plaintext, size_t datalen)
{
	struct lc_ascon_cryptor *ascon = state;

	lc_ascon_dec_update(ascon, ciphertext, plaintext, datalen);
}

static int lc_ascon_dec_final_interface(void *state, const uint8_t *tag,
					size_t taglen)
{
	struct lc_ascon_cryptor *ascon = state;

	return lc_ascon_dec_final(ascon, tag, taglen);
}

static void lc_ascon_zero_interface(void *state)
{
	struct lc_ascon_cryptor *ascon = state;

	lc_ascon_zero(ascon);
}

static const struct lc_aead _lc_ascon_aead = {
	.setkey = lc_ascon_setkey,
	.encrypt = lc_ascon_encrypt,
	.enc_init = lc_ascon_aad_interface,
	.enc_update = lc_ascon_enc_update_interface,
	.enc_final = lc_ascon_enc_final_interface,
	.decrypt = lc_ascon_decrypt,
	.dec_init = lc_ascon_aad_interface,
	.dec_update = lc_ascon_dec_update_interface,
	.dec_final = lc_ascon_dec_final_interface,
	.zero = lc_ascon_zero_interface };
LC_INTERFACE_SYMBOL(const struct lc_aead *, lc_ascon_aead) = &_lc_ascon_aead;
