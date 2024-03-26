/*
 * Copyright (C) 2024, Stephan Mueller <smueller@chronox.de>
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

#include "bitshift.h"
#include "conv_be_le.h"
#include "alignment.h"
#include "lc_ascon_keccak.h"
#include "lc_memcmp_secure.h"
#include "lc_memory_support.h"
#include "math_helper.h"
#include "visibility.h"
#include "xor256.h"

/*
 * Algorithms with 256 bit security strength based on the fact that the
 * capacity is 512 bits or larger.
 *
 *                       ----- Bit size of ----- Rounds
 *                       Key Nonce Tag DataBlock pa pb
 *                                     Rate
 * Ascon-Keccak 256/512  256 128   128  576      24 24
 * Ascon-Keccak 256/256  256 128   128 1088      24 24
 *
 * Note, the tag is allowed also to be larger, up to the size of the capacity.
 */
#define LC_AEAD_AK_SHA3_512_INIT 0x0100024000180018
#define LC_AEAD_AK_SHA3_256_INIT 0x0100044000180018

/**
 * @brief Set the key for the encyption or decryption operation
 *
 * @param ak [in] Ascon-Keccak crypt cipher handle
 * @param key [in] Buffer with key
 * @param keylen [in] Length of key buffer
 * @param iv [in] initialization vector to be used
 * @param ivlen [in] length of initialization vector
 *
 * The algorithm supports a key of arbitrary size. The only requirement is that
 * the same key is used for decryption as for encryption.
 */
static int lc_ak_setkey(void *state, const uint8_t *key, size_t keylen,
			const uint8_t *iv, size_t ivlen)
{
	struct lc_ak_cryptor *ak = state;
	const struct lc_hash *hash = ak->hash;
	unsigned int i;
//	static int tested = 0;

//	lc_ak_selftest(&tested, "cSHAKE AEAD");

	memset(state, 0, LC_SHA3_STATE_SIZE);

	/* INIT || 0* || key || iv */
	switch (hash->rate) {
	case 0x240 / 8:
		if (ivlen != 16 || keylen != 32)
			return -EINVAL;
		ak->keccak_state[0] = be_bswap64(LC_AEAD_AK_SHA3_512_INIT);
		for (i = 1;
		     i < (LC_SHA3_STATE_WORDS - (16 + 32) / sizeof(uint64_t));
		     i++)
			ak->keccak_state[i] = 0;

		memcpy(ak->key, key, keylen);

		break;
	case 0x440 / 8:
		if (ivlen != 16 || keylen != 32)
			return -EINVAL;
		ak->keccak_state[0] = be_bswap64(LC_AEAD_AK_SHA3_256_INIT);
		for (i = 1;
		     i < (LC_SHA3_STATE_WORDS - (16 + 16) / sizeof(uint64_t));
		     i++)
			ak->keccak_state[i] = 0;

		memcpy(ak->key, key, keylen);
		memset(ak->key + 16, 0, 16);
		break;
	default:
		return -EINVAL;
	}

	lc_keccak_add_bytes(hash, ak->keccak_state, key,
			    (unsigned int)(LC_SHA3_STATE_SIZE - ivlen - keylen),
			    (unsigned int)keylen);
	lc_keccak_add_bytes(hash, ak->keccak_state, iv,
			    (unsigned int)(LC_SHA3_STATE_SIZE - ivlen),
			    (unsigned int)ivlen);

	/* Keccak */
	lc_keccak(hash, state);

	/* XOR key to last part of state */
	lc_keccak_add_bytes(hash, ak->keccak_state, key,
			    (unsigned int)(LC_SHA3_STATE_SIZE - keylen),
			    (unsigned int)keylen);

	return 0;
}

static void lc_ak_add_padbyte(struct lc_ak_cryptor *ak, size_t offset)
{
	const struct lc_hash *hash = ak->hash;
	static const uint8_t pad_data = 0x80;

	/*
	 * The data was exactly a multiple of the rate -> permute before adding
	 * the padding byte.
	 */
	if (offset == hash->rate)
		lc_keccak(hash, ak->keccak_state);

	lc_keccak_add_bytes(hash, ak->keccak_state, &pad_data,
			    (unsigned int)offset, 1);
}

static void lc_ak_aad(struct lc_ak_cryptor *ak, const uint8_t *aad,
		      size_t aadlen)
{
	const struct lc_hash *hash = ak->hash;
	size_t todo = 0;
	static const uint8_t pad_trail = 0x01;

	/* Authenticated Data - Insert into rate */
	while (aadlen) {
		todo = min_size(aadlen, hash->rate);
		lc_keccak_add_bytes(hash, ak->keccak_state, aad, 0,
				    (unsigned int)todo);

		aadlen -= todo;

		/* Insert the trailing 1 */
		if (!aadlen)
			lc_ak_add_padbyte(ak, todo);

		lc_keccak(hash, ak->keccak_state);
	}

	/* Add pad_trail bit */
	lc_keccak_add_bytes(hash, ak->keccak_state, &pad_trail,
			    LC_SHA3_STATE_SIZE - 1, 1);
}

static void lc_ak_finalization(struct lc_ak_cryptor *ak, uint8_t *tag,
			       size_t taglen)
{
	const struct lc_hash *hash = ak->hash;

	/* Finalization - Insert key into capacity */
	lc_keccak_add_bytes(hash, ak->keccak_state, ak->key, hash->rate, 32);

	lc_keccak(hash, ak->keccak_state);

	/* Finalization - Insert key into capacity */
	lc_keccak_add_bytes(hash, ak->keccak_state, ak->key, hash->rate, 32);

	/* Finalization - Extract tag from capacity */
	lc_keccak_extract_bytes(hash, ak->keccak_state, tag, hash->rate,
				(unsigned int)taglen);
}

static void lc_ak_encrypt(void *state, const uint8_t *plaintext,
			  uint8_t *ciphertext, size_t datalen,
			  const uint8_t *aad, size_t aadlen, uint8_t *tag,
			  size_t taglen)
{
	struct lc_ak_cryptor *ak = state;
	const struct lc_hash *hash = ak->hash;
	size_t todo = 0;

	if (taglen > (LC_SHA3_STATE_SIZE - hash->rate) || taglen < 16)
		return;

	/* Authenticated Data */
	lc_ak_aad(ak, aad, aadlen);

	/* Plaintext - Insert into rate */
	while (datalen) {
		todo = min_size(datalen, hash->rate);

		lc_keccak_add_bytes(hash, ak->keccak_state, plaintext, 0,
				    (unsigned int)todo);

		lc_keccak_extract_bytes(hash, ak->keccak_state, ciphertext, 0,
					(unsigned int)todo);

		datalen -= todo;

		/* Apply Keccak for all rounds other than the last one */
		if (datalen) {
			lc_keccak(hash, ak->keccak_state);
			plaintext += todo;
			ciphertext += todo;
		} else {
			lc_ak_add_padbyte(ak, todo);
		}
	}

	/* Finalization */
	lc_ak_finalization(ak, tag, taglen);
}

static int lc_ak_decrypt(void *state, const uint8_t *ciphertext,
			 uint8_t *plaintext, size_t datalen, const uint8_t *aad,
			 size_t aadlen, const uint8_t *tag, size_t taglen)
{
	struct lc_ak_cryptor *ak = state;
	const struct lc_hash *hash = ak->hash;
	uint8_t calctag[128] __align(sizeof(uint64_t));
	uint8_t *calctag_p = calctag;
	size_t todo;
	int ret;

	if (taglen > sizeof(calctag)) {
		ret = lc_alloc_aligned((void **)&calctag_p,
				       LC_MEM_COMMON_ALIGNMENT, taglen);
		if (ret)
			return -ret;
	}

	/* Authenticated Data - Insert into rate */
	lc_ak_aad(ak, aad, aadlen);

	/* Plaintext - Insert into rate */
	while (datalen) {
		todo = min_size(datalen, hash->rate);
		lc_keccak_extract_bytes(hash, ak->keccak_state, plaintext, 0,
					(unsigned int)todo);

		datalen -= todo;

		/*
		 * Replace state with ciphertext and apply Keccak for all
		 * rounds other than the last one.
		 */
		if (datalen) {
			lc_keccak_newstate(hash, ak->keccak_state, ciphertext,
					   0, todo);
			lc_keccak(hash, ak->keccak_state);

			/*
			 * Perform XOR operation here to ensure decryption in
			 * place.
			 */
			xor_256(plaintext, ciphertext, todo);

			plaintext += todo;
			ciphertext += todo;
		} else {
			xor_256(plaintext, ciphertext, todo);

			lc_keccak_add_bytes(hash, ak->keccak_state, plaintext,
					    0, (unsigned int)todo);

			lc_ak_add_padbyte(ak, todo);
		}
	}

	/* Finalization */
	lc_ak_finalization(ak, calctag_p, taglen);

	ret = (lc_memcmp_secure(calctag_p, taglen, tag, taglen) ? -EBADMSG : 0);
	lc_memset_secure(calctag_p, 0, taglen);
	if (taglen > sizeof(calctag))
		lc_free(calctag_p);

	return ret;
}

LC_INTERFACE_FUNCTION(int, lc_ak_alloc, const struct lc_hash *hash,
		      struct lc_aead_ctx **ctx)
{
	struct lc_aead_ctx *tmp = NULL;
	int ret;

	ret = lc_alloc_aligned((void **)&tmp, LC_ASCON_KECCAK_ALIGNMENT,
			       LC_AK_CTX_SIZE(hash));
	if (ret)
		return -ret;

	LC_AK_SET_CTX(tmp, hash);

	*ctx = tmp;

	return 0;
}

static void lc_ak_zero(void *state)
{
	struct lc_ak_cryptor *ak = state;

	lc_memset_secure((uint8_t *)ak->keccak_state, 0,
			 sizeof(ak->keccak_state));
	lc_memset_secure((uint8_t *)ak->key, 0, sizeof(ak->key));
}

struct lc_aead _lc_ascon_keccak_aead = {
	.setkey = lc_ak_setkey,
	.encrypt = lc_ak_encrypt,
	.enc_update = NULL,
	.enc_final = NULL,
	.decrypt = lc_ak_decrypt,
	.dec_update = NULL,
	.dec_final = NULL,
	.zero = lc_ak_zero };
LC_INTERFACE_SYMBOL(const struct lc_aead *, lc_ascon_keccak_aead) =
	&_lc_ascon_keccak_aead;
